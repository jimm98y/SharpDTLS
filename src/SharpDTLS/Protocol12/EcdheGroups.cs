// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Linq;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// (EC)DHE named groups (RFC 8422, RFC 8446 §4.2.7). Private keys are opaque byte arrays:
    /// the raw scalar for X25519, the big-endian scalar for NIST curves.
    /// </summary>
    internal static class EcdheGroups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort X25519    = 0x001d;

        /// <summary>Implemented groups in preference order.</summary>
        public static readonly ushort[] Supported = { X25519, Secp256r1, Secp384r1 };

        public static bool IsSupported(ushort group) => Supported.Contains(group);

        public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair(ushort group)
        {
            var random = new SecureRandom();
            if (group == X25519)
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(new X25519KeyGenerationParameters(random));
                var keyPair = generator.GenerateKeyPair();
                var pair = (((X25519PrivateKeyParameters)keyPair.Private).GetEncoded(), ((X25519PublicKeyParameters)keyPair.Public).GetEncoded());
                if (TlsInspector.Current is { } x25519Inspector)
                    TlsInspector.KeyExchange(x25519Inspector, group, pair.Item1, pair.Item2);
                return pair;
            }

            var domain = Domain(group);
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(domain, random));
            var ecKeyPair = ecGenerator.GenerateKeyPair();
            byte[] privateKey = BigIntegers.AsUnsignedByteArray(FieldLength(group), ((ECPrivateKeyParameters)ecKeyPair.Private).D);
            byte[] publicKey = ((ECPublicKeyParameters)ecKeyPair.Public).Q.GetEncoded(false); // uncompressed
            if (TlsInspector.Current is { } inspector)
                TlsInspector.KeyExchange(inspector, group, privateKey, publicKey);
            return (privateKey, publicKey);
        }

        /// <summary>
        /// Computes the shared secret. Invalid peer keys (off-curve points, identity, all-zero X25519
        /// output) are rejected with illegal_parameter.
        /// </summary>
        public static byte[] Agree(ushort group, byte[] privateKey, byte[] peerPublicKey)
        {
            if (group == X25519)
                return SharpDTLS.Protocol13.Dtls13CryptoUtils.DeriveSharedSecretX25519(privateKey, peerPublicKey);

            var domain = Domain(group);
            int fieldLength = FieldLength(group);

            // RFC 8422 §5.4.1: only the uncompressed point format is used.
            if (peerPublicKey == null || peerPublicKey.Length != 1 + 2 * fieldLength || peerPublicKey[0] != 0x04)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid EC point encoding.");

            Org.BouncyCastle.Math.EC.ECPoint point;
            try
            {
                point = domain.Curve.DecodePoint(peerPublicKey); // validates that the point is on the curve
            }
            catch (ArgumentException ex)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "EC point is not on the curve.", ex);
            }

            var agreement = new ECDHBasicAgreement();
            agreement.Init(new ECPrivateKeyParameters(new BigInteger(1, privateKey), domain));
            BigInteger shared = agreement.CalculateAgreement(new ECPublicKeyParameters(point, domain));
            return BigIntegers.AsUnsignedByteArray(fieldLength, shared);
        }

        private static int FieldLength(ushort group) => group switch
        {
            Secp256r1 => 32,
            Secp384r1 => 48,
            _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unsupported group 0x{group:X4}"),
        };

        private static ECDomainParameters Domain(ushort group)
        {
            string name = group switch
            {
                Secp256r1 => "P-256",
                Secp384r1 => "P-384",
                _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unsupported group 0x{group:X4}"),
            };
            X9ECParameters curve = ECNamedCurveTable.GetByName(name);
            return new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        }
    }
}
