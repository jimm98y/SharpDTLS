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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SharpDTLS.Protocol12;
using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using BcECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace SharpDTLS
{
    /// <summary>
    /// A TLS-PWD password as a server stores it (RFC 8492 §3.4): base = HMAC-SHA256(salt, username | password),
    /// never the password itself.
    /// </summary>
    public sealed class PwdCredential
    {
        public PwdCredential(byte[] salt, byte[] passwordBase)
        {
            if (salt == null || salt.Length is 0 or > 255)
                throw new ArgumentException("The salt must be 1 to 255 bytes.", nameof(salt));
            Salt = salt;
            Base = passwordBase ?? throw new ArgumentNullException(nameof(passwordBase));
        }

        public byte[] Salt { get; }
        public byte[] Base { get; }

        /// <summary>Creates a credential with a random 32-byte salt (RFC 8492 §3.4).</summary>
        public static PwdCredential Create(string username, string password)
        {
            byte[] salt = Dtls12CryptoUtils.GenerateRandom(32);
            return new PwdCredential(salt, ComputeBase(salt, username, password));
        }

        /// <summary>base = HMAC-SHA256(salt, username | password), both prepared as OpaqueString (RFC 8265).</summary>
        public static byte[] ComputeBase(byte[] salt, string username, string password)
        {
            byte[] data = EccPwd.PrepareOpaqueString(username).Concat(EccPwd.PrepareOpaqueString(password)).ToArray();
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(salt));
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        /// A username-protection key pair (RFC 8492 §4.3), on secp256r1 unless another curve is named: D and Q.
        /// The server keeps the private key; clients are provisioned with the public key, Q alone.
        /// </summary>
        public static ECParameters GenerateProtectionKeyPair(string curveName = "P-256")
        {
            var curve = ECNamedCurveTable.GetByName(curveName) ?? throw new ArgumentException($"Unknown curve {curveName}.", nameof(curveName));
            if (!curve.H.Equals(BigInteger.One))
                throw new ArgumentException("Username protection needs a curve with cofactor 1.", nameof(curveName));
            var oid = ECNamedCurveTable.GetOid(curveName);
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(oid, new SecureRandom()));
            var pair = generator.GenerateKeyPair();
            int length = (curve.Curve.FieldSize + 7) / 8;
            var q = ((ECPublicKeyParameters)pair.Public).Q;
            return new ECParameters
            {
                Curve = ECCurve.CreateFromValue(oid.Id),
                D = BigIntegers.AsUnsignedByteArray(length, ((ECPrivateKeyParameters)pair.Private).D),
                Q = new ECPoint
                {
                    X = BigIntegers.AsUnsignedByteArray(length, q.AffineXCoord.ToBigInteger()),
                    Y = BigIntegers.AsUnsignedByteArray(length, q.AffineYCoord.ToBigInteger()),
                },
            };
        }

        /// <summary>A protection key's private half, as BouncyCastle's; null for none.</summary>
        internal static ECPrivateKeyParameters PrivateKeyOf(ECParameters? key)
        {
            if (key == null)
                return null;
            if (key.Value.D == null)
                throw new ArgumentException("The protection key has no private key (D).");
            return new ECPrivateKeyParameters("EC", new BigInteger(1, key.Value.D), Certificates.CurveOid(key.Value.Curve));
        }

        /// <summary>A protection key's public half, as BouncyCastle's; null for none.</summary>
        internal static ECPublicKeyParameters PublicKeyOf(ECParameters? key)
        {
            if (key == null)
                return null;
            var q = key.Value.Q;
            if (q.X == null || q.Y == null)
                throw new ArgumentException("The protection key has no public key (Q).");
            DerObjectIdentifier oid = Certificates.CurveOid(key.Value.Curve);
            var curve = ECNamedCurveTable.GetByOid(oid) ?? throw new ArgumentException("The protection key's curve is unknown.");
            BcECPoint point;
            try
            {
                point = curve.Curve.CreatePoint(new BigInteger(1, q.X), new BigInteger(1, q.Y));
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException("The protection key's Q is not on its curve.", ex);
            }
            if (!point.IsValid())
                throw new ArgumentException("The protection key's Q is not on its curve.");
            return new ECPublicKeyParameters("EC", point, oid);
        }
    }
}
