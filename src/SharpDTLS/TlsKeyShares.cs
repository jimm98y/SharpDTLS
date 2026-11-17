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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// One ephemeral key of a key exchange group (RFC 8446 §4.2.7): (EC)DHE, X25519, X448, FFDHE, or the decapsulation key
    /// of ML-KEM. Hybrid groups are made of two.
    /// </summary>
    public interface ITlsKeyShare
    {
        /// <summary>
        /// Our public value as TLS sends it: an uncompressed EC point, an X25519 or X448 key, an FFDHE value as long as
        /// the prime, or an ML-KEM encapsulation key.
        /// </summary>
        byte[] PublicKey { get; }

        /// <summary>
        /// The shared secret with the peer's public value (of ML-KEM, its ciphertext): an EC x-coordinate, the raw
        /// X25519/X448 result or the FFDHE secret, each as long as the field. Throws a <see cref="System.Security.Cryptography.CryptographicException"/>
        /// for an invalid peer value (off the curve, the wrong length, a small-order point).
        /// </summary>
        byte[] Agree(byte[] peerPublicKey);
    }

    /// <summary>A key share of a public value and an agreement.</summary>
    internal sealed class KeyShare : ITlsKeyShare
    {
        private readonly Func<byte[], byte[]> _agree;

        public KeyShare(byte[] publicKey, Func<byte[], byte[]> agree)
        {
            PublicKey = publicKey;
            _agree = agree;
        }

        public byte[] PublicKey { get; }

        public byte[] Agree(byte[] peerPublicKey) => _agree(peerPublicKey);
    }

    /// <summary>BouncyCastle's key exchange groups: every group SharpDTLS implements.</summary>
    internal static class BcKeyShares
    {
        public static ITlsKeyShare Create(ushort group)
        {
            var random = new SecureRandom();
            switch (group)
            {
                case Dtls13Groups.X25519:
                {
                    var key = new X25519PrivateKeyParameters(random);
                    byte[] share = key.GeneratePublicKey().GetEncoded();
                    if (TlsInspector.Current is { } inspector)
                        TlsInspector.KeyExchange(inspector, group, key.GetEncoded(), share);
                    return new KeyShare(share, peer =>
                    {
                        Expect(peer, 32);
                        return NonZero(Agree(new X25519Agreement(), key, new X25519PublicKeyParameters(peer, 0)));
                    });
                }
                case Dtls13Groups.X448:
                {
                    var key = new X448PrivateKeyParameters(random);
                    byte[] share = key.GeneratePublicKey().GetEncoded();
                    if (TlsInspector.Current is { } inspector)
                        TlsInspector.KeyExchange(inspector, group, key.GetEncoded(), share);
                    return new KeyShare(share, peer =>
                    {
                        Expect(peer, 56);
                        return NonZero(Agree(new X448Agreement(), key, new X448PublicKeyParameters(peer, 0)));
                    });
                }
                case Dtls13Groups.Secp256r1:
                case Dtls13Groups.Secp384r1:
                case Dtls13Groups.Secp521r1:
                {
                    var domain = Curve(group);
                    var generator = new ECKeyPairGenerator();
                    generator.Init(new ECKeyGenerationParameters(domain, random));
                    var pair = generator.GenerateKeyPair();
                    var key = (ECPrivateKeyParameters)pair.Private;
                    // RFC 8446 §4.2.8.2: uncompressed points; the secret is the x-coordinate, field-size long.
                    byte[] share = ((ECPublicKeyParameters)pair.Public).Q.GetEncoded(false);
                    if (TlsInspector.Current is { } inspector)
                        TlsInspector.KeyExchange(inspector, group, BigIntegers.AsUnsignedByteArray((domain.Curve.FieldSize + 7) / 8, key.D), share);
                    return new KeyShare(share, peer => EcdhSecret(domain, key, peer));
                }
                case Dtls13Groups.MlKem512:
                case Dtls13Groups.MlKem768:
                case Dtls13Groups.MlKem1024:
                    return MlKem(group);
                default:
                {
                    var parameters = FfdheGroups.Parameters(group);
                    int length = (parameters.P.BitLength + 7) / 8;
                    var (x, y) = DhUtilities.GenerateKeyPair(parameters);
                    // RFC 8446 §4.2.8.1 / §7.4.1: values and the secret keep their leading zeros, as long as p.
                    return new KeyShare(BigIntegers.AsUnsignedByteArray(length, y), peer =>
                    {
                        Expect(peer, length);
                        var peerY = new BigInteger(1, peer);
                        if (peerY.CompareTo(BigInteger.One) <= 0 || peerY.CompareTo(parameters.P.Subtract(BigInteger.One)) >= 0)
                            throw new DtlsException(AlertDescription.IllegalParameter, "Invalid FFDHE public value.");
                        return BigIntegers.AsUnsignedByteArray(length, peerY.ModPow(x, parameters.P));
                    });
                }
            }
        }

        public static byte[] Encapsulate(ushort group, byte[] encapsulationKey, out byte[] sharedSecret)
        {
            var parameters = MlKemParameters(group);
            MLKemPublicKeyParameters publicKey;
            try
            {
                publicKey = MLKemPublicKeyParameters.FromEncoding(parameters, encapsulationKey);
            }
            catch (ArgumentException)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid ML-KEM encapsulation key.");
            }
            var encapsulator = new MLKemEncapsulator(parameters);
            encapsulator.Init(new ParametersWithRandom(publicKey, new SecureRandom()));
            byte[] ciphertext = new byte[encapsulator.EncapsulationLength];
            sharedSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
            return ciphertext;
        }

        private static ITlsKeyShare MlKem(ushort group)
        {
            var parameters = MlKemParameters(group);
            var generator = new MLKemKeyPairGenerator();
            generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), parameters));
            var pair = generator.GenerateKeyPair();
            byte[] encapsulationKey = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
            if (TlsInspector.Current is { } inspector)
                TlsInspector.KeyExchange(inspector, group, ((MLKemPrivateKeyParameters)pair.Private).GetEncoded(), encapsulationKey);
            return new KeyShare(encapsulationKey, ciphertext =>
            {
                var decapsulator = new MLKemDecapsulator(parameters);
                decapsulator.Init(pair.Private);
                Expect(ciphertext, decapsulator.EncapsulationLength);
                byte[] secret = new byte[decapsulator.SecretLength];
                decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);
                return secret;
            });
        }

        private static MLKemParameters MlKemParameters(ushort group) => group switch
        {
            Dtls13Groups.MlKem512 => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_512,
            Dtls13Groups.MlKem768 => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768,
            Dtls13Groups.MlKem1024 => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_1024,
            _ => throw new DtlsException(AlertDescription.InternalError, $"Group {Dtls13Groups.Name(group)} is not a KEM."),
        };

        private static byte[] Agree(IRawAgreement agreement, ICipherParameters privateKey, ICipherParameters publicKey)
        {
            agreement.Init(privateKey);
            byte[] secret = new byte[agreement.AgreementSize];
            try
            {
                agreement.CalculateAgreement(publicKey, secret, 0);
            }
            catch (InvalidOperationException ex)
            {
                // BouncyCastle refuses X25519/X448 small-order points itself.
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid key share.", ex);
            }
            return secret;
        }

        private static byte[] NonZero(byte[] secret)
        {
            // RFC 8446 §7.4.2: an all-zero X25519/X448 result means a small-order peer key.
            if (secret.All(b => b == 0))
                throw new DtlsException(AlertDescription.IllegalParameter, "All-zero key exchange result.");
            return secret;
        }

        private static ECDomainParameters Curve(ushort group)
        {
            string name = group switch { Dtls13Groups.Secp256r1 => "P-256", Dtls13Groups.Secp384r1 => "P-384", _ => "P-521" };
            return new ECNamedDomainParameters(ECNamedCurveTable.GetOid(name), ECNamedCurveTable.GetByName(name));
        }

        private static byte[] EcdhSecret(ECDomainParameters domain, ECPrivateKeyParameters key, byte[] peer)
        {
            int fieldLength = (domain.Curve.FieldSize + 7) / 8;
            ECPoint point;
            try
            {
                Expect(peer, 1 + 2 * fieldLength);
                if (peer[0] != 0x04)
                    throw new ArgumentException("not uncompressed");
                point = domain.Curve.DecodePoint(peer);
            }
            catch (ArgumentException)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid elliptic curve key share.");
            }
            var agreement = new ECDHBasicAgreement();
            agreement.Init(key);
            BigInteger z = agreement.CalculateAgreement(new ECPublicKeyParameters(point, domain));
            return BigIntegers.AsUnsignedByteArray(fieldLength, z);
        }

        internal static void Expect(byte[] value, int length)
        {
            if (value == null || value.Length != length)
                throw new DtlsException(AlertDescription.IllegalParameter, $"Key share is {value?.Length ?? 0} bytes, expected {length}.");
        }
    }

#if NETCOREAPP
    /// <summary>.NET's ECDH on the NIST curves, and ML-KEM where the platform has it (.NET 10).</summary>
    internal static class NetKeyShares
    {
        /// <summary>Null for a group .NET has no key for here.</summary>
        public static ITlsKeyShare Create(ushort group)
        {
            System.Security.Cryptography.ECCurve? curve = group switch
            {
                Dtls13Groups.Secp256r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
                Dtls13Groups.Secp384r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP384,
                Dtls13Groups.Secp521r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP521,
                _ => null,
            };
            if (curve == null)
                return null;
            var ecdh = System.Security.Cryptography.ECDiffieHellman.Create(curve.Value);
            var parameters = ecdh.ExportParameters(includePrivateParameters: TlsInspector.Current != null);
            int fieldLength = parameters.Q.X.Length;
            byte[] share = new byte[1 + 2 * fieldLength];
            share[0] = 0x04;
            parameters.Q.X.CopyTo(share, 1);
            parameters.Q.Y.CopyTo(share, 1 + fieldLength);
            if (TlsInspector.Current is { } inspector)
                TlsInspector.KeyExchange(inspector, group, parameters.D, share);
            return new KeyShare(share, peer =>
            {
                using (ecdh)
                {
                    BcKeyShares.Expect(peer, share.Length);
                    if (peer[0] != 0x04)
                        throw new DtlsException(AlertDescription.IllegalParameter, "Invalid elliptic curve key share.");
                    var peerParameters = new System.Security.Cryptography.ECParameters
                    {
                        Curve = curve.Value,
                        Q = new System.Security.Cryptography.ECPoint { X = peer.AsSpan(1, fieldLength).ToArray(), Y = peer.AsSpan(1 + fieldLength).ToArray() },
                    };
                    try
                    {
                        // the import refuses a point off the curve
                        using var peerKey = System.Security.Cryptography.ECDiffieHellman.Create(peerParameters);
                        return ecdh.DeriveRawSecretAgreement(peerKey.PublicKey);
                    }
                    catch (System.Security.Cryptography.CryptographicException ex)
                    {
                        throw new DtlsException(AlertDescription.IllegalParameter, "Invalid elliptic curve key share.", ex);
                    }
                }
            });
        }
    }
#endif
}
