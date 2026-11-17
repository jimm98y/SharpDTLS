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
using SharpDTLS.Protocol13;
using System;
using System.Linq;

namespace SharpDTLS
{
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

        /// <summary>
        /// TLS 1.2's finite-field DH on explicit parameters: the public value and the secret without leading zeros (RFC 5246
        /// §8.1.2), the peer's value checked (1 &lt; Y &lt; p - 1) and a secret of one refused.
        /// </summary>
        public static ITlsKeyShare Dh(byte[] prime, byte[] generator)
        {
            var parameters = new DHParameters(new BigInteger(1, prime), new BigInteger(1, generator));
            var (x, y) = DhUtilities.GenerateKeyPair(parameters);
            return new KeyShare(y.ToByteArrayUnsigned(), peer => DhUtilities.Agree(parameters, x, new BigInteger(1, peer)));
        }

        /// <summary>An ephemeral key on the curve or DH group of a peer's static key (static ECDH and DH, RFC 8422 §2.1, RFC 5246 §7.4.7.2).</summary>
        public static ITlsKeyShare OnDomainOf(byte[] subjectPublicKeyInfo)
        {
            switch (PublicKeyFactory.CreateKey(subjectPublicKeyInfo))
            {
                case ECPublicKeyParameters ec:
                {
                    var generator = new ECKeyPairGenerator();
                    generator.Init(new ECKeyGenerationParameters(ec.Parameters, new SecureRandom()));
                    var pair = generator.GenerateKeyPair();
                    return new KeyShare(((ECPublicKeyParameters)pair.Public).Q.GetEncoded(false), peer => StaticEcdh.Agree((ECPrivateKeyParameters)pair.Private, peer));
                }
                case DHPublicKeyParameters dh:
                    return Dh(dh.Parameters.P.ToByteArrayUnsigned(), dh.Parameters.G.ToByteArrayUnsigned());
                default:
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "The peer's key is not a key agreement key.");
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

    /// <summary>The RFC 7919 FFDHE groups.</summary>
    internal static class FfdheGroups
    {
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;

        /// <summary>Groups in preference order (smallest first: all are considered secure, and they are faster).</summary>
        public static readonly ushort[] Supported = { Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192 };

        public static DHParameters Parameters(ushort group) => group switch
        {
            Ffdhe2048 => DHStandardGroups.rfc7919_ffdhe2048,
            Ffdhe3072 => DHStandardGroups.rfc7919_ffdhe3072,
            Ffdhe4096 => DHStandardGroups.rfc7919_ffdhe4096,
            Ffdhe6144 => DHStandardGroups.rfc7919_ffdhe6144,
            Ffdhe8192 => DHStandardGroups.rfc7919_ffdhe8192,
            _ => throw new ArgumentOutOfRangeException(nameof(group)),
        };

        /// <summary>The named group whose prime and generator match, or 0 for custom parameters.</summary>
        public static ushort Identify(BigInteger p, BigInteger g)
            => Supported.FirstOrDefault(id => Parameters(id).P.Equals(p) && Parameters(id).G.Equals(g));

        /// <inheritdoc cref="Identify(BigInteger, BigInteger)"/>
        public static ushort Identify(byte[] p, byte[] g) => Identify(new BigInteger(1, p), new BigInteger(1, g));

        /// <summary>The group's prime and generator as TLS 1.2 sends them (unsigned, no leading zeros).</summary>
        public static byte[] Prime(ushort group) => Parameters(group).P.ToByteArrayUnsigned();

        public static byte[] Generator(ushort group) => Parameters(group).G.ToByteArrayUnsigned();
    }

    internal static class DhUtilities
    {
        public static (BigInteger PrivateX, BigInteger PublicY) GenerateKeyPair(DHParameters parameters)
        {
            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
            var pair = generator.GenerateKeyPair();
            var (x, y) = (((DHPrivateKeyParameters)pair.Private).X, ((DHPublicKeyParameters)pair.Public).Y);
            if (TlsInspector.Current is { } inspector)
                TlsInspector.KeyExchange(inspector, FfdheGroups.Identify(parameters.P, parameters.G), x.ToByteArrayUnsigned(), y.ToByteArrayUnsigned());
            return (x, y);
        }

        /// <summary>Z = Y^x mod p with leading zero bytes stripped (RFC 5246 §8.1.2). Rejects Y outside 1 &lt; Y &lt; p-1.</summary>
        public static byte[] Agree(DHParameters parameters, BigInteger privateX, BigInteger peerY)
        {
            if (peerY.CompareTo(BigInteger.One) <= 0 || peerY.CompareTo(parameters.P.Subtract(BigInteger.One)) >= 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid Diffie-Hellman public value.");

            var agreement = new DHBasicAgreement();
            agreement.Init(new DHPrivateKeyParameters(privateX, parameters));
            BigInteger z = agreement.CalculateAgreement(new DHPublicKeyParameters(peerY, parameters));
            if (z.Equals(BigInteger.One))
                throw new DtlsException(AlertDescription.IllegalParameter, "Degenerate Diffie-Hellman shared secret.");
            return z.ToByteArrayUnsigned();
        }
    }

    internal static class StaticEcdh
    {
        /// <summary>The x-coordinate of d·Q, padded to the field size (RFC 8422 §5.10).</summary>
        public static byte[] Agree(ECPrivateKeyParameters privateKey, byte[] peerPoint)
        {
            var domain = privateKey.Parameters;
            int fieldLength = (domain.Curve.FieldSize + 7) / 8;
            if (peerPoint == null || peerPoint.Length != 1 + 2 * fieldLength || peerPoint[0] != 0x04)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid EC point encoding.");

            Org.BouncyCastle.Math.EC.ECPoint point;
            try
            {
                point = domain.Curve.DecodePoint(peerPoint);
            }
            catch (ArgumentException ex)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "EC point is not on the curve.", ex);
            }

            var agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey);
            return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(fieldLength,
                agreement.CalculateAgreement(new ECPublicKeyParameters(point, domain)));
        }
    }
}
