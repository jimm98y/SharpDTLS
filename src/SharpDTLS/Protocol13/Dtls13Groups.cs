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
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// DTLS 1.3 key exchange groups (RFC 8446 §4.2.7): elliptic curves, X25519/X448, RFC 7919 FFDHE, ML-KEM
    /// (draft-ietf-tls-mlkem) and the ECDHE + ML-KEM hybrids (draft-ietf-tls-ecdhe-mlkem).
    /// </summary>
    internal static class Dtls13Groups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort Secp521r1 = 0x0019;
        public const ushort X25519 = 0x001d;
        public const ushort X448 = 0x001e;
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;
        public const ushort MlKem512 = 0x0200;
        public const ushort MlKem768 = 0x0201;
        public const ushort MlKem1024 = 0x0202;
        public const ushort SecP256r1MlKem768 = 0x11eb;
        public const ushort X25519MlKem768 = 0x11ec;
        public const ushort SecP384r1MlKem1024 = 0x11ed;

        /// <summary>Every implemented group.</summary>
        public static IReadOnlyList<ushort> All { get; } = new[]
        {
            X25519MlKem768, SecP256r1MlKem768, SecP384r1MlKem1024, X25519, Secp256r1, Secp384r1, X448, Secp521r1,
            MlKem768, MlKem1024, MlKem512, Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192,
        };

        /// <summary>
        /// Default preference: the post-quantum hybrid first, then the elliptic curves, then FFDHE. Pure ML-KEM is
        /// not in it (it has no classical fallback) and must be listed explicitly.
        /// </summary>
        public static IReadOnlyList<ushort> DefaultPreference { get; } = new[]
        {
            X25519MlKem768, X25519, Secp256r1, Secp384r1, X448, Secp521r1, SecP256r1MlKem768, SecP384r1MlKem1024,
            Ffdhe2048, Ffdhe3072, Ffdhe4096,
        };

        public static bool IsSupported(ushort group) => All.Contains(group);

        public static string Name(ushort group) => group switch
        {
            Secp256r1 => "secp256r1", Secp384r1 => "secp384r1", Secp521r1 => "secp521r1", X25519 => "x25519", X448 => "x448",
            Ffdhe2048 => "ffdhe2048", Ffdhe3072 => "ffdhe3072", Ffdhe4096 => "ffdhe4096", Ffdhe6144 => "ffdhe6144", Ffdhe8192 => "ffdhe8192",
            MlKem512 => "MLKEM512", MlKem768 => "MLKEM768", MlKem1024 => "MLKEM1024",
            SecP256r1MlKem768 => "SecP256r1MLKEM768", X25519MlKem768 => "X25519MLKEM768", SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
            _ => $"0x{group:X4}",
        };

        /// <summary>The client's private half of a key share.</summary>
        internal sealed class ClientKeyShare
        {
            public ushort Group { get; init; }
            public byte[] Share { get; init; }
            internal Func<byte[], byte[]> Complete { get; init; }
        }

        /// <summary>Generates the client's key share for <paramref name="group"/>.</summary>
        internal static ClientKeyShare Generate(ushort group)
        {
            switch (group)
            {
                case X25519:
                case X448:
                case Secp256r1:
                case Secp384r1:
                case Secp521r1:
                case Ffdhe2048:
                case Ffdhe3072:
                case Ffdhe4096:
                case Ffdhe6144:
                case Ffdhe8192:
                {
                    var (share, agree) = GenerateClassical(group);
                    return new ClientKeyShare { Group = group, Share = share, Complete = agree };
                }
                case MlKem512:
                case MlKem768:
                case MlKem1024:
                {
                    var (share, decapsulate) = GenerateMlKem(MlKemParameters(group));
                    return new ClientKeyShare { Group = group, Share = share, Complete = decapsulate };
                }
                case X25519MlKem768:
                {
                    // ML-KEM first for X25519MLKEM768: share = ek || x25519, secret = ss || x25519 secret.
                    var (ek, decapsulate) = GenerateMlKem(Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768);
                    var (ecdh, agree) = GenerateClassical(X25519);
                    return new ClientKeyShare
                    {
                        Group = group,
                        Share = Concat(ek, ecdh),
                        Complete = serverShare =>
                        {
                            Expect(serverShare, 1088 + 32);
                            return Concat(decapsulate(serverShare[..1088]), agree(serverShare[1088..]));
                        },
                    };
                }
                case SecP256r1MlKem768:
                case SecP384r1MlKem1024:
                {
                    // ECDH first: share = point || ek, secret = ECDH secret || ss.
                    ushort curve = group == SecP256r1MlKem768 ? Secp256r1 : Secp384r1;
                    var parameters = group == SecP256r1MlKem768
                        ? Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768
                        : Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_1024;
                    int pointLength = group == SecP256r1MlKem768 ? 65 : 97;
                    int ciphertextLength = group == SecP256r1MlKem768 ? 1088 : 1568;
                    var (ecdh, agree) = GenerateClassical(curve);
                    var (ek, decapsulate) = GenerateMlKem(parameters);
                    return new ClientKeyShare
                    {
                        Group = group,
                        Share = Concat(ecdh, ek),
                        Complete = serverShare =>
                        {
                            Expect(serverShare, pointLength + ciphertextLength);
                            return Concat(agree(serverShare[..pointLength]), decapsulate(serverShare[pointLength..]));
                        },
                    };
                }
                default:
                    throw new DtlsException(AlertDescription.InternalError, $"Group {Name(group)} is not supported.");
            }
        }

        /// <summary>The server's side: its key share and the shared secret for the client's <paramref name="clientShare"/>.</summary>
        internal static (byte[] Share, byte[] Secret) Respond(ushort group, byte[] clientShare)
        {
            switch (group)
            {
                case MlKem512:
                case MlKem768:
                case MlKem1024:
                    return Encapsulate(MlKemParameters(group), clientShare);

                case X25519MlKem768:
                {
                    Expect(clientShare, 1184 + 32);
                    var (ciphertext, kemSecret) = Encapsulate(Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768, clientShare[..1184]);
                    var (ecdh, ecdhSecret) = RespondClassical(X25519, clientShare[1184..]);
                    return (Concat(ciphertext, ecdh), Concat(kemSecret, ecdhSecret));
                }
                case SecP256r1MlKem768:
                case SecP384r1MlKem1024:
                {
                    ushort curve = group == SecP256r1MlKem768 ? Secp256r1 : Secp384r1;
                    var parameters = group == SecP256r1MlKem768
                        ? Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768
                        : Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_1024;
                    int pointLength = group == SecP256r1MlKem768 ? 65 : 97;
                    int keyLength = group == SecP256r1MlKem768 ? 1184 : 1568;
                    Expect(clientShare, pointLength + keyLength);
                    var (ecdh, ecdhSecret) = RespondClassical(curve, clientShare[..pointLength]);
                    var (ciphertext, kemSecret) = Encapsulate(parameters, clientShare[pointLength..]);
                    return (Concat(ecdh, ciphertext), Concat(ecdhSecret, kemSecret));
                }
                default:
                    return RespondClassical(group, clientShare);
            }
        }

        // ── (EC)DHE ──────────────────────────────────────────────────────────────────────────

        private static (byte[] Share, Func<byte[], byte[]> Agree) GenerateClassical(ushort group)
        {
            var random = new SecureRandom();
            switch (group)
            {
                case X25519:
                {
                    var key = new X25519PrivateKeyParameters(random);
                    return (key.GeneratePublicKey().GetEncoded(), peer =>
                    {
                        Expect(peer, 32);
                        return NonZero(Agree(new X25519Agreement(), key, new X25519PublicKeyParameters(peer, 0)));
                    });
                }
                case X448:
                {
                    var key = new X448PrivateKeyParameters(random);
                    return (key.GeneratePublicKey().GetEncoded(), peer =>
                    {
                        Expect(peer, 56);
                        return NonZero(Agree(new X448Agreement(), key, new X448PublicKeyParameters(peer, 0)));
                    });
                }
                case Secp256r1:
                case Secp384r1:
                case Secp521r1:
                {
                    var domain = Curve(group);
                    var generator = new ECKeyPairGenerator();
                    generator.Init(new ECKeyGenerationParameters(domain, random));
                    var pair = generator.GenerateKeyPair();
                    var key = (ECPrivateKeyParameters)pair.Private;
                    // RFC 8446 §4.2.8.2: uncompressed points; the secret is the x-coordinate, field-size long.
                    return (((ECPublicKeyParameters)pair.Public).Q.GetEncoded(false), peer => EcdhSecret(domain, key, peer));
                }
                default:
                {
                    var parameters = FfdheGroups.Parameters(group);
                    int length = (parameters.P.BitLength + 7) / 8;
                    var (x, y) = DhUtilities.GenerateKeyPair(parameters);
                    // RFC 8446 §4.2.8.1 / §7.4.1: values and the secret keep their leading zeros, as long as p.
                    return (BigIntegers.AsUnsignedByteArray(length, y), peer =>
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

        private static (byte[] Share, byte[] Secret) RespondClassical(ushort group, byte[] clientShare)
        {
            var (share, agree) = GenerateClassical(group);
            return (share, agree(clientShare));
        }

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
            string name = group switch { Secp256r1 => "P-256", Secp384r1 => "P-384", _ => "P-521" };
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

        // ── ML-KEM ───────────────────────────────────────────────────────────────────────────

        private static MLKemParameters MlKemParameters(ushort group) => group switch
        {
            MlKem512 => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_512,
            MlKem768 => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768,
            _ => Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_1024,
        };

        private static (byte[] EncapsulationKey, Func<byte[], byte[]> Decapsulate) GenerateMlKem(MLKemParameters parameters)
        {
            var generator = new MLKemKeyPairGenerator();
            generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), parameters));
            var pair = generator.GenerateKeyPair();
            return (((MLKemPublicKeyParameters)pair.Public).GetEncoded(), ciphertext =>
            {
                var decapsulator = new MLKemDecapsulator(parameters);
                decapsulator.Init(pair.Private);
                Expect(ciphertext, decapsulator.EncapsulationLength);
                byte[] secret = new byte[decapsulator.SecretLength];
                decapsulator.Decapsulate(ciphertext, secret);
                return secret;
            });
        }

        private static (byte[] Ciphertext, byte[] Secret) Encapsulate(MLKemParameters parameters, byte[] encapsulationKey)
        {
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
            byte[] secret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, secret);
            return (ciphertext, secret);
        }

        private static void Expect(byte[] value, int length)
        {
            if (value == null || value.Length != length)
                throw new DtlsException(AlertDescription.IllegalParameter, $"Key share is {value?.Length ?? 0} bytes, expected {length}.");
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }
    }
}
