using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS12
{
    public static class Dtls12CryptoUtils
    {
        private static readonly byte[] _cookieKey;

        static Dtls12CryptoUtils()
        {
            _cookieKey = new byte[32];
            new SecureRandom().NextBytes(_cookieKey);
        }

        // TLS 1.2 PRF = P_SHA256
        public static byte[] PRF(byte[] secret, string label, byte[] seed, int length)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            byte[] fullSeed = labelBytes.Concat(seed).ToArray();
            return P_SHA256(secret, fullSeed, length);
        }

        private static byte[] P_SHA256(byte[] secret, byte[] seed, int length)
        {
            var result = new List<byte>();
            var hmac = new HMac(new Sha256Digest());

            // A(1) = HMAC(secret, seed)
            hmac.Init(new KeyParameter(secret));
            hmac.BlockUpdate(seed, 0, seed.Length);
            byte[] a = new byte[hmac.GetMacSize()];
            hmac.DoFinal(a, 0);

            while (result.Count < length)
            {
                // output_i = HMAC(secret, A(i) + seed)
                hmac.Reset();
                hmac.Init(new KeyParameter(secret));
                hmac.BlockUpdate(a, 0, a.Length);
                hmac.BlockUpdate(seed, 0, seed.Length);
                byte[] output = new byte[hmac.GetMacSize()];
                hmac.DoFinal(output, 0);
                result.AddRange(output);

                // A(i+1) = HMAC(secret, A(i))
                hmac.Reset();
                hmac.Init(new KeyParameter(secret));
                hmac.BlockUpdate(a, 0, a.Length);
                byte[] newA = new byte[hmac.GetMacSize()];
                hmac.DoFinal(newA, 0);
                a = newA;
            }

            return result.Take(length).ToArray();
        }

        public static byte[] CalculateMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom)
        {
            byte[] seed = clientRandom.Concat(serverRandom).ToArray();
            return PRF(preMasterSecret, "master secret", seed, 48);
        }

        // Derives keys for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        // client_write_key(16) + server_write_key(16) + client_write_IV(4) + server_write_IV(4)
        public static Dtls12CryptoContext DeriveKeys(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom)
        {
            byte[] seed = serverRandom.Concat(clientRandom).ToArray();
            byte[] keyBlock = PRF(masterSecret, "key expansion", seed, 40);

            byte[] clientKey = keyBlock.Take(16).ToArray();
            byte[] serverKey = keyBlock.Skip(16).Take(16).ToArray();
            byte[] clientIv  = keyBlock.Skip(32).Take(4).ToArray();
            byte[] serverIv  = keyBlock.Skip(36).Take(4).ToArray();

            return new Dtls12CryptoContext(masterSecret, clientKey, serverKey, clientIv, serverIv);
        }

        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash)
        {
            return PRF(masterSecret, label, transcriptHash, 12);
        }

        // Hash the DTLS 1.2 handshake transcript using the TLS convention:
        // each message contributes: msg_type(1) + length(3) + body
        // (stripping the 13-byte DTLS record header and the 8-byte DTLS reconstruction fields)
        public static byte[] HashTranscript(List<IDatagram> messages)
        {
            var hash = new Sha256Digest();

            foreach (var msg in messages)
            {
                IDatagram msgToHash = msg;
                int skip = 13; // skip DTLS record header

                if (msg is ClientEncryptedDatagram clientEnc)
                {
                    msgToHash = clientEnc.Datagram;
                    skip = 0;
                }
                else if (msg is ServerEncryptedDatagram serverEnc)
                {
                    msgToHash = serverEnc.Datagram;
                    skip = 0;
                }

                byte[] bytes = msgToHash.Bytes;
                // type(1) + length(3) — skip reconstruction fields (msg_seq + frag_offset + frag_len = 8 bytes)
                byte[] contribution = bytes.Skip(skip).Take(4)
                    .Concat(bytes.Skip(skip + 4 + 8).Take(bytes.Length - skip - 4 - 8))
                    .ToArray();

                hash.BlockUpdate(contribution, 0, contribution.Length);
            }

            byte[] result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);
            return result;
        }

        public static byte[] CreateCookie(DateTime timestamp, string clientIP, int clientPort, int minuteOffset = 0)
        {
            DateTime rounded = new DateTime(timestamp.Year, timestamp.Month, timestamp.Day,
                timestamp.Hour, timestamp.Minute, 0, DateTimeKind.Utc)
                .AddMinutes(minuteOffset);

            string data = $"{clientIP}:{clientPort}:{rounded.ToFileTime()}";
            using var hmac = new System.Security.Cryptography.HMACSHA256(_cookieKey);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public static bool ValidateCookie(DateTime timestamp, string clientIP, int clientPort, byte[] cookie)
        {
            byte[] expected = CreateCookie(timestamp, clientIP, clientPort);
            if (expected.SequenceEqual(cookie)) return true;
            expected = CreateCookie(timestamp, clientIP, clientPort, -1);
            return expected.SequenceEqual(cookie);
        }

        public static (X25519PrivateKeyParameters privateX25519, X25519PublicKeyParameters publicX25519) CreateX25519KeyPair()
        {
            X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = x25519KeyPairGenerator.GenerateKeyPair();
            return (keyPair.Private as X25519PrivateKeyParameters, keyPair.Public as X25519PublicKeyParameters);
        }

        public static byte[] GenerateRandom(int length)
        {
            var clientRandom = new byte[length];
            var secureRandom = new SecureRandom();
            secureRandom.NextBytes(clientRandom);
            return clientRandom;
        }

        public static byte[] DeriveSharedSecretX25519(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (privateKey.Length != 32) throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
            if (publicKey.Length != 32) throw new ArgumentException("Public key must be 32 bytes.", nameof(publicKey));

            var priv = new X25519PrivateKeyParameters(privateKey, 0);
            var pub = new X25519PublicKeyParameters(publicKey, 0);

            var shared = new byte[32];
            priv.GenerateSecret(pub, shared, 0);
            return shared;
        }

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) GenerateSelfSignedCertificate()
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetIssuerDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetSubjectDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certGenerator.SetPublicKey(keyPair.Public);
            var certificate = certGenerator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private, new SecureRandom()));

            return (keyPair, certificate);
        }

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) GenerateSelfSignedEcCertificate()
        {
            var ecCurve = ECNamedCurveTable.GetByName("P-256");
            var domainParams = new ECDomainParameters(ecCurve.Curve, ecCurve.G, ecCurve.N, ecCurve.H);
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
            var keyPair = ecGenerator.GenerateKeyPair();

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetIssuerDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetSubjectDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certGenerator.SetPublicKey(keyPair.Public);
            var certificate = certGenerator.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private, new SecureRandom()));

            return (keyPair, certificate);
        }
    }
}
