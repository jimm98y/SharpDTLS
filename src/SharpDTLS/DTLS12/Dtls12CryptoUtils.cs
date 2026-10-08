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

        // TLS 1.2 PRF: P_SHA256 by default; P_SHA384 for AES-256-GCM-SHA384 suites.
        public static byte[] PRF(byte[] secret, string label, byte[] seed, int length, bool useSha384 = false)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            byte[] fullSeed = labelBytes.Concat(seed).ToArray();
            return useSha384 ? P_Hash(new Sha384Digest(), secret, fullSeed, length)
                             : P_Hash(new Sha256Digest(), secret, fullSeed, length);
        }

        private static byte[] P_Hash(IDigest digest, byte[] secret, byte[] seed, int length)
        {
            var result = new List<byte>();
            var hmac = new HMac(digest);

            hmac.Init(new KeyParameter(secret));
            hmac.BlockUpdate(seed, 0, seed.Length);
            byte[] a = new byte[hmac.GetMacSize()];
            hmac.DoFinal(a, 0);

            while (result.Count < length)
            {
                hmac.Reset();
                hmac.Init(new KeyParameter(secret));
                hmac.BlockUpdate(a, 0, a.Length);
                hmac.BlockUpdate(seed, 0, seed.Length);
                byte[] output = new byte[hmac.GetMacSize()];
                hmac.DoFinal(output, 0);
                result.AddRange(output);

                hmac.Reset();
                hmac.Init(new KeyParameter(secret));
                hmac.BlockUpdate(a, 0, a.Length);
                byte[] newA = new byte[hmac.GetMacSize()];
                hmac.DoFinal(newA, 0);
                a = newA;
            }

            return result.Take(length).ToArray();
        }

        public static byte[] CalculateMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom, bool useSha384 = false)
        {
            byte[] seed = clientRandom.Concat(serverRandom).ToArray();
            return PRF(preMasterSecret, "master secret", seed, 48, useSha384);
        }

        // RFC 5705 §4: PRF(master_secret, label, client_random + server_random [+ context_length + context])
        public static byte[] ExportKeyingMaterial(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom,
            string label, byte[] context, int length, bool useSha384 = false)
        {
            byte[] seed = BuildExporterSeed(clientRandom, serverRandom, context);
            return PRF(masterSecret, label, seed, length, useSha384);
        }

        internal static byte[] BuildExporterSeed(byte[] clientRandom, byte[] serverRandom, byte[] context)
        {
            int contextLength = context == null ? 0 : 2 + context.Length;
            byte[] seed = new byte[64 + contextLength];
            Buffer.BlockCopy(clientRandom, 0, seed, 0, 32);
            Buffer.BlockCopy(serverRandom, 0, seed, 32, 32);
            if (context != null)
            {
                if (context.Length > 0xFFFF) throw new ArgumentException("Exporter context too long.", nameof(context));
                seed[64] = (byte)(context.Length >> 8);
                seed[65] = (byte)context.Length;
                Buffer.BlockCopy(context, 0, seed, 66, context.Length);
            }
            return seed;
        }

        // RFC 7627 §4: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..47]
        // where session_hash is the transcript hash up to and including ClientKeyExchange.
        public static byte[] CalculateExtendedMasterSecret(byte[] preMasterSecret, byte[] sessionHash, bool useSha384 = false)
        {
            return PRF(preMasterSecret, "extended master secret", sessionHash, 48, useSha384);
        }

        // Key block layout:
        //   AES-128-GCM (0xC02F, 0xC02B):  clientKey(16)+serverKey(16)+clientIV(4)+serverIV(4)   = 40 bytes, P_SHA256
        //   AES-256-GCM (0xC030, 0xC02C):  clientKey(32)+serverKey(32)+clientIV(4)+serverIV(4)   = 72 bytes, P_SHA384
        //   ChaCha20    (0xCCA8, 0xCCA9):  clientKey(32)+serverKey(32)+clientIV(12)+serverIV(12) = 88 bytes, P_SHA256
        public static Dtls12CryptoContext DeriveKeys(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, ushort cipherSuite = 0xC02F)
        {
            bool isChaCha20 = cipherSuite == 0xCCA8 || cipherSuite == 0xCCA9;
            bool useSha384  = cipherSuite == 0xC030 || cipherSuite == 0xC02C;
            int  keyLen     = (cipherSuite == 0xC02F || cipherSuite == 0xC02B) ? 16 : 32;
            int  ivLen      = isChaCha20 ? 12 : 4;
            int  keyBlockLen = 2 * keyLen + 2 * ivLen;

            byte[] seed     = serverRandom.Concat(clientRandom).ToArray();
            byte[] keyBlock = PRF(masterSecret, "key expansion", seed, keyBlockLen, useSha384);

            byte[] clientKey = keyBlock.Take(keyLen).ToArray();
            byte[] serverKey = keyBlock.Skip(keyLen).Take(keyLen).ToArray();
            byte[] clientIv  = keyBlock.Skip(2 * keyLen).Take(ivLen).ToArray();
            byte[] serverIv  = keyBlock.Skip(2 * keyLen + ivLen).Take(ivLen).ToArray();

            return new Dtls12CryptoContext(masterSecret, clientKey, serverKey, clientIv, serverIv, cipherSuite);
        }

        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash, bool useSha384 = false)
        {
            return PRF(masterSecret, label, transcriptHash, 12, useSha384);
        }

        // Hash the DTLS 1.2 handshake transcript.
        // SHA-384 is used for cipher suites whose PRF is P_SHA384 (AES-256-GCM-SHA384).
        public static byte[] HashTranscript(List<IDatagram> messages, bool useSha384 = false)
        {
            IDigest hash = useSha384 ? (IDigest)new Sha384Digest() : new Sha256Digest();

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
                byte[] contribution = DtlsHandshakeHash.Contribution(bytes, skip);

                hash.BlockUpdate(contribution, 0, contribution.Length);
            }

            byte[] result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);
            return result;
        }

        // Returns the raw concatenation of all handshake message contributions (not hashed).
        // Used for CertificateVerify signature input — each signer applies its own hash internally.
        public static byte[] GetTranscriptBytes(List<IDatagram> messages)
        {
            var result = new List<byte>();
            foreach (var msg in messages)
            {
                IDatagram m    = msg;
                int        skip = 13;

                if (msg is ClientEncryptedDatagram ce) { m = ce.Datagram; skip = 0; }
                else if (msg is ServerEncryptedDatagram se) { m = se.Datagram; skip = 0; }

                byte[] bytes = m.Bytes;
                byte[] contribution = DtlsHandshakeHash.Contribution(bytes, skip);
                result.AddRange(contribution);
            }
            return result.ToArray();
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
            // Named curve (OID) parameters: RFC 5480 §2.1.1 forbids explicit curve parameters in certificates,
            // and platform validators (e.g. Apple's) reject them.
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
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
