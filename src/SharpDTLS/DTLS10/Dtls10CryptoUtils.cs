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
using SharpDTLS.DTLS10.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10
{
    public static class Dtls10CryptoUtils
    {
        private static readonly byte[] _cookieKey;

        static Dtls10CryptoUtils()
        {
            _cookieKey = new byte[32];
            new SecureRandom().NextBytes(_cookieKey);
        }

        // TLS 1.0 PRF = P_MD5(S1, label+seed) XOR P_SHA1(S2, label+seed)
        // S1 = first ceil(len/2) bytes of secret, S2 = last ceil(len/2) bytes
        public static byte[] PRF(byte[] secret, string label, byte[] seed, int length)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            byte[] fullSeed   = labelBytes.Concat(seed).ToArray();

            int halfLen = (secret.Length + 1) / 2;
            byte[] s1 = secret.Take(halfLen).ToArray();
            byte[] s2 = secret.Skip(secret.Length / 2).ToArray();

            byte[] pMd5  = P_MD5(s1, fullSeed, length);
            byte[] pSha1 = P_SHA1(s2, fullSeed, length);

            byte[] result = new byte[length];
            for (int i = 0; i < length; i++)
                result[i] = (byte)(pMd5[i] ^ pSha1[i]);
            return result;
        }

        private static byte[] P_MD5(byte[] secret, byte[] seed, int length)
        {
            var result = new List<byte>();
            var hmac   = new HMac(new MD5Digest());

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

        private static byte[] P_SHA1(byte[] secret, byte[] seed, int length)
        {
            var result = new List<byte>();
            var hmac   = new HMac(new Sha1Digest());

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

        public static byte[] CalculateMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom)
        {
            byte[] seed = clientRandom.Concat(serverRandom).ToArray();
            return PRF(preMasterSecret, "master secret", seed, 48);
        }

        // RFC 5705 §4: PRF(master_secret, label, client_random + server_random [+ context_length + context])
        public static byte[] ExportKeyingMaterial(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom,
            string label, byte[] context, int length)
        {
            return PRF(masterSecret, label, DTLS12.Dtls12CryptoUtils.BuildExporterSeed(clientRandom, serverRandom, context), length);
        }

        // RFC 7627 §4: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..47]
        // where session_hash is MD5 || SHA1 of the handshake messages up to and including ClientKeyExchange.
        public static byte[] CalculateExtendedMasterSecret(byte[] preMasterSecret, byte[] sessionHash)
        {
            return PRF(preMasterSecret, "extended master secret", sessionHash, 48);
        }

        // Key block: clientMacKey(20) + serverMacKey(20) + clientKey(keyLen) + serverKey(keyLen)
        // keyLen: 16 for AES-128 suites (0xC013, 0xC009), 32 for AES-256 (0xC014, 0xC00A)
        public static Dtls10CryptoContext DeriveKeys(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, ushort cipherSuite = 0xC013)
        {
            int keyLen = cipherSuite == 0xC014 || cipherSuite == 0xC00A ? 32 : 16;
            int keyBlockLen = 20 + 20 + keyLen + keyLen;

            byte[] seed     = serverRandom.Concat(clientRandom).ToArray();
            byte[] keyBlock = PRF(masterSecret, "key expansion", seed, keyBlockLen);

            byte[] clientMacKey = keyBlock.Take(20).ToArray();
            byte[] serverMacKey = keyBlock.Skip(20).Take(20).ToArray();
            byte[] clientKey    = keyBlock.Skip(40).Take(keyLen).ToArray();
            byte[] serverKey    = keyBlock.Skip(40 + keyLen).Take(keyLen).ToArray();

            return new Dtls10CryptoContext(masterSecret, clientMacKey, serverMacKey, clientKey, serverKey);
        }

        // Finished verify_data: PRF(master, label, MD5(messages) || SHA1(messages))[0..11]
        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash)
        {
            return PRF(masterSecret, label, transcriptHash, 12);
        }

        // Returns MD5(messages) || SHA1(messages) = 36 bytes (TLS 1.0/1.1 convention).
        // Each message contributes its 12-byte DTLS handshake header + body (record header stripped).
        public static byte[] HashTranscript(List<IDatagram> messages)
        {
            var md5  = new MD5Digest();
            var sha1 = new Sha1Digest();

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

                md5.BlockUpdate(contribution, 0, contribution.Length);
                sha1.BlockUpdate(contribution, 0, contribution.Length);
            }

            byte[] md5Hash  = new byte[md5.GetDigestSize()];
            byte[] sha1Hash = new byte[sha1.GetDigestSize()];
            md5.DoFinal(md5Hash, 0);
            sha1.DoFinal(sha1Hash, 0);

            return md5Hash.Concat(sha1Hash).ToArray(); // 16 + 20 = 36 bytes
        }

        // Returns the raw concatenation of all handshake message contributions (not hashed).
        // Used for CertificateVerify signature input — each signer applies its own hash internally.
        public static byte[] GetTranscriptBytes(List<IDatagram> messages)
        {
            var result = new List<byte>();
            foreach (var msg in messages)
            {
                IDatagram m   = msg;
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
