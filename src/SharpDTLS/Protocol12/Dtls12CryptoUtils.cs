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

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Linq;
using System.Text;

namespace SharpDTLS.Protocol12
{
    internal static class Dtls12CryptoUtils
    {
        private static readonly byte[] _cookieKey;

        static Dtls12CryptoUtils()
        {
            _cookieKey = new byte[32];
            new SecureRandom().NextBytes(_cookieKey);
        }

        // TLS 1.2 PRF: P_SHA256 by default; P_SHA384 for AES-256-GCM-SHA384 suites.
        public static byte[] PRF(byte[] secret, string label, byte[] seed, int length, bool useSha384 = false, ITlsCrypto crypto = null)
        {
            byte[] fullSeed = Encoding.ASCII.GetBytes(label).Concat(seed).ToArray();
            return TlsKdf.PHash(crypto ?? BouncyCastleTlsCrypto.Default, useSha384 ? TlsHashAlgorithm.Sha384 : TlsHashAlgorithm.Sha256, secret, fullSeed, length);
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

        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash, bool useSha384 = false)
        {
            return PRF(masterSecret, label, transcriptHash, 12, useSha384);
        }

        // Hash the DTLS 1.2 handshake transcript.
        // SHA-384 is used for cipher suites whose PRF is P_SHA384 (AES-256-GCM-SHA384).

        // Returns the raw concatenation of all handshake message contributions (not hashed).
        // Used for CertificateVerify signature input — each signer applies its own hash internally.

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
            if (cookie == null)
                return false;
            byte[] expected = CreateCookie(timestamp, clientIP, clientPort);
            if (System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, cookie)) return true;
            expected = CreateCookie(timestamp, clientIP, clientPort, -1);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, cookie);
        }


        public static byte[] GenerateRandom(int length)
        {
            var clientRandom = new byte[length];
            var secureRandom = new SecureRandom();
            secureRandom.NextBytes(clientRandom);
            return clientRandom;
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
