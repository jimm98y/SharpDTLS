using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
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

        // For TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        //   clientMacKey(20) + serverMacKey(20) + clientKey(16) + serverKey(16) = 72 bytes
        public static Dtls10CryptoContext DeriveKeys(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom)
        {
            byte[] seed     = serverRandom.Concat(clientRandom).ToArray();
            byte[] keyBlock = PRF(masterSecret, "key expansion", seed, 72);

            byte[] clientMacKey = keyBlock.Take(20).ToArray();
            byte[] serverMacKey = keyBlock.Skip(20).Take(20).ToArray();
            byte[] clientKey    = keyBlock.Skip(40).Take(16).ToArray();
            byte[] serverKey    = keyBlock.Skip(56).Take(16).ToArray();

            return new Dtls10CryptoContext(masterSecret, clientMacKey, serverMacKey, clientKey, serverKey);
        }

        // Finished verify_data: PRF(master, label, MD5(messages) || SHA1(messages))[0..11]
        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash)
        {
            return PRF(masterSecret, label, transcriptHash, 12);
        }

        // Returns MD5(messages) || SHA1(messages) = 36 bytes (TLS 1.0/1.1 convention).
        // Each message contributes: type(1) + length(3) + body
        // (stripping the 13-byte DTLS record header and the 8-byte DTLS reconstruction fields)
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
                // type(1) + length(3) — skip reconstruction fields (msg_seq + frag_offset + frag_len = 8 bytes)
                byte[] contribution = bytes.Skip(skip).Take(4)
                    .Concat(bytes.Skip(skip + 4 + 8).Take(bytes.Length - skip - 4 - 8))
                    .ToArray();

                md5.BlockUpdate(contribution, 0, contribution.Length);
                sha1.BlockUpdate(contribution, 0, contribution.Length);
            }

            byte[] md5Hash  = new byte[md5.GetDigestSize()];
            byte[] sha1Hash = new byte[sha1.GetDigestSize()];
            md5.DoFinal(md5Hash, 0);
            sha1.DoFinal(sha1Hash, 0);

            return md5Hash.Concat(sha1Hash).ToArray(); // 16 + 20 = 36 bytes
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
    }
}
