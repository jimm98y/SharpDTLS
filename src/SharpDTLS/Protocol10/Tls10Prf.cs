using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDTLS.Protocol10
{
    /// <summary>
    /// The TLS 1.0/1.1 PRF (RFC 2246 §5, RFC 4346 §5) and what is derived with it: master secret, extended master
    /// secret, Finished verify_data and exported keying material. DTLS 1.0 uses it unchanged.
    /// </summary>
    public static class Tls10Prf
    {
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
            return PRF(masterSecret, label, SharpDTLS.Protocol12.Dtls12CryptoUtils.BuildExporterSeed(clientRandom, serverRandom, context), length);
        }

        // RFC 7627 §4: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..47]
        // where session_hash is MD5 || SHA1 of the handshake messages up to and including ClientKeyExchange.
        public static byte[] CalculateExtendedMasterSecret(byte[] preMasterSecret, byte[] sessionHash)
        {
            return PRF(preMasterSecret, "extended master secret", sessionHash, 48);
        }

        // Finished verify_data: PRF(master, label, MD5(messages) || SHA1(messages))[0..11]
        public static byte[] CalculateVerifyData(byte[] masterSecret, string label, byte[] transcriptHash)
        {
            return PRF(masterSecret, label, transcriptHash, 12);
        }
    }
}
