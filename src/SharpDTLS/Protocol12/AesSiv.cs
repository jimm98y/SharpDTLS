using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// SIV-AES deterministic authenticated encryption (RFC 5297). Keys are 256, 384 or 512 bits: the first half
    /// keys S2V (AES-CMAC), the second half keys CTR.
    /// </summary>
    internal static class AesSiv
    {
        private const int BlockSize = 16;

        /// <summary>Returns V || C for <paramref name="plaintext"/> and the associated data vector.</summary>
        public static byte[] Encrypt(byte[] key, byte[] plaintext, params byte[][] associatedData)
        {
            var (k1, k2) = Split(key);
            byte[] v = S2V(k1, associatedData, plaintext);
            byte[] z = new byte[BlockSize + plaintext.Length];
            v.CopyTo(z, 0);
            Ctr(k2, v, plaintext).CopyTo(z, BlockSize);
            return z;
        }

        /// <summary>Returns the plaintext, or null when <paramref name="z"/> fails authentication.</summary>
        public static byte[] Decrypt(byte[] key, byte[] z, params byte[][] associatedData)
        {
            if (z.Length < BlockSize)
                return null;
            var (k1, k2) = Split(key);
            byte[] v = z.AsSpan(0, BlockSize).ToArray();
            byte[] plaintext = Ctr(k2, v, z.AsSpan(BlockSize).ToArray());
            return CryptographicOperations.FixedTimeEquals(v, S2V(k1, associatedData, plaintext)) ? plaintext : null;
        }

        private static (byte[] K1, byte[] K2) Split(byte[] key)
        {
            if (key.Length is not (32 or 48 or 64))
                throw new ArgumentException("SIV keys are 256, 384 or 512 bits.", nameof(key));
            return (key.AsSpan(0, key.Length / 2).ToArray(), key.AsSpan(key.Length / 2).ToArray());
        }

        // S2V (RFC 5297 §2.4) over the associated data followed by the plaintext.
        private static byte[] S2V(byte[] key, byte[][] associatedData, byte[] plaintext)
        {
            byte[] d = Cmac(key, new byte[BlockSize]);
            foreach (byte[] ad in associatedData)
                d = Xor(Dbl(d), Cmac(key, ad));

            byte[] t;
            if (plaintext.Length >= BlockSize)
            {
                // T = Sn xorend D
                t = (byte[])plaintext.Clone();
                for (int i = 0; i < BlockSize; i++)
                    t[t.Length - BlockSize + i] ^= d[i];
            }
            else
            {
                // T = dbl(D) xor pad(Sn), pad = Sn || 1 || 0*
                byte[] padded = new byte[BlockSize];
                plaintext.CopyTo(padded, 0);
                padded[plaintext.Length] = 0x80;
                t = Xor(Dbl(d), padded);
            }
            return Cmac(key, t);
        }

        private static byte[] Ctr(byte[] key, byte[] v, byte[] input)
        {
            // Q = V with bits 63 and 31 (counting from the right) cleared.
            byte[] q = (byte[])v.Clone();
            q[8] &= 0x7f;
            q[12] &= 0x7f;

            var ctr = new SicBlockCipher(new AesEngine());
            ctr.Init(true, new ParametersWithIV(new KeyParameter(key), q));
            byte[] output = new byte[input.Length];
            byte[] block = new byte[BlockSize];
            for (int offset = 0; offset < input.Length; offset += BlockSize)
            {
                int n = Math.Min(BlockSize, input.Length - offset);
                input.AsSpan(offset, n).CopyTo(block);
                ctr.ProcessBlock(block, 0, block, 0);
                block.AsSpan(0, n).CopyTo(output.AsSpan(offset));
            }
            return output;
        }

        private static byte[] Cmac(byte[] key, byte[] data)
        {
            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[BlockSize];
            cmac.DoFinal(result, 0);
            return result;
        }

        // Doubling in GF(2^128) (RFC 5297 §2.3).
        private static byte[] Dbl(byte[] s)
        {
            byte[] result = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
                result[i] = (byte)((s[i] << 1) | (i + 1 < BlockSize ? s[i + 1] >> 7 : 0));
            if ((s[0] & 0x80) != 0)
                result[BlockSize - 1] ^= 0x87;
            return result;
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}
