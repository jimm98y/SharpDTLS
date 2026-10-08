using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using ArmAes = System.Runtime.Intrinsics.Arm.Aes;
using X86Aes = System.Runtime.Intrinsics.X86.Aes;

namespace SharpDTLS
{
    /// <summary>
    /// AEGIS-128L and AEGIS-256 (draft-irtf-cfrg-aegis-aead-08, the revision the TLS cipher suites cite).
    /// Encrypt returns ct || tag; Decrypt returns the plaintext, or null when the tag does not verify.
    /// </summary>
    internal static class Aegis
    {
        private static readonly Vector128<byte> C0 = Vector128.Create(
            (byte)0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62);
        private static readonly Vector128<byte> C1 = Vector128.Create(
            (byte)0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd);

        // ── AEGIS-128L: eight 128-bit blocks, 256-bit rate ───────────────────────────────────

        public static byte[] Encrypt128L(byte[] key, byte[] nonce, byte[] ad, byte[] msg, int tagLength = 16)
        {
            var s = Init128L(key, nonce);
            Absorb(ad, 32, block => Update128L(s, Load(block, 0), Load(block, 16)));

            byte[] output = new byte[msg.Length + tagLength];
            byte[] block = new byte[32];
            for (int offset = 0; offset < msg.Length; offset += 32)
            {
                int n = Math.Min(32, msg.Length - offset);
                Array.Clear(block);
                msg.AsSpan(offset, n).CopyTo(block);
                var t0 = Load(block, 0);
                var t1 = Load(block, 16);
                var (z0, z1) = Keystream128L(s);
                Store(t0 ^ z0, block, 0);
                Store(t1 ^ z1, block, 16);
                Update128L(s, t0, t1);
                block.AsSpan(0, n).CopyTo(output.AsSpan(offset));
            }

            Finalize128L(s, ad.Length, msg.Length, tagLength).CopyTo(output, msg.Length);
            return output;
        }

        public static byte[] Decrypt128L(byte[] key, byte[] nonce, byte[] ad, byte[] ctAndTag, int tagLength = 16)
        {
            if (ctAndTag.Length < tagLength)
                return null;
            int length = ctAndTag.Length - tagLength;
            var s = Init128L(key, nonce);
            Absorb(ad, 32, block => Update128L(s, Load(block, 0), Load(block, 16)));

            byte[] msg = new byte[length];
            byte[] block = new byte[32];
            for (int offset = 0; offset < length; offset += 32)
            {
                int n = Math.Min(32, length - offset);
                Array.Clear(block);
                ctAndTag.AsSpan(offset, n).CopyTo(block);
                var (z0, z1) = Keystream128L(s);
                Store(Load(block, 0) ^ z0, block, 0);
                Store(Load(block, 16) ^ z1, block, 16);
                // DecPartial: the state absorbs the zero-padded plaintext, not the keystream tail.
                block.AsSpan(n).Clear();
                Update128L(s, Load(block, 0), Load(block, 16));
                block.AsSpan(0, n).CopyTo(msg.AsSpan(offset));
            }

            return Verify(Finalize128L(s, ad.Length, length, tagLength), ctAndTag.AsSpan(length), msg);
        }

        private static Vector128<byte>[] Init128L(byte[] key, byte[] nonce)
        {
            var k = Load(key, 0);
            var n = Load(nonce, 0);
            var s = new[] { k ^ n, C1, C0, C1, k ^ n, k ^ C0, k ^ C1, k ^ C0 };
            for (int i = 0; i < 10; i++)
                Update128L(s, n, k);
            return s;
        }

        internal static void Update128L(Vector128<byte>[] s, Vector128<byte> m0, Vector128<byte> m1)
        {
            var s7 = s[7];
            s[7] = AesRound(s[6], s7);
            s[6] = AesRound(s[5], s[6]);
            s[5] = AesRound(s[4], s[5]);
            s[4] = AesRound(s[3], s[4] ^ m1);
            s[3] = AesRound(s[2], s[3]);
            s[2] = AesRound(s[1], s[2]);
            s[1] = AesRound(s[0], s[1]);
            s[0] = AesRound(s7, s[0] ^ m0);
        }

        private static (Vector128<byte>, Vector128<byte>) Keystream128L(Vector128<byte>[] s)
            => (s[6] ^ s[1] ^ (s[2] & s[3]), s[2] ^ s[5] ^ (s[6] & s[7]));

        private static byte[] Finalize128L(Vector128<byte>[] s, int adLength, int msgLength, int tagLength)
        {
            var t = s[2] ^ Lengths(adLength, msgLength);
            for (int i = 0; i < 7; i++)
                Update128L(s, t, t);
            return tagLength == 16
                ? ToArray(s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[6])
                : Concat(s[0] ^ s[1] ^ s[2] ^ s[3], s[4] ^ s[5] ^ s[6] ^ s[7]);
        }

        // ── AEGIS-256: six 128-bit blocks, 128-bit rate ──────────────────────────────────────

        public static byte[] Encrypt256(byte[] key, byte[] nonce, byte[] ad, byte[] msg, int tagLength = 16)
        {
            var s = Init256(key, nonce);
            Absorb(ad, 16, block => Update256(s, Load(block, 0)));

            byte[] output = new byte[msg.Length + tagLength];
            byte[] block = new byte[16];
            for (int offset = 0; offset < msg.Length; offset += 16)
            {
                int n = Math.Min(16, msg.Length - offset);
                Array.Clear(block);
                msg.AsSpan(offset, n).CopyTo(block);
                var x = Load(block, 0);
                Store(x ^ Keystream256(s), block, 0);
                Update256(s, x);
                block.AsSpan(0, n).CopyTo(output.AsSpan(offset));
            }

            Finalize256(s, ad.Length, msg.Length, tagLength).CopyTo(output, msg.Length);
            return output;
        }

        public static byte[] Decrypt256(byte[] key, byte[] nonce, byte[] ad, byte[] ctAndTag, int tagLength = 16)
        {
            if (ctAndTag.Length < tagLength)
                return null;
            int length = ctAndTag.Length - tagLength;
            var s = Init256(key, nonce);
            Absorb(ad, 16, block => Update256(s, Load(block, 0)));

            byte[] msg = new byte[length];
            byte[] block = new byte[16];
            for (int offset = 0; offset < length; offset += 16)
            {
                int n = Math.Min(16, length - offset);
                Array.Clear(block);
                ctAndTag.AsSpan(offset, n).CopyTo(block);
                Store(Load(block, 0) ^ Keystream256(s), block, 0);
                block.AsSpan(n).Clear();
                Update256(s, Load(block, 0));
                block.AsSpan(0, n).CopyTo(msg.AsSpan(offset));
            }

            return Verify(Finalize256(s, ad.Length, length, tagLength), ctAndTag.AsSpan(length), msg);
        }

        private static Vector128<byte>[] Init256(byte[] key, byte[] nonce)
        {
            var k0 = Load(key, 0);
            var k1 = Load(key, 16);
            var n0 = Load(nonce, 0);
            var n1 = Load(nonce, 16);
            var s = new[] { k0 ^ n0, k1 ^ n1, C1, C0, k0 ^ C0, k1 ^ C1 };
            for (int i = 0; i < 4; i++)
            {
                Update256(s, k0);
                Update256(s, k1);
                Update256(s, k0 ^ n0);
                Update256(s, k1 ^ n1);
            }
            return s;
        }

        internal static void Update256(Vector128<byte>[] s, Vector128<byte> m)
        {
            var s5 = s[5];
            s[5] = AesRound(s[4], s5);
            s[4] = AesRound(s[3], s[4]);
            s[3] = AesRound(s[2], s[3]);
            s[2] = AesRound(s[1], s[2]);
            s[1] = AesRound(s[0], s[1]);
            s[0] = AesRound(s5, s[0] ^ m);
        }

        private static Vector128<byte> Keystream256(Vector128<byte>[] s) => s[1] ^ s[4] ^ s[5] ^ (s[2] & s[3]);

        private static byte[] Finalize256(Vector128<byte>[] s, int adLength, int msgLength, int tagLength)
        {
            var t = s[3] ^ Lengths(adLength, msgLength);
            for (int i = 0; i < 7; i++)
                Update256(s, t);
            return tagLength == 16
                ? ToArray(s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5])
                : Concat(s[0] ^ s[1] ^ s[2], s[3] ^ s[4] ^ s[5]);
        }

        // ── Shared helpers ───────────────────────────────────────────────────────────────────

        /// <summary>Stream(len, key, nonce): the encryption of len zero bytes, without the tag.</summary>
        public static byte[] Stream128L(int length, byte[] key, byte[] nonce)
            => Encrypt128L(key, nonce, Array.Empty<byte>(), new byte[length]).AsSpan(0, length).ToArray();

        public static byte[] Stream256(int length, byte[] key, byte[] nonce)
            => Encrypt256(key, nonce, Array.Empty<byte>(), new byte[length]).AsSpan(0, length).ToArray();

        private static void Absorb(byte[] ad, int rate, Action<byte[]> absorb)
        {
            byte[] block = new byte[rate];
            for (int offset = 0; offset < ad.Length; offset += rate)
            {
                Array.Clear(block);
                ad.AsSpan(offset, Math.Min(rate, ad.Length - offset)).CopyTo(block);
                absorb(block);
            }
        }

        private static byte[] Verify(byte[] expectedTag, ReadOnlySpan<byte> tag, byte[] msg)
        {
            if (CryptographicOperations.FixedTimeEquals(expectedTag, tag))
                return msg;
            CryptographicOperations.ZeroMemory(msg);
            return null;
        }

        // LE64(ad_len_bits) || LE64(msg_len_bits)
        private static Vector128<byte> Lengths(int adLength, int msgLength)
        {
            byte[] lengths = new byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)adLength * 8);
            BinaryPrimitives.WriteUInt64LittleEndian(lengths.AsSpan(8), (ulong)msgLength * 8);
            return Load(lengths, 0);
        }

        private static Vector128<byte> Load(byte[] source, int offset) => Vector128.Create(source.AsSpan(offset, 16));
        private static void Store(Vector128<byte> value, byte[] destination, int offset) => value.CopyTo(destination.AsSpan(offset, 16));

        private static byte[] ToArray(Vector128<byte> value)
        {
            byte[] result = new byte[16];
            value.CopyTo(result);
            return result;
        }

        private static byte[] Concat(Vector128<byte> a, Vector128<byte> b)
        {
            byte[] result = new byte[32];
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(16));
            return result;
        }

        /// <summary>
        /// One AES encryption round: SubBytes, ShiftRows, MixColumns, AddRoundKey (FIPS 197 §5). Uses the AES
        /// instructions when available; the table-based fallback is not constant-time.
        /// </summary>
        internal static Vector128<byte> AesRound(Vector128<byte> state, Vector128<byte> roundKey)
        {
            if (X86Aes.IsSupported)
                return X86Aes.Encrypt(state, roundKey);
            if (ArmAes.IsSupported)
                return ArmAes.MixColumns(ArmAes.Encrypt(state, Vector128<byte>.Zero)) ^ roundKey;
            return SoftwareAesRound(state, roundKey);
        }

        internal static Vector128<byte> SoftwareAesRound(Vector128<byte> state, Vector128<byte> roundKey)
        {
            Span<byte> s = stackalloc byte[16];
            state.CopyTo(s);

            // SubBytes and ShiftRows: output column c, row r comes from input column (c + r) mod 4.
            Span<byte> t = stackalloc byte[16];
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    t[4 * c + r] = SBox[s[4 * ((c + r) & 3) + r]];

            // MixColumns
            Span<byte> o = stackalloc byte[16];
            for (int c = 0; c < 4; c++)
            {
                byte a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                o[4 * c]     = (byte)(Xtime(a0) ^ Xtime(a1) ^ a1 ^ a2 ^ a3);
                o[4 * c + 1] = (byte)(a0 ^ Xtime(a1) ^ Xtime(a2) ^ a2 ^ a3);
                o[4 * c + 2] = (byte)(a0 ^ a1 ^ Xtime(a2) ^ Xtime(a3) ^ a3);
                o[4 * c + 3] = (byte)(Xtime(a0) ^ a0 ^ a1 ^ a2 ^ Xtime(a3));
            }
            return Vector128.Create((ReadOnlySpan<byte>)o) ^ roundKey;
        }

        private static byte Xtime(byte b) => (byte)((b << 1) ^ ((b & 0x80) != 0 ? 0x1b : 0));

        private static readonly byte[] SBox =
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        };
    }
}
