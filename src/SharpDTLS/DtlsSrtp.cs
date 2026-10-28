using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// SRTP master keys and salts derived from a DTLS association (RFC 5764 §4.2).
    /// </summary>
    public sealed class DtlsSrtpKeys
    {
        public DtlsSrtpKeys(ushort profile, byte[] clientWriteKey, byte[] serverWriteKey, byte[] clientWriteSalt, byte[] serverWriteSalt, byte[] mki = null)
        {
            Profile = profile;
            ClientWriteKey = clientWriteKey;
            ServerWriteKey = serverWriteKey;
            ClientWriteSalt = clientWriteSalt;
            ServerWriteSalt = serverWriteSalt;
            Mki = mki ?? Array.Empty<byte>();
        }

        public ushort Profile { get; }
        public byte[] ClientWriteKey { get; }
        public byte[] ServerWriteKey { get; }
        public byte[] ClientWriteSalt { get; }
        public byte[] ServerWriteSalt { get; }

        /// <summary>The SRTP Master Key Identifier negotiated with use_srtp; empty when no MKI is in use.</summary>
        public byte[] Mki { get; }
    }

    /// <summary>
    /// DTLS-SRTP (RFC 5764, RFC 7714, RFC 8269, RFC 8723) protection profiles and keying material layout.
    /// </summary>
    public static class DtlsSrtp
    {
        public const string ExporterLabel = "EXTRACTOR-dtls_srtp";

        public const ushort SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001;
        public const ushort SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002;
        public const ushort SRTP_NULL_HMAC_SHA1_80      = 0x0005;
        public const ushort SRTP_NULL_HMAC_SHA1_32      = 0x0006;
        public const ushort SRTP_AEAD_AES_128_GCM       = 0x0007;
        public const ushort SRTP_AEAD_AES_256_GCM       = 0x0008;
        public const ushort DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 0x0009;
        public const ushort DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 0x000A;
        public const ushort SRTP_ARIA_128_CTR_HMAC_SHA1_80 = 0x000B;
        public const ushort SRTP_ARIA_128_CTR_HMAC_SHA1_32 = 0x000C;
        public const ushort SRTP_ARIA_256_CTR_HMAC_SHA1_80 = 0x000D;
        public const ushort SRTP_ARIA_256_CTR_HMAC_SHA1_32 = 0x000E;
        public const ushort SRTP_AEAD_ARIA_128_GCM      = 0x000F;
        public const ushort SRTP_AEAD_ARIA_256_GCM      = 0x0010;

        // (master key length, master salt length) per profile
        private static readonly Dictionary<ushort, (int Key, int Salt)> _profiles = new()
        {
            [SRTP_AES128_CM_HMAC_SHA1_80] = (16, 14),
            [SRTP_AES128_CM_HMAC_SHA1_32] = (16, 14),
            [SRTP_NULL_HMAC_SHA1_80]      = (16, 14),
            [SRTP_NULL_HMAC_SHA1_32]      = (16, 14),
            [SRTP_AEAD_AES_128_GCM]       = (16, 12),
            [SRTP_AEAD_AES_256_GCM]       = (32, 12),
            // RFC 8723 §8.1: inner and outer key and salt together
            [DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM] = (32, 24),
            [DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM] = (64, 24),
            [SRTP_ARIA_128_CTR_HMAC_SHA1_80] = (16, 14),
            [SRTP_ARIA_128_CTR_HMAC_SHA1_32] = (16, 14),
            [SRTP_ARIA_256_CTR_HMAC_SHA1_80] = (32, 14),
            [SRTP_ARIA_256_CTR_HMAC_SHA1_32] = (32, 14),
            [SRTP_AEAD_ARIA_128_GCM]      = (16, 12),
            [SRTP_AEAD_ARIA_256_GCM]      = (32, 12),
        };

        private static bool IsDoubleAead(ushort profile)
            => profile == DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM || profile == DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM;

        public static bool IsSupported(ushort profile) => _profiles.ContainsKey(profile);

        /// <summary>Total exporter output length for <paramref name="profile"/>: 2 * (key + salt).</summary>
        public static int KeyingMaterialLength(ushort profile)
        {
            if (!_profiles.TryGetValue(profile, out var p))
                throw new ArgumentException($"Unknown SRTP protection profile 0x{profile:X4}", nameof(profile));
            return 2 * (p.Key + p.Salt);
        }

        /// <summary>
        /// Splits exporter output: client_write_key | server_write_key | client_write_salt | server_write_salt.
        /// Double AEAD (RFC 8723) keeps the inner and outer halves apart: the inner keying material, then the outer one,
        /// each in that order; every key and salt is then the inner part followed by the outer part.
        /// </summary>
        public static DtlsSrtpKeys Split(ushort profile, byte[] material, byte[] mki = null)
        {
            var (keyLength, saltLength) = _profiles[profile];
            if (material.Length != 2 * (keyLength + saltLength))
                throw new ArgumentException("Keying material has the wrong length for the profile.", nameof(material));

            if (!IsDoubleAead(profile))
            {
                byte[] Slice(int offset, int length) => material.AsSpan(offset, length).ToArray();
                return new DtlsSrtpKeys(profile,
                    Slice(0, keyLength),
                    Slice(keyLength, keyLength),
                    Slice(2 * keyLength, saltLength),
                    Slice(2 * keyLength + saltLength, saltLength),
                    mki);
            }

            int half = material.Length / 2, halfKey = keyLength / 2, halfSalt = saltLength / 2;
            byte[] Join(int offset, int length) => material.AsSpan(offset, length).ToArray().Concat(material.AsSpan(half + offset, length).ToArray()).ToArray();
            return new DtlsSrtpKeys(profile,
                Join(0, halfKey),
                Join(halfKey, halfKey),
                Join(2 * halfKey, halfSalt),
                Join(2 * halfKey + halfSalt, halfSalt),
                mki);
        }

        /// <summary>The largest MKI use_srtp can carry (a one-byte length, RFC 5764 §4.1.1).</summary>
        public const int MaxMkiLength = 255;

        /// <summary>Validates an MKI to offer: null or empty for none, at most <see cref="MaxMkiLength"/> bytes.</summary>
        public static byte[] CheckMki(byte[] mki)
        {
            if (mki != null && mki.Length > MaxMkiLength)
                throw new ArgumentOutOfRangeException(nameof(mki), $"An SRTP MKI is at most {MaxMkiLength} bytes.");
            return mki;
        }

        /// <summary>
        /// The MKI a client ends up with after the server's use_srtp (RFC 5764 §4.1.1): the server either echoes the
        /// offered MKI or sends an empty one; any other value aborts the handshake with illegal_parameter.
        /// </summary>
        public static byte[] AcceptServerMki(byte[] offered, byte[] received)
        {
            received ??= Array.Empty<byte>();
            if (received.Length != 0 && !received.AsSpan().SequenceEqual(offered ?? Array.Empty<byte>()))
                throw new DtlsException(AlertDescription.IllegalParameter, "Server selected an SRTP MKI that was not offered.");
            return received;
        }

        /// <summary>Picks the first profile from <paramref name="serverPreference"/> that the client offered.</summary>
        public static ushort? Select(IEnumerable<ushort> serverPreference, IEnumerable<ushort> offered)
        {
            if (serverPreference == null || offered == null)
                return null;
            var set = new HashSet<ushort>(offered);
            foreach (ushort profile in serverPreference)
                if (set.Contains(profile) && IsSupported(profile))
                    return profile;
            return null;
        }
    }
}
