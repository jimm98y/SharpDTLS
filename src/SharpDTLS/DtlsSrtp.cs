using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// SRTP master keys and salts derived from a DTLS association (RFC 5764 §4.2).
    /// </summary>
    public sealed class DtlsSrtpKeys
    {
        public DtlsSrtpKeys(ushort profile, byte[] clientWriteKey, byte[] serverWriteKey, byte[] clientWriteSalt, byte[] serverWriteSalt)
        {
            Profile = profile;
            ClientWriteKey = clientWriteKey;
            ServerWriteKey = serverWriteKey;
            ClientWriteSalt = clientWriteSalt;
            ServerWriteSalt = serverWriteSalt;
        }

        public ushort Profile { get; }
        public byte[] ClientWriteKey { get; }
        public byte[] ServerWriteKey { get; }
        public byte[] ClientWriteSalt { get; }
        public byte[] ServerWriteSalt { get; }
    }

    /// <summary>
    /// DTLS-SRTP (RFC 5764, RFC 7714) protection profiles and keying material layout.
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

        // (master key length, master salt length) per profile
        private static readonly Dictionary<ushort, (int Key, int Salt)> _profiles = new()
        {
            [SRTP_AES128_CM_HMAC_SHA1_80] = (16, 14),
            [SRTP_AES128_CM_HMAC_SHA1_32] = (16, 14),
            [SRTP_NULL_HMAC_SHA1_80]      = (16, 14),
            [SRTP_NULL_HMAC_SHA1_32]      = (16, 14),
            [SRTP_AEAD_AES_128_GCM]       = (16, 12),
            [SRTP_AEAD_AES_256_GCM]       = (32, 12),
        };

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
        /// </summary>
        public static DtlsSrtpKeys Split(ushort profile, byte[] material)
        {
            var (keyLength, saltLength) = _profiles[profile];
            if (material.Length != 2 * (keyLength + saltLength))
                throw new ArgumentException("Keying material has the wrong length for the profile.", nameof(material));

            byte[] Slice(int offset, int length) => material.AsSpan(offset, length).ToArray();
            return new DtlsSrtpKeys(profile,
                Slice(0, keyLength),
                Slice(keyLength, keyLength),
                Slice(2 * keyLength, saltLength),
                Slice(2 * keyLength + saltLength, saltLength));
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
