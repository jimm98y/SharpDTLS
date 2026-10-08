using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    public enum KeyExchangeAlgorithm
    {
        ECDHE_ECDSA,
        ECDHE_RSA,
    }

    public enum BulkCipherAlgorithm
    {
        Aes128Cbc,
        Aes256Cbc,
        Aes128Gcm,
        Aes256Gcm,
        ChaCha20Poly1305,
    }

    public enum MacAlgorithm
    {
        /// <summary>No separate MAC: an AEAD cipher.</summary>
        Aead,
        HmacSha1,
        HmacSha256,
        HmacSha384,
    }

    public enum PrfHashAlgorithm
    {
        Sha256,
        Sha384,
    }

    /// <summary>Certificate (signature) type a key exchange requires from the server.</summary>
    public enum CertificateKeyType
    {
        None,
        Rsa,
        Ecdsa,
    }

    /// <summary>
    /// A DTLS 1.0/1.2 cipher suite (RFC 5246 Appendix A.5 and the IANA TLS Cipher Suites registry).
    /// </summary>
    public sealed class CipherSuiteInfo
    {
        public CipherSuiteInfo(ushort id, string name, KeyExchangeAlgorithm keyExchange, BulkCipherAlgorithm cipher,
            MacAlgorithm mac, PrfHashAlgorithm prf, ushort minimumVersion)
        {
            Id = id;
            Name = name;
            KeyExchange = keyExchange;
            Cipher = cipher;
            Mac = mac;
            Prf = prf;
            MinimumVersion = minimumVersion;
        }

        public ushort Id { get; }
        public string Name { get; }
        public KeyExchangeAlgorithm KeyExchange { get; }
        public BulkCipherAlgorithm Cipher { get; }
        public MacAlgorithm Mac { get; }

        /// <summary>PRF hash in DTLS 1.2 (DTLS 1.0 always uses the MD5/SHA-1 PRF).</summary>
        public PrfHashAlgorithm Prf { get; }

        /// <summary>Oldest protocol version the suite may be used with (AEAD and SHA-256+ MACs need DTLS 1.2).</summary>
        public ushort MinimumVersion { get; }

        public bool IsAead => Mac == MacAlgorithm.Aead;
        public bool IsCbc => Cipher is BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes256Cbc;

        public int KeyLength => Cipher switch
        {
            BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes128Gcm => 16,
            _ => 32,
        };

        /// <summary>Implicit IV from the key block: 4 for GCM, 12 for ChaCha20, 0 for CBC (explicit per-record IV).</summary>
        public int FixedIvLength => Cipher switch
        {
            BulkCipherAlgorithm.Aes128Gcm or BulkCipherAlgorithm.Aes256Gcm => 4,
            BulkCipherAlgorithm.ChaCha20Poly1305 => 12,
            _ => 0,
        };

        public int MacKeyLength => Mac switch
        {
            MacAlgorithm.HmacSha1 => 20,
            MacAlgorithm.HmacSha256 => 32,
            MacAlgorithm.HmacSha384 => 48,
            _ => 0,
        };

        public CertificateKeyType ServerCertificateType => KeyExchange switch
        {
            KeyExchangeAlgorithm.ECDHE_ECDSA => CertificateKeyType.Ecdsa,
            KeyExchangeAlgorithm.ECDHE_RSA => CertificateKeyType.Rsa,
            _ => CertificateKeyType.None,
        };

        public bool IsUsableWith(ushort version) => DtlsVersion.IsAtLeast(version, MinimumVersion);

        public override string ToString() => $"{Name} (0x{Id:X4})";
    }

    /// <summary>
    /// Registry of implemented DTLS 1.0/1.2 cipher suites.
    /// </summary>
    public static class CipherSuites
    {
        public const ushort TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

        private static readonly CipherSuiteInfo[] _all =
        {
            // ECDHE + AES-GCM / ChaCha20-Poly1305 (RFC 5289, RFC 7905) — DTLS 1.2
            new(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes128Gcm, MacAlgorithm.Aead, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),
            new(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes256Gcm, MacAlgorithm.Aead, PrfHashAlgorithm.Sha384, DtlsVersion.Dtls12),
            new(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.ChaCha20Poly1305, MacAlgorithm.Aead, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),
            new(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes128Gcm, MacAlgorithm.Aead, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),
            new(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes256Gcm, MacAlgorithm.Aead, PrfHashAlgorithm.Sha384, DtlsVersion.Dtls12),
            new(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.ChaCha20Poly1305, MacAlgorithm.Aead, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),

            // ECDHE + AES-CBC with SHA-256/384 MAC (RFC 5289) — DTLS 1.2
            new(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes128Cbc, MacAlgorithm.HmacSha256, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),
            new(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes256Cbc, MacAlgorithm.HmacSha384, PrfHashAlgorithm.Sha384, DtlsVersion.Dtls12),
            new(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes128Cbc, MacAlgorithm.HmacSha256, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls12),
            new(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes256Cbc, MacAlgorithm.HmacSha384, PrfHashAlgorithm.Sha384, DtlsVersion.Dtls12),

            // ECDHE + AES-CBC with SHA-1 MAC (RFC 8422) — DTLS 1.0 and later
            new(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes128Cbc, MacAlgorithm.HmacSha1, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls10),
            new(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExchangeAlgorithm.ECDHE_ECDSA, BulkCipherAlgorithm.Aes256Cbc, MacAlgorithm.HmacSha1, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls10),
            new(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes128Cbc, MacAlgorithm.HmacSha1, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls10),
            new(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExchangeAlgorithm.ECDHE_RSA, BulkCipherAlgorithm.Aes256Cbc, MacAlgorithm.HmacSha1, PrfHashAlgorithm.Sha256, DtlsVersion.Dtls10),
        };

        private static readonly Dictionary<ushort, CipherSuiteInfo> _byId = _all.ToDictionary(s => s.Id);

        /// <summary>All implemented suites, in default preference order.</summary>
        public static IReadOnlyList<CipherSuiteInfo> All => _all;

        public static bool TryGet(ushort id, out CipherSuiteInfo suite) => _byId.TryGetValue(id, out suite);

        public static CipherSuiteInfo Get(ushort id)
            => _byId.TryGetValue(id, out var suite) ? suite : throw new DtlsException(AlertDescription.HandshakeFailure, $"Unsupported cipher suite 0x{id:X4}");

        /// <summary>Default suites for a version range, in preference order.</summary>
        public static List<ushort> DefaultFor(ushort minimumVersion, ushort maximumVersion)
            => _all.Where(s => s.IsUsableWith(maximumVersion)).Select(s => s.Id).ToList();
    }
}
