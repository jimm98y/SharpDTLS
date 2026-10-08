using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>Key exchange of a cipher suite, named as in the IANA registry.</summary>
    public enum KeyExchangeAlgorithm
    {
        Unknown,
        NULL,
        RSA, RSA_EXPORT,
        DH_DSS, DH_RSA, DHE_DSS, DHE_RSA, DH_anon,
        DH_DSS_EXPORT, DH_RSA_EXPORT, DHE_DSS_EXPORT, DHE_RSA_EXPORT, DH_anon_EXPORT,
        KRB5, KRB5_EXPORT,
        PSK, DHE_PSK, RSA_PSK, ECDHE_PSK, PSK_DHE,
        ECDH_ECDSA, ECDHE_ECDSA, ECDH_RSA, ECDHE_RSA, ECDH_anon,
        SRP_SHA, SRP_SHA_RSA, SRP_SHA_DSS,
        ECCPWD,

        /// <summary>TLS 1.3 suites, which do not name a key exchange.</summary>
        TLS13,
    }

    public enum BulkCipherAlgorithm
    {
        Unknown,
        Null,
        Rc4_40, Rc4_128, Rc2Cbc40,
        Des40Cbc, DesCbc40, DesCbc, TripleDesEdeCbc, IdeaCbc, SeedCbc,
        Aes128Cbc, Aes256Cbc, Aes128Gcm, Aes256Gcm,
        Aes128Ccm, Aes256Ccm, Aes128Ccm8, Aes256Ccm8,
        Camellia128Cbc, Camellia256Cbc, Camellia128Gcm, Camellia256Gcm,
        Aria128Cbc, Aria256Cbc, Aria128Gcm, Aria256Gcm,
        ChaCha20Poly1305,
    }

    public enum MacAlgorithm
    {
        Unknown,
        /// <summary>No separate MAC: an AEAD cipher.</summary>
        Aead,
        /// <summary>TLS_NULL_WITH_NULL_NULL: no protection at all.</summary>
        None,
        HmacMd5,
        HmacSha1,
        HmacSha256,
        HmacSha384,
    }

    public enum PrfHashAlgorithm
    {
        Sha256,
        Sha384,
    }

    /// <summary>Certificate (signature) key a key exchange requires from the server.</summary>
    public enum CertificateKeyType
    {
        None,
        Rsa,
        Ecdsa,
        Dsa,
    }

    /// <summary>Coarse security classification used to choose default suites.</summary>
    public enum CipherSuiteSecurity
    {
        /// <summary>Forward-secret key exchange with an AEAD cipher.</summary>
        Recommended,
        /// <summary>Sound but dated: CBC ciphers, or RSA key transport without forward secrecy.</summary>
        Legacy,
        /// <summary>Broken or obsolete (export, DES, 3DES, IDEA, NULL encryption, anonymous): never offered by default.</summary>
        Weak,
    }

    /// <summary>
    /// A DTLS 1.0/1.2 cipher suite. Properties are derived from the IANA name
    /// (TLS_{key exchange}_WITH_{cipher}_{MAC}).
    /// </summary>
    public sealed class CipherSuiteInfo
    {
        // Longest tokens first so that e.g. AES_128_CCM_8 is not read as AES_128_CCM.
        private static readonly (string Token, BulkCipherAlgorithm Cipher)[] CipherTokens =
        {
            ("CHACHA20_POLY1305", BulkCipherAlgorithm.ChaCha20Poly1305),
            ("CAMELLIA_128_CBC", BulkCipherAlgorithm.Camellia128Cbc), ("CAMELLIA_256_CBC", BulkCipherAlgorithm.Camellia256Cbc),
            ("CAMELLIA_128_GCM", BulkCipherAlgorithm.Camellia128Gcm), ("CAMELLIA_256_GCM", BulkCipherAlgorithm.Camellia256Gcm),
            ("ARIA_128_CBC", BulkCipherAlgorithm.Aria128Cbc), ("ARIA_256_CBC", BulkCipherAlgorithm.Aria256Cbc),
            ("ARIA_128_GCM", BulkCipherAlgorithm.Aria128Gcm), ("ARIA_256_GCM", BulkCipherAlgorithm.Aria256Gcm),
            ("AES_128_CCM_8", BulkCipherAlgorithm.Aes128Ccm8), ("AES_256_CCM_8", BulkCipherAlgorithm.Aes256Ccm8),
            ("AES_128_CCM", BulkCipherAlgorithm.Aes128Ccm), ("AES_256_CCM", BulkCipherAlgorithm.Aes256Ccm),
            ("AES_128_CBC", BulkCipherAlgorithm.Aes128Cbc), ("AES_256_CBC", BulkCipherAlgorithm.Aes256Cbc),
            ("AES_128_GCM", BulkCipherAlgorithm.Aes128Gcm), ("AES_256_GCM", BulkCipherAlgorithm.Aes256Gcm),
            ("3DES_EDE_CBC", BulkCipherAlgorithm.TripleDesEdeCbc),
            ("DES40_CBC", BulkCipherAlgorithm.Des40Cbc), ("DES_CBC_40", BulkCipherAlgorithm.DesCbc40), ("DES_CBC", BulkCipherAlgorithm.DesCbc),
            ("RC2_CBC_40", BulkCipherAlgorithm.Rc2Cbc40), ("RC4_40", BulkCipherAlgorithm.Rc4_40), ("RC4_128", BulkCipherAlgorithm.Rc4_128),
            ("IDEA_CBC", BulkCipherAlgorithm.IdeaCbc), ("SEED_CBC", BulkCipherAlgorithm.SeedCbc),
            ("NULL", BulkCipherAlgorithm.Null),
        };

        private CipherSuiteInfo(ushort id, string name, bool dtlsOk)
        {
            Id = id;
            Name = name;
            DtlsOk = dtlsOk;
            Parse();
        }

        internal static CipherSuiteInfo FromRegistry(ushort id, string name, bool dtlsOk) => new CipherSuiteInfo(id, name, dtlsOk);

        public ushort Id { get; }
        public string Name { get; }

        /// <summary>The IANA registry allows the suite with DTLS (stream ciphers such as RC4 are excluded).</summary>
        public bool DtlsOk { get; }

        public KeyExchangeAlgorithm KeyExchange { get; private set; }
        public BulkCipherAlgorithm Cipher { get; private set; }
        public MacAlgorithm Mac { get; private set; }

        /// <summary>PRF hash in DTLS 1.2 (DTLS 1.0 always uses the MD5/SHA-1 PRF).</summary>
        public PrfHashAlgorithm Prf { get; private set; }

        /// <summary>Oldest version the suite may be used with (AEAD and SHA-256+ MACs need DTLS 1.2).</summary>
        public ushort MinimumVersion { get; private set; }

        /// <summary>Newest version the suite may be used with (export, DES and IDEA suites are not defined for TLS 1.2).</summary>
        public ushort MaximumVersion { get; private set; }

        public bool IsExport { get; private set; }

        public bool IsAead => Mac == MacAlgorithm.Aead;

        public bool IsCbc => Cipher is not (BulkCipherAlgorithm.Null or BulkCipherAlgorithm.Unknown or BulkCipherAlgorithm.Rc4_40
            or BulkCipherAlgorithm.Rc4_128) && !IsAead;

        public bool IsAnonymous => KeyExchange is KeyExchangeAlgorithm.DH_anon or KeyExchangeAlgorithm.DH_anon_EXPORT or KeyExchangeAlgorithm.ECDH_anon;

        public bool HasForwardSecrecy => KeyExchange is KeyExchangeAlgorithm.DHE_DSS or KeyExchangeAlgorithm.DHE_RSA
            or KeyExchangeAlgorithm.ECDHE_ECDSA or KeyExchangeAlgorithm.ECDHE_RSA or KeyExchangeAlgorithm.DHE_PSK
            or KeyExchangeAlgorithm.PSK_DHE or KeyExchangeAlgorithm.ECDHE_PSK
            or KeyExchangeAlgorithm.DHE_DSS_EXPORT or KeyExchangeAlgorithm.DHE_RSA_EXPORT;

        /// <summary>The key exchange authenticates with a pre-shared key (RFC 4279, RFC 5489).</summary>
        public bool RequiresPsk => KeyExchange is KeyExchangeAlgorithm.PSK or KeyExchangeAlgorithm.DHE_PSK
            or KeyExchangeAlgorithm.PSK_DHE or KeyExchangeAlgorithm.ECDHE_PSK or KeyExchangeAlgorithm.RSA_PSK;

        /// <summary>Whether this implementation supports the suite.</summary>
        public bool IsImplemented => DtlsOk && CipherSuites.IsKeyExchangeImplemented(KeyExchange) && CipherSuites.IsCipherImplemented(Cipher)
            && Mac is not (MacAlgorithm.Unknown or MacAlgorithm.None);

        public CipherSuiteSecurity Security
        {
            get
            {
                if (IsExport || IsAnonymous || Cipher is BulkCipherAlgorithm.Null or BulkCipherAlgorithm.DesCbc or BulkCipherAlgorithm.TripleDesEdeCbc
                    or BulkCipherAlgorithm.IdeaCbc or BulkCipherAlgorithm.Rc2Cbc40 or BulkCipherAlgorithm.Des40Cbc or BulkCipherAlgorithm.DesCbc40
                    or BulkCipherAlgorithm.Rc4_40 or BulkCipherAlgorithm.Rc4_128 || Mac == MacAlgorithm.HmacMd5)
                    return CipherSuiteSecurity.Weak;
                return HasForwardSecrecy && IsAead ? CipherSuiteSecurity.Recommended : CipherSuiteSecurity.Legacy;
            }
        }

        public int KeyLength => Cipher switch
        {
            BulkCipherAlgorithm.Null => 0,
            BulkCipherAlgorithm.DesCbc => 8,
            BulkCipherAlgorithm.TripleDesEdeCbc => 24,
            BulkCipherAlgorithm.IdeaCbc or BulkCipherAlgorithm.SeedCbc => 16,
            BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes128Gcm or BulkCipherAlgorithm.Aes128Ccm or BulkCipherAlgorithm.Aes128Ccm8
                or BulkCipherAlgorithm.Camellia128Cbc or BulkCipherAlgorithm.Camellia128Gcm
                or BulkCipherAlgorithm.Aria128Cbc or BulkCipherAlgorithm.Aria128Gcm => 16,
            _ => 32,
        };

        /// <summary>Implicit IV from the key block: 4 for GCM/CCM, 12 for ChaCha20, 0 otherwise (explicit per-record IV).</summary>
        public int FixedIvLength => Cipher == BulkCipherAlgorithm.ChaCha20Poly1305 ? 12 : IsAead ? 4 : 0;

        public int MacKeyLength => Mac switch
        {
            MacAlgorithm.HmacMd5 => 16,
            MacAlgorithm.HmacSha1 => 20,
            MacAlgorithm.HmacSha256 => 32,
            MacAlgorithm.HmacSha384 => 48,
            _ => 0,
        };

        public CertificateKeyType ServerCertificateType => KeyExchange switch
        {
            KeyExchangeAlgorithm.RSA or KeyExchangeAlgorithm.RSA_EXPORT or KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_RSA_EXPORT
                or KeyExchangeAlgorithm.ECDHE_RSA or KeyExchangeAlgorithm.RSA_PSK or KeyExchangeAlgorithm.SRP_SHA_RSA => CertificateKeyType.Rsa,
            KeyExchangeAlgorithm.DHE_DSS or KeyExchangeAlgorithm.DHE_DSS_EXPORT or KeyExchangeAlgorithm.SRP_SHA_DSS => CertificateKeyType.Dsa,
            KeyExchangeAlgorithm.ECDHE_ECDSA => CertificateKeyType.Ecdsa,
            _ => CertificateKeyType.None,
        };

        public bool IsUsableWith(ushort version)
            => DtlsVersion.IsAtLeast(version, MinimumVersion) && DtlsVersion.IsAtLeast(MaximumVersion, version);

        public override string ToString() => $"{Name} (0x{Id:X4})";

        private void Parse()
        {
            MinimumVersion = DtlsVersion.Dtls10;
            MaximumVersion = DtlsVersion.Dtls12;
            string rest = Name.StartsWith("TLS_") ? Name.Substring(4) : Name;

            int with = rest.IndexOf("_WITH_", StringComparison.Ordinal);
            if (with < 0)
            {
                KeyExchange = KeyExchangeAlgorithm.TLS13; // TLS 1.3 suites and signalling values
                Cipher = BulkCipherAlgorithm.Unknown;
                Mac = MacAlgorithm.Unknown;
                return;
            }

            KeyExchange = Enum.TryParse(rest.Substring(0, with), out KeyExchangeAlgorithm kx) ? kx : KeyExchangeAlgorithm.Unknown;
            string cipherAndMac = rest.Substring(with + 6);
            IsExport = Name.Contains("EXPORT");

            Cipher = BulkCipherAlgorithm.Unknown;
            string macPart = null;
            foreach (var (token, cipher) in CipherTokens)
            {
                if (cipherAndMac == token || cipherAndMac.StartsWith(token + "_", StringComparison.Ordinal))
                {
                    Cipher = cipher;
                    macPart = cipherAndMac.Length > token.Length ? cipherAndMac.Substring(token.Length + 1) : "";
                    break;
                }
            }

            bool aead = Cipher is BulkCipherAlgorithm.Aes128Gcm or BulkCipherAlgorithm.Aes256Gcm or BulkCipherAlgorithm.Aes128Ccm
                or BulkCipherAlgorithm.Aes256Ccm or BulkCipherAlgorithm.Aes128Ccm8 or BulkCipherAlgorithm.Aes256Ccm8
                or BulkCipherAlgorithm.Camellia128Gcm or BulkCipherAlgorithm.Camellia256Gcm or BulkCipherAlgorithm.Aria128Gcm
                or BulkCipherAlgorithm.Aria256Gcm or BulkCipherAlgorithm.ChaCha20Poly1305;

            if (aead)
            {
                Mac = MacAlgorithm.Aead;
                Prf = macPart == "SHA384" ? PrfHashAlgorithm.Sha384 : PrfHashAlgorithm.Sha256;
                MinimumVersion = DtlsVersion.Dtls12;
            }
            else
            {
                Mac = macPart switch
                {
                    "MD5" => MacAlgorithm.HmacMd5,
                    "SHA" => MacAlgorithm.HmacSha1,
                    "SHA256" => MacAlgorithm.HmacSha256,
                    "SHA384" => MacAlgorithm.HmacSha384,
                    "NULL" => MacAlgorithm.None,
                    _ => MacAlgorithm.Unknown,
                };
                Prf = Mac == MacAlgorithm.HmacSha384 ? PrfHashAlgorithm.Sha384 : PrfHashAlgorithm.Sha256;
                if (Mac is MacAlgorithm.HmacSha256 or MacAlgorithm.HmacSha384)
                    MinimumVersion = DtlsVersion.Dtls12;
            }

            // RFC 5246 Appendix A.5 / RFC 5469: export, DES and IDEA suites must not be used with TLS 1.2.
            if (IsExport || Cipher is BulkCipherAlgorithm.DesCbc or BulkCipherAlgorithm.IdeaCbc)
                MaximumVersion = DtlsVersion.Dtls10;
        }
    }

    /// <summary>
    /// The IANA cipher suite registry with the DTLS 1.0/1.2 properties of every suite, and the set implemented here.
    /// </summary>
    public static class CipherSuites
    {
        public const ushort TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

        private static readonly HashSet<KeyExchangeAlgorithm> ImplementedKeyExchanges = new()
        {
            KeyExchangeAlgorithm.RSA,
            KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.DHE_DSS,
            KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDHE_ECDSA,
            KeyExchangeAlgorithm.PSK, KeyExchangeAlgorithm.DHE_PSK, KeyExchangeAlgorithm.PSK_DHE,
            KeyExchangeAlgorithm.ECDHE_PSK, KeyExchangeAlgorithm.RSA_PSK,
        };

        private static readonly HashSet<BulkCipherAlgorithm> ImplementedCiphers = new()
        {
            BulkCipherAlgorithm.Null,
            BulkCipherAlgorithm.DesCbc, BulkCipherAlgorithm.TripleDesEdeCbc, BulkCipherAlgorithm.IdeaCbc, BulkCipherAlgorithm.SeedCbc,
            BulkCipherAlgorithm.Aes128Cbc, BulkCipherAlgorithm.Aes256Cbc, BulkCipherAlgorithm.Aes128Gcm, BulkCipherAlgorithm.Aes256Gcm,
            BulkCipherAlgorithm.Aes128Ccm, BulkCipherAlgorithm.Aes256Ccm, BulkCipherAlgorithm.Aes128Ccm8, BulkCipherAlgorithm.Aes256Ccm8,
            BulkCipherAlgorithm.Camellia128Cbc, BulkCipherAlgorithm.Camellia256Cbc, BulkCipherAlgorithm.Camellia128Gcm, BulkCipherAlgorithm.Camellia256Gcm,
            BulkCipherAlgorithm.Aria128Cbc, BulkCipherAlgorithm.Aria256Cbc, BulkCipherAlgorithm.Aria128Gcm, BulkCipherAlgorithm.Aria256Gcm,
            BulkCipherAlgorithm.ChaCha20Poly1305,
        };

        private static readonly CipherSuiteInfo[] _registry = CipherSuiteRegistry.Entries
            .Select(e => CipherSuiteInfo.FromRegistry(e.Id, e.Name, e.DtlsOk))
            .ToArray();

        private static readonly Dictionary<ushort, CipherSuiteInfo> _byId = _registry.ToDictionary(s => s.Id);

        // Default preference: forward secrecy, then AEAD, then key exchange, then MAC strength, then key size.
        private static readonly CipherSuiteInfo[] _implemented = _registry
            .Where(s => s.IsImplemented)
            .OrderBy(s => s.HasForwardSecrecy ? 0 : 1)
            .ThenBy(s => CipherRank(s.Cipher))
            .ThenBy(s => KeyExchangeRank(s.KeyExchange))
            .ThenBy(s => s.Mac switch { MacAlgorithm.Aead => 0, MacAlgorithm.HmacSha384 => 1, MacAlgorithm.HmacSha256 => 2, MacAlgorithm.HmacSha1 => 3, _ => 4 })
            .ThenBy(s => s.KeyLength)
            .ToArray();

        internal static bool IsKeyExchangeImplemented(KeyExchangeAlgorithm kx) => ImplementedKeyExchanges.Contains(kx);
        internal static bool IsCipherImplemented(BulkCipherAlgorithm cipher) => ImplementedCiphers.Contains(cipher);

        /// <summary>Every assigned suite in the IANA registry, implemented or not.</summary>
        public static IReadOnlyList<CipherSuiteInfo> Registry => _registry;

        /// <summary>All implemented suites, in default preference order.</summary>
        public static IReadOnlyList<CipherSuiteInfo> All => _implemented;

        public static bool TryGet(ushort id, out CipherSuiteInfo suite)
            => _byId.TryGetValue(id, out suite) && suite.IsImplemented;

        public static CipherSuiteInfo Get(ushort id)
            => TryGet(id, out var suite) ? suite : throw new DtlsException(AlertDescription.HandshakeFailure, $"Unsupported cipher suite 0x{id:X4}");

        /// <summary>
        /// Suites offered when none are configured: implemented, not weak, usable within the version range,
        /// in preference order. PSK suites are included only when a pre-shared key is configured.
        /// </summary>
        public static List<ushort> DefaultFor(ushort minimumVersion, ushort maximumVersion, bool includePsk = false)
            => _implemented
                .Where(s => s.Security != CipherSuiteSecurity.Weak)
                .Where(s => includePsk || !s.RequiresPsk)
                .Where(s => s.IsUsableWith(maximumVersion) || s.IsUsableWith(minimumVersion))
                .Select(s => s.Id)
                .ToList();

        private static int CipherRank(BulkCipherAlgorithm cipher) => cipher switch
        {
            BulkCipherAlgorithm.Aes128Gcm or BulkCipherAlgorithm.Aes256Gcm => 0,
            BulkCipherAlgorithm.ChaCha20Poly1305 => 1,
            BulkCipherAlgorithm.Aes128Ccm or BulkCipherAlgorithm.Aes256Ccm => 2,
            BulkCipherAlgorithm.Camellia128Gcm or BulkCipherAlgorithm.Camellia256Gcm or BulkCipherAlgorithm.Aria128Gcm or BulkCipherAlgorithm.Aria256Gcm => 3,
            BulkCipherAlgorithm.Aes128Ccm8 or BulkCipherAlgorithm.Aes256Ccm8 => 4,
            BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes256Cbc => 5,
            BulkCipherAlgorithm.Camellia128Cbc or BulkCipherAlgorithm.Camellia256Cbc or BulkCipherAlgorithm.Aria128Cbc or BulkCipherAlgorithm.Aria256Cbc => 6,
            BulkCipherAlgorithm.SeedCbc => 7,
            BulkCipherAlgorithm.TripleDesEdeCbc or BulkCipherAlgorithm.IdeaCbc => 8,
            BulkCipherAlgorithm.DesCbc => 9,
            _ => 10,
        };

        private static int KeyExchangeRank(KeyExchangeAlgorithm kx) => kx switch
        {
            KeyExchangeAlgorithm.ECDHE_ECDSA => 0,
            KeyExchangeAlgorithm.ECDHE_RSA => 1,
            KeyExchangeAlgorithm.DHE_RSA => 2,
            KeyExchangeAlgorithm.DHE_DSS => 3,
            KeyExchangeAlgorithm.ECDHE_PSK => 4,
            KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE => 5,
            KeyExchangeAlgorithm.RSA => 6,
            KeyExchangeAlgorithm.RSA_PSK => 7,
            KeyExchangeAlgorithm.PSK => 8,
            _ => 9,
        };
    }
}
