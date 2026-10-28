namespace SharpDTLS
{
    /// <summary>
    /// Key exchange groups (IANA TLS Supported Groups). TLS/DTLS 1.0-1.2 use the elliptic curves for ECDHE suites
    /// and the FFDHE groups for DHE suites; TLS/DTLS 1.3 use all of them, including ML-KEM and the hybrids.
    /// </summary>
    public static class NamedGroups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort Secp521r1 = 0x0019;
        public const ushort X25519 = 0x001d;
        public const ushort X448 = 0x001e;
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;
        public const ushort MlKem512 = 0x0200;
        public const ushort MlKem768 = 0x0201;
        public const ushort MlKem1024 = 0x0202;
        public const ushort SecP256r1MlKem768 = 0x11eb;
        public const ushort X25519MlKem768 = 0x11ec;
        public const ushort SecP384r1MlKem1024 = 0x11ed;
    }
}
