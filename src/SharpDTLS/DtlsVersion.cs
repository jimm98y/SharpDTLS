namespace SharpDTLS
{
    /// <summary>
    /// DTLS protocol version code points. DTLS versions count down: 1.0 = 0xFEFF, 1.2 = 0xFEFD, 1.3 = 0xFEFC.
    /// (DTLS 1.1 was never defined; DTLS 1.2 corresponds to TLS 1.2, DTLS 1.0 to TLS 1.1.)
    /// </summary>
    public static class DtlsVersion
    {
        public const ushort Dtls10 = 0xFEFF;
        public const ushort Dtls12 = 0xFEFD;
        public const ushort Dtls13 = 0xFEFC;

        /// <summary>True when <paramref name="version"/> is the same as or newer than <paramref name="minimum"/>.</summary>
        public static bool IsAtLeast(ushort version, ushort minimum) => version <= minimum;

        public static string Name(ushort version) => version switch
        {
            Dtls10 => "DTLS 1.0",
            Dtls12 => "DTLS 1.2",
            Dtls13 => "DTLS 1.3",
            _ => $"0x{version:X4}",
        };
    }
}
