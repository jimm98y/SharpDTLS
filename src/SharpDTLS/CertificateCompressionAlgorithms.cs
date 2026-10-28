namespace SharpDTLS
{
    /// <summary>Certificate compression algorithms (RFC 8879), used by TLS/DTLS 1.3.</summary>
    public static class CertificateCompressionAlgorithms
    {
        public const ushort Zlib = 1;
        public const ushort Brotli = 2;
        public const ushort Zstd = 3;
    }
}
