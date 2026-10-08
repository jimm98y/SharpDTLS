using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// TLS certificate compression (RFC 8879) for DTLS 1.3: zlib and Brotli (zstd is not available in .NET). Decompression
    /// is bounded by the declared length, itself capped at the largest handshake message accepted.
    /// </summary>
    public static class CertificateCompression
    {
        public const ushort Zlib = 1;
        public const ushort Brotli = 2;
        public const ushort Zstd = 3;

        /// <summary>The implemented algorithms, in default preference order.</summary>
        public static IReadOnlyList<ushort> Supported { get; } = new[] { Brotli, Zlib };

        /// <summary>The largest uncompressed Certificate accepted.</summary>
        public const int MaxUncompressedLength = HandshakeReassembler.MaxMessageLength;

        internal static void Validate(IEnumerable<ushort> algorithms)
        {
            foreach (ushort algorithm in algorithms ?? Array.Empty<ushort>())
            {
                if (!Supported.Contains(algorithm))
                    throw new InvalidOperationException($"Certificate compression algorithm {algorithm} is not implemented.");
            }
        }

        /// <summary>Our first preferred algorithm that the peer offered, or null.</summary>
        internal static ushort? Select(IEnumerable<ushort> preference, IEnumerable<ushort> offered)
        {
            if (preference == null || offered == null)
                return null;
            var peer = offered.ToList();
            foreach (ushort algorithm in preference)
            {
                if (Supported.Contains(algorithm) && peer.Contains(algorithm))
                    return algorithm;
            }
            return null;
        }

        public static byte[] Compress(ushort algorithm, byte[] data)
        {
            using var output = new MemoryStream();
            using (Stream compressor = algorithm switch
            {
                Zlib => new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true),
                Brotli => new BrotliStream(output, CompressionLevel.Optimal, leaveOpen: true),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
            })
            {
                compressor.Write(data);
            }
            return output.ToArray();
        }

        /// <summary>
        /// Decompresses exactly <paramref name="uncompressedLength"/> bytes; anything else (including more data) is
        /// bad_certificate (RFC 8879 §4).
        /// </summary>
        public static byte[] Decompress(ushort algorithm, byte[] compressed, int uncompressedLength)
        {
            if (uncompressedLength <= 0 || uncompressedLength > MaxUncompressedLength)
                throw new DtlsException(AlertDescription.BadCertificate, $"Compressed certificate of {uncompressedLength} bytes.");
            try
            {
                using var input = new MemoryStream(compressed);
                using Stream decompressor = algorithm switch
                {
                    Zlib => new ZLibStream(input, CompressionMode.Decompress),
                    Brotli => new BrotliStream(input, CompressionMode.Decompress),
                    _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unknown certificate compression algorithm {algorithm}."),
                };
                byte[] result = new byte[uncompressedLength];
                int read = 0, n;
                while (read < result.Length && (n = decompressor.Read(result, read, result.Length - read)) > 0)
                    read += n;
                if (read != uncompressedLength || decompressor.ReadByte() != -1)
                    throw new DtlsException(AlertDescription.BadCertificate, "Compressed certificate has the wrong length.");
                return result;
            }
            catch (InvalidDataException ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "Compressed certificate could not be decompressed.", ex);
            }
        }
    }

    /// <summary>compress_certificate (RFC 8879 §3): the algorithms the sender can decompress, in preference order.</summary>
    public class CompressCertificateExtension : ITlsExtension
    {
        public const ushort Type = 27;

        public CompressCertificateExtension() { }

        public CompressCertificateExtension(IEnumerable<ushort> algorithms)
        {
            Algorithms = algorithms.ToList();
            if (Algorithms.Count == 0 || Algorithms.Count > 127)
                throw new ArgumentException("One to 127 algorithms.", nameof(algorithms));
        }

        public List<ushort> Algorithms { get; private set; } = new();

        public int CalculateLength() => 5 + 2 * Algorithms.Count;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length || length < 3 || source[offset + 4] != length - 1 || (length - 1) % 2 != 0)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid compress_certificate extension.");
            Algorithms = new List<ushort>();
            for (int i = 0; i < length - 1; i += 2)
                Algorithms.Add((ushort)((source[offset + 5 + i] << 8) | source[offset + 6 + i]));
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            int length = 1 + 2 * Algorithms.Count;
            destination[offset] = 0;
            destination[offset + 1] = (byte)Type;
            destination[offset + 2] = 0;
            destination[offset + 3] = (byte)length;
            destination[offset + 4] = (byte)(2 * Algorithms.Count);
            for (int i = 0; i < Algorithms.Count; i++)
            {
                destination[offset + 5 + 2 * i] = (byte)(Algorithms[i] >> 8);
                destination[offset + 6 + 2 * i] = (byte)Algorithms[i];
            }
            return 4 + length;
        }
    }
}
