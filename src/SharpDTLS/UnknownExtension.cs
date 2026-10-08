using System;

namespace SharpDTLS
{
    /// <summary>
    /// An extension this implementation does not interpret. Unknown extensions MUST be ignored
    /// (RFC 8446 §4.2), so the raw bytes are only kept for round-tripping.
    /// </summary>
    public class UnknownExtension : ITlsExtension
    {
        public ushort ExtensionType { get; private set; }
        public byte[] Data { get; private set; } = Array.Empty<byte>();

        public UnknownExtension() { }

        public UnknownExtension(ushort extensionType, byte[] data)
        {
            ExtensionType = extensionType;
            Data = data ?? Array.Empty<byte>();
        }

        public int CalculateLength() => 4 + Data.Length;

        public int Read(int offset, byte[] source)
        {
            if (source.Length < offset + 4) throw new DtlsException(AlertDescription.DecodeError, "Truncated extension header.");
            ExtensionType = (ushort)((source[offset] << 8) | source[offset + 1]);
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length) throw new DtlsException(AlertDescription.DecodeError, "Truncated extension body.");
            Data = new byte[length];
            Buffer.BlockCopy(source, offset + 4, Data, 0, length);
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = (byte)(ExtensionType >> 8);
            destination[offset + 1] = (byte)ExtensionType;
            destination[offset + 2] = (byte)(Data.Length >> 8);
            destination[offset + 3] = (byte)Data.Length;
            Buffer.BlockCopy(Data, 0, destination, offset + 4, Data.Length);
            return 4 + Data.Length;
        }
    }
}
