// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using System;

namespace SharpDTLS
{
    /// <summary>
    /// An extension this implementation does not interpret. Unknown extensions MUST be ignored
    /// (RFC 8446 §4.2), so the raw bytes are only kept for round-tripping.
    /// </summary>
    internal class UnknownExtension : ITlsExtension
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
