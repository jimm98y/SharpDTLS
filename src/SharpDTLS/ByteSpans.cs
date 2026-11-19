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
using System.Buffers.Binary;
#if NET8_0_OR_GREATER
using System.Runtime.Intrinsics;
#endif

namespace SharpDTLS
{
    /// <summary>
    /// Byte span operations of the record path. XOR: 32 and 16 bytes at a time where the hardware has the vectors, then
    /// 8, then 1.
    /// </summary>
    internal static class ByteSpans
    {
        /// <summary>destination = a XOR b, of destination's length; destination may be a or b itself.</summary>
        public static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
        {
            int length = destination.Length;
            if (a.Length < length || b.Length < length)
                throw new ArgumentException("The inputs are shorter than the destination.");
            int i = 0;
#if NET8_0_OR_GREATER
            if (Vector256.IsHardwareAccelerated)
            {
                for (; i <= length - 32; i += 32)
                    (Vector256.Create(a.Slice(i, 32)) ^ Vector256.Create(b.Slice(i, 32))).CopyTo(destination.Slice(i, 32));
            }
            if (Vector128.IsHardwareAccelerated)
            {
                for (; i <= length - 16; i += 16)
                    (Vector128.Create(a.Slice(i, 16)) ^ Vector128.Create(b.Slice(i, 16))).CopyTo(destination.Slice(i, 16));
            }
#endif
            for (; i <= length - 8; i += 8)
                BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(i), BinaryPrimitives.ReadUInt64LittleEndian(a.Slice(i)) ^ BinaryPrimitives.ReadUInt64LittleEndian(b.Slice(i)));
            for (; i < length; i++)
                destination[i] = (byte)(a[i] ^ b[i]);
        }

        /// <summary>
        /// The length of <paramref name="data"/> without its trailing zeros (TLSInnerPlaintext padding, RFC 8446 §5.4):
        /// vectorized on .NET 8+.
        /// </summary>
        public static int WithoutTrailingZeros(ReadOnlySpan<byte> data)
        {
#if NET8_0_OR_GREATER
            return data.LastIndexOfAnyExcept((byte)0) + 1;
#else
            int end = data.Length;
            while (end > 0 && data[end - 1] == 0)
                end--;
            return end;
#endif
        }

        /// <summary>Whether every byte is zero, in time independent of the bytes (for secrets).</summary>
        public static bool IsAllZero(ReadOnlySpan<byte> data)
        {
            int any = 0;
            for (int i = 0; i < data.Length; i++)
                any |= data[i];
            return any == 0;
        }

        /// <summary>The nonce of RFC 8446 §5.3: the IV, its last 8 bytes XOR the big-endian 64-bit sequence number.</summary>
        public static void XorNonce(ReadOnlySpan<byte> iv, ulong sequenceNumber, Span<byte> nonce)
        {
            iv.CopyTo(nonce);
            var tail = nonce.Slice(nonce.Length - 8);
            BinaryPrimitives.WriteUInt64BigEndian(tail, BinaryPrimitives.ReadUInt64BigEndian(tail) ^ sequenceNumber);
        }
    }
}
