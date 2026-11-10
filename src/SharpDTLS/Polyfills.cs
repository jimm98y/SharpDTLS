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

#if !NETCOREAPP
// What SharpDTLS uses on netstandard2.0 beyond Meziantou.Polyfill (which covers the rest).
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

internal static class SharpDtlsPolyfills
{
    // FixedTimeEquals comes from Meziantou.Polyfill (1.0.170 and later).
    extension(CryptographicOperations)
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroMemory(Span<byte> buffer) => buffer.Clear();
    }

    extension(IPEndPoint)
    {
        /// <summary>"address:port", or "[address]:port" for IPv6.</summary>
        public static IPEndPoint Parse(string s)
        {
            int colon = s.LastIndexOf(':');
            string address = s.Substring(0, colon);
            if (address.StartsWith("[") && address.EndsWith("]"))
                address = address.Substring(1, address.Length - 2);
            return new IPEndPoint(IPAddress.Parse(address), int.Parse(s.Substring(colon + 1)));
        }
    }

    extension(uint)
    {
        public static uint RotateLeft(uint value, int offset) => (value << offset) | (value >> (32 - offset));
    }

    /// <summary>Removes the entry only while it still has this value.</summary>
    public static bool TryRemove<TKey, TValue>(this ConcurrentDictionary<TKey, TValue> dictionary, KeyValuePair<TKey, TValue> item)
        => ((ICollection<KeyValuePair<TKey, TValue>>)dictionary).Remove(item);

    public static Task<int> ReadAsync(this Stream stream, byte[] buffer) => stream.ReadAsync(buffer, 0, buffer.Length);

    public static async Task ReadExactlyAsync(this Stream stream, byte[] buffer, CancellationToken cancellationToken = default)
    {
        for (int read = 0, n; read < buffer.Length; read += n)
        {
            n = await stream.ReadAsync(buffer, read, buffer.Length - read, cancellationToken).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException();
        }
    }
}

namespace System.IO.Compression
{
    /// <summary>
    /// The zlib format (RFC 1950) over <see cref="DeflateStream"/>: a 2-byte header, raw deflate data and an Adler-32
    /// trailer. Decompression does not check the trailer.
    /// </summary>
    internal sealed class ZLibStream : Stream
    {
        private readonly Stream _stream;
        private readonly DeflateStream _deflate;
        private readonly bool _compress;
        private readonly bool _leaveOpen;
        private uint _adlerA = 1, _adlerB;

        public ZLibStream(Stream stream, CompressionLevel level, bool leaveOpen)
        {
            _stream = stream;
            _compress = true;
            _leaveOpen = leaveOpen;
            stream.WriteByte(0x78); // deflate, 32K window
            stream.WriteByte(0xDA); // no dictionary; (0x78 << 8 | 0xDA) % 31 == 0
            _deflate = new DeflateStream(stream, level, leaveOpen: true);
        }

        public ZLibStream(Stream stream, CompressionMode mode)
        {
            if (mode != CompressionMode.Decompress)
                throw new ArgumentException("Compression needs a CompressionLevel.", nameof(mode));
            _stream = stream;
            int cmf = stream.ReadByte(), flg = stream.ReadByte();
            if (cmf < 0 || flg < 0 || (cmf & 0x0F) != 8 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20) != 0)
                throw new InvalidDataException("Not a zlib stream.");
            _deflate = new DeflateStream(stream, CompressionMode.Decompress, leaveOpen: true);
        }

        public override bool CanRead => !_compress;
        public override bool CanWrite => _compress;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _deflate.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _deflate.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count)
        {
            for (int i = offset; i < offset + count; i++)
            {
                _adlerA = (_adlerA + buffer[i]) % 65521;
                _adlerB = (_adlerB + _adlerA) % 65521;
            }
            _deflate.Write(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _deflate.Dispose();
                if (_compress)
                {
                    uint adler = (_adlerB << 16) | _adlerA;
                    _stream.Write(new[] { (byte)(adler >> 24), (byte)(adler >> 16), (byte)(adler >> 8), (byte)adler }, 0, 4);
                }
                if (!_leaveOpen)
                    _stream.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
#endif
