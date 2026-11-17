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

namespace SharpDTLS
{
    /// <summary>
    /// A connection ID as a dictionary key, made of the received record's bytes without allocating: up to 32 bytes are
    /// held in the key itself (servers issue 8 by default), a longer one as a string.
    /// </summary>
    internal readonly struct ConnectionIdKey : IEquatable<ConnectionIdKey>
    {
        private readonly ulong _a, _b, _c, _d;
        private readonly int _length;
        private readonly string _long;

        public ConnectionIdKey(ReadOnlySpan<byte> connectionId)
        {
            _length = connectionId.Length;
            _a = _b = _c = _d = 0;
            _long = null;
            if (connectionId.Length > 32)
            {
                _long = Convert.ToHexString(connectionId.ToArray());
                return;
            }
            Span<byte> padded = stackalloc byte[32];
            padded.Clear();
            connectionId.CopyTo(padded);
            _a = BinaryPrimitives.ReadUInt64LittleEndian(padded);
            _b = BinaryPrimitives.ReadUInt64LittleEndian(padded.Slice(8));
            _c = BinaryPrimitives.ReadUInt64LittleEndian(padded.Slice(16));
            _d = BinaryPrimitives.ReadUInt64LittleEndian(padded.Slice(24));
        }

        public bool Equals(ConnectionIdKey other)
            => _length == other._length && _a == other._a && _b == other._b && _c == other._c && _d == other._d && _long == other._long;

        public override bool Equals(object obj) => obj is ConnectionIdKey other && Equals(other);

        // a peer chooses the bytes: on .NET the hash is randomized per process, as a string's is
        public override int GetHashCode()
#if NETCOREAPP
            => _long?.GetHashCode() ?? HashCode.Combine(_a, _b, _c, _d, _length);
#else
            => _long?.GetHashCode() ?? (int)(_a ^ (_a >> 32) ^ _b ^ (_b >> 32) ^ _c ^ (_c >> 32) ^ _d ^ (_d >> 32)) ^ _length;
#endif
    }
}
