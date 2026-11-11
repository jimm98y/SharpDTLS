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
using System.Collections;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// Bytes received and not yet consumed, taken from the front: unlike a List, taking a record off the front
    /// does not move the rest, so a read packed with small records costs linear time, not quadratic.
    /// </summary>
    internal sealed class ByteQueue : IEnumerable<byte>
    {
        private byte[] _buffer = new byte[256];
        private int _start;
        private int _count;

        public int Count => _count;

        public byte this[int index]
        {
            get
            {
                if ((uint)index >= (uint)_count)
                    throw new ArgumentOutOfRangeException(nameof(index));
                return _buffer[_start + index];
            }
        }

        public void Add(byte value) => AddRange(new[] { value }, 0, 1);

        public void AddRange(byte[] data) => AddRange(data, 0, data.Length);

        public void AddRange(IEnumerable<byte> data)
        {
            foreach (byte b in data)
                Add(b);
        }

        public void AddRange(byte[] data, int offset, int count)
        {
            if (_start + _count + count > _buffer.Length)
            {
                if (_count + count <= _buffer.Length / 2)
                {
                    Buffer.BlockCopy(_buffer, _start, _buffer, 0, _count);
                }
                else
                {
                    var grown = new byte[Math.Max(_buffer.Length * 2, _count + count)];
                    Buffer.BlockCopy(_buffer, _start, grown, 0, _count);
                    _buffer = grown;
                }
                _start = 0;
            }
            Buffer.BlockCopy(data, offset, _buffer, _start + _count, count);
            _count += count;
        }

        /// <summary>A copy of <paramref name="count"/> bytes from <paramref name="index"/>.</summary>
        public byte[] GetRange(int index, int count)
        {
            if (index < 0 || count < 0 || index + count > _count)
                throw new ArgumentOutOfRangeException(nameof(count));
            var copy = new byte[count];
            Buffer.BlockCopy(_buffer, _start + index, copy, 0, count);
            return copy;
        }

        /// <summary>Drops <paramref name="count"/> bytes from the front (<paramref name="index"/> must be 0).</summary>
        public void RemoveRange(int index, int count)
        {
            if (index != 0 || count < 0 || count > _count)
                throw new ArgumentOutOfRangeException(nameof(count));
            _start += count;
            _count -= count;
            if (_count == 0)
                _start = 0;
        }

        public void Clear()
        {
            _start = 0;
            _count = 0;
        }

        public byte[] ToArray() => GetRange(0, _count);

        public IEnumerator<byte> GetEnumerator()
        {
            for (int i = 0; i < _count; i++)
                yield return _buffer[_start + i];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
