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
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS
{
    /// <summary>A stream that first returns bytes already read from <c>inner</c> (e.g. a peeked ClientHello).</summary>
    internal sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
    {
        private int _offset;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override int Read(byte[] buffer, int offset, int count)
            => _offset < prefix.Length ? ReadPrefix(buffer.AsSpan(offset, count)) : inner.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _offset < prefix.Length ? Task.FromResult(ReadPrefix(buffer.AsSpan(offset, count))) : inner.ReadAsync(buffer, offset, count, cancellationToken);

#if NETCOREAPP
        public override int Read(Span<byte> buffer) => _offset < prefix.Length ? ReadPrefix(buffer) : inner.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _offset < prefix.Length ? new ValueTask<int>(ReadPrefix(buffer.Span)) : inner.ReadAsync(buffer, cancellationToken);
#endif

        private int ReadPrefix(Span<byte> buffer)
        {
            int n = Math.Min(buffer.Length, prefix.Length - _offset);
            prefix.AsSpan(_offset, n).CopyTo(buffer);
            _offset += n;
            return n;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
