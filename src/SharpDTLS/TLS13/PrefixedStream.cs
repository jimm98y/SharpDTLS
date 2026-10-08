using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.TLS13
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

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_offset < prefix.Length)
            {
                int n = Math.Min(buffer.Length, prefix.Length - _offset);
                prefix.AsSpan(_offset, n).CopyTo(buffer);
                _offset += n;
                return n;
            }
            return inner.Read(buffer);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _offset < prefix.Length ? new ValueTask<int>(Read(buffer.Span)) : inner.ReadAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
