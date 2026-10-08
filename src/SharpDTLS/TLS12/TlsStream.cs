using SharpDTLS.DTLS12;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.TLS12
{
    /// <summary>
    /// A TLS connection as a <see cref="Stream"/>, like <see cref="System.Net.Security.SslStream"/>: writes are split
    /// into records, reads block until data arrives, a close_notify from the peer reads as the end of the stream and a
    /// failed connection throws <see cref="IOException"/>. Disposing sends close_notify.
    /// </summary>
    public sealed class TlsStream : Stream
    {
        private readonly object _sync = new();
        private readonly Queue<byte[]> _received = new();
        private byte[] _current;
        private int _currentOffset;
        private bool _ended;
        private Exception _error;
        private TaskCompletionSource<bool> _dataAvailable = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private TlsStream(Dtls12Connection connection)
        {
            Connection = connection;
            connection.ApplicationDataReceived += (_, data) => Signal(() => _received.Enqueue(data));
            connection.Closed += (_, _) => Signal(() => _ended = true);
            connection.Failed += (_, ex) => Signal(() => _error = ex);
        }

        /// <summary>The underlying connection: negotiated version, cipher suite, ALPN, certificates, exporter.</summary>
        public Dtls12Connection Connection { get; }

        /// <summary>Connects as a client over <paramref name="inner"/> (e.g. a NetworkStream) and completes the handshake.</summary>
        public static async Task<TlsStream> ConnectAsync(Stream inner, Action<Tls12Client> configure = null, CancellationToken cancellationToken = default)
        {
            var client = new Tls12Client(inner);
            configure?.Invoke(client);
            var stream = new TlsStream(client);
            var handshake = Handshake(client, h => client.HandshakeFinished += h);
            client.BeginHandshake();
            await handshake.WaitAsync(cancellationToken).ConfigureAwait(false);
            return stream;
        }

        /// <summary>Serves a client connected on <paramref name="inner"/> with <paramref name="server"/>'s settings and completes the handshake.</summary>
        public static async Task<TlsStream> AcceptAsync(Tls12Server server, Stream inner, CancellationToken cancellationToken = default)
        {
            var connection = server.Accept(inner);
            var stream = new TlsStream(connection);
            await Handshake(connection, h => connection.HandshakeFinished += h).WaitAsync(cancellationToken).ConfigureAwait(false);
            return stream;
        }

        private static Task Handshake(Dtls12Connection connection, Action<EventHandler<EventArgs>> subscribe)
        {
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            subscribe((_, _) => done.TrySetResult(true));
            connection.Failed += (_, ex) => done.TrySetException(new IOException("The TLS handshake failed: " + ex.Message, ex));
            connection.Closed += (_, _) => done.TrySetException(new IOException("The connection closed during the TLS handshake."));
            if (connection.IsHandshakeComplete)
                done.TrySetResult(true);
            return done.Task;
        }

        private void Signal(Action update)
        {
            TaskCompletionSource<bool> waiting;
            lock (_sync)
            {
                update();
                waiting = _dataAvailable;
            }
            waiting.TrySetResult(true);
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0)
                return 0;
            while (true)
            {
                Task wait;
                lock (_sync)
                {
                    if (_current == null && _received.Count > 0)
                        (_current, _currentOffset) = (_received.Dequeue(), 0);
                    if (_current != null)
                    {
                        int n = Math.Min(buffer.Length, _current.Length - _currentOffset);
                        _current.AsMemory(_currentOffset, n).CopyTo(buffer);
                        _currentOffset += n;
                        if (_currentOffset == _current.Length)
                            _current = null;
                        if (n > 0)
                            return n;
                        continue; // an empty record
                    }
                    if (_error != null)
                        throw new IOException("The TLS connection failed: " + _error.Message, _error);
                    if (_ended)
                        return 0;
                    if (_dataAvailable.Task.IsCompleted)
                        _dataAvailable = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _dataAvailable.Task;
                }
                await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            try
            {
                while (buffer.Length > 0)
                {
                    int n = Math.Min(buffer.Length, Connection.MaxApplicationDataSize);
                    Connection.SendApplicationData(buffer.Slice(0, n).ToArray());
                    buffer = buffer.Slice(n);
                }
            }
            catch (InvalidOperationException ex)
            {
                throw new IOException("The TLS connection is closed.", ex);
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Connection.Close();
            base.Dispose(disposing);
        }
    }
}
