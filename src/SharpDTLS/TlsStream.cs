using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.TLS12;
using SharpDTLS.Protocol13;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS
{
    /// <summary>
    /// A TLS connection as a <see cref="Stream"/>, like <see cref="System.Net.Security.SslStream"/>: writes are split
    /// into records, reads block until data arrives, a close_notify from the peer reads as the end of the stream and a
    /// failed connection throws <see cref="IOException"/>. Disposing sends close_notify. Any TLS version: clients offer
    /// TLS 1.3 and 1.2 (see <see cref="TlsClient"/>), and a <see cref="TlsServer"/> answers with either.
    /// </summary>
    public sealed class TlsStream : Stream
    {
        private readonly object _sync = new();
        private readonly Queue<byte[]> _received = new();
        private readonly Func<TlsConnectionBase> _connection;
        private byte[] _current;
        private int _currentOffset;
        private bool _ended;
        private Exception _error;
        private TaskCompletionSource<bool> _dataAvailable = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private TlsStream(Func<TlsConnectionBase> connection) => _connection = connection;

        /// <summary>
        /// The connection carrying the stream: a TLS 1.0-1.2 (<see cref="Tls12Connection"/>) or TLS 1.3
        /// (<see cref="Tls13Connection"/>) engine, with its certificates, ALPN and exporter.
        /// </summary>
        public TlsConnectionBase Connection => _connection();

        /// <summary>The negotiated TLS version.</summary>
        public ushort NegotiatedVersion => Connection is Tls12Connection tls12 ? tls12.NegotiatedVersion : TlsVersion.Tls13;

        /// <summary>Connects as a client over <paramref name="inner"/> (e.g. a NetworkStream) and completes the handshake.</summary>
        public static async Task<TlsStream> ConnectAsync(Stream inner, Action<TlsClient> configure = null, CancellationToken cancellationToken = default)
        {
            var client = new TlsClient(inner);
            configure?.Invoke(client);
            var stream = new TlsStream(() => client.Connection);
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.ApplicationDataReceived += (_, data) => stream.Signal(() => stream._received.Enqueue(data));
            client.Closed += (_, _) => { stream.Signal(() => stream._ended = true); done.TrySetException(new IOException("The connection closed during the TLS handshake.")); };
            client.Failed += (_, ex) => { stream.Signal(() => stream._error = ex); done.TrySetException(new IOException("The TLS handshake failed: " + ex.Message, ex)); };
            client.BeginHandshake();
            await done.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return stream;
        }

        /// <summary>Serves a client connected on <paramref name="inner"/> with any TLS version and completes the handshake.</summary>
        public static async Task<TlsStream> AcceptAsync(TlsServer server, Stream inner, CancellationToken cancellationToken = default)
        {
            var connection = await server.AcceptAsync(inner, cancellationToken: cancellationToken).ConfigureAwait(false)
                ?? throw new IOException("The client did not send a ClientHello.");
            return await Accepted(connection, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Serves a TLS 1.0-1.2 client connected on <paramref name="inner"/> and completes the handshake.</summary>
        internal static Task<TlsStream> AcceptAsync(Tls12Server server, Stream inner, CancellationToken cancellationToken = default)
            => Accepted(server.Accept(inner), cancellationToken);

        private static async Task<TlsStream> Accepted(TlsConnectionBase connection, CancellationToken cancellationToken)
        {
            var stream = new TlsStream(() => connection);
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler<EventArgs> finished = (_, _) => done.TrySetResult(true);
            if (connection is Tls12ServerConnection tls12)
                tls12.HandshakeFinished += finished;
            else
                ((Tls13ServerConnection)connection).HandshakeFinished += finished;
            connection.ApplicationDataReceived += (_, data) => stream.Signal(() => stream._received.Enqueue(data));
            connection.Closed += (_, _) => { stream.Signal(() => stream._ended = true); done.TrySetException(new IOException("The connection closed during the TLS handshake.")); };
            connection.Failed += (_, ex) => { stream.Signal(() => stream._error = ex); done.TrySetException(new IOException("The TLS handshake failed: " + ex.Message, ex)); };
            if (connection.IsHandshakeComplete)
                done.TrySetResult(true);
            await done.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return stream;
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

        public override int Read(byte[] buffer, int offset, int count) => ReadCoreAsync(buffer.AsMemory(offset, count), default).GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadCoreAsync(buffer.AsMemory(offset, count), cancellationToken);

#if NETCOREAPP
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new ValueTask<int>(ReadCoreAsync(buffer, cancellationToken));
#endif

        private async Task<int> ReadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken)
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

        public override void Write(byte[] buffer, int offset, int count) => WriteCore(buffer.AsSpan(offset, count));

#if NETCOREAPP
        public override void Write(ReadOnlySpan<byte> buffer) => WriteCore(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            WriteCore(buffer.Span);
            return ValueTask.CompletedTask;
        }
#endif

        private void WriteCore(ReadOnlySpan<byte> buffer)
        {
            try
            {
                var connection = Connection;
                while (buffer.Length > 0)
                {
                    int n = Math.Min(buffer.Length, connection.MaxApplicationDataSize);
                    connection.SendApplicationData(buffer.Slice(0, n).ToArray());
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

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Connection?.Close();
            base.Dispose(disposing);
        }
    }
}
