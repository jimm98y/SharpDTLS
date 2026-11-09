using SharpDTLS.Protocol12;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace SharpDTLS
{
    /// <summary>Feeds bytes read from a stream into a TLS connection until the stream ends.</summary>
    internal static class TlsStreamPump
    {
        /// <summary>
        /// How long the stream of a closed connection stays open before it is disposed, being read and the data
        /// dropped. Closing a socket with data still unread makes it reset the connection (on Windows), and the reset
        /// can discard what was sent last, such as our close_notify: a TLS 1.3 client that closes right after the
        /// handshake has not read the server's NewSessionTicket yet. This does not wait for the peer to close.
        /// </summary>
        internal static readonly TimeSpan CloseLinger = TimeSpan.FromMilliseconds(200);

        /// <param name="ownsStream">
        /// Whether the stream is disposed when the connection closes: it is then read until disposed, see
        /// <see cref="CloseLinger"/>; otherwise reading stops when the connection closes, leaving the rest to the caller.
        /// </param>
        public static Task Start(Stream stream, Tls12Connection connection, bool ownsStream)
            => Start(stream, connection, connection.ProcessStreamData, connection.OnTransportClosed, ownsStream);

        /// <inheritdoc cref="Start(Stream, Tls12Connection, bool)"/>
        public static Task Start(Stream stream, SharpDTLS.Protocol13.Tls13Connection connection, bool ownsStream)
            => Start(stream, connection, connection.ProcessStreamData, connection.OnTransportClosed, ownsStream);

        private static Task Start(Stream stream, TlsConnectionBase connection, Action<byte[], int, int> process, Action closed, bool ownsStream)
            => Run(stream, () => connection, (buffer, read) => process(buffer, 0, read), closed, ownsStream);

        /// <summary>
        /// Reads <paramref name="stream"/> into the connection <paramref name="active"/> returns, until the stream ends,
        /// then calls <paramref name="closed"/>. Once the connection is closed, data read is dropped, and reading stops
        /// unless <paramref name="ownsStream"/>.
        /// </summary>
        public static Task Run(Stream stream, Func<TlsConnectionBase> active, Action<byte[], int> process, Action closed, bool ownsStream) => Task.Run(async () =>
        {
            byte[] buffer = new byte[16384 + 2048 + 5];
            try
            {
                int read;
                while ((ownsStream || !active().IsClosed) && (read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
                {
                    if (!active().IsClosed)
                        process(buffer, read);
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                Debug.WriteLine($"[TLS] Read failed: {ex.Message}");
            }
            closed();
        });

        /// <summary>Disposes the stream of a closed connection after <see cref="CloseLinger"/>.</summary>
        public static void DisposeAfterLinger(Stream stream)
            => _ = Task.Delay(CloseLinger).ContinueWith(_ => stream.Dispose(), TaskScheduler.Default);

        /// <summary>Writes a record; failures surface as a closed stream on the read side.</summary>
        public static void Write(Stream stream, byte[] record)
        {
            stream.Write(record, 0, record.Length);
            stream.Flush();
        }
    }
}
