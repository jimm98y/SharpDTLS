using SharpDTLS.DTLS12;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace SharpDTLS.TLS12
{
    /// <summary>Feeds bytes read from a stream into a TLS connection until the stream ends.</summary>
    internal static class TlsStreamPump
    {
        public static Task Start(Stream stream, Tls12Connection connection)
            => Start(stream, connection, connection.ProcessStreamData, connection.OnTransportClosed);

        public static Task Start(Stream stream, SharpDTLS.DTLS13.Tls13Connection connection)
            => Start(stream, connection, connection.ProcessStreamData, connection.OnTransportClosed);

        private static Task Start(Stream stream, TlsConnectionBase connection, Action<byte[], int, int> process, Action closed) => Task.Run(async () =>
        {
            byte[] buffer = new byte[16384 + 2048 + 5];
            try
            {
                int read;
                while (!connection.IsClosed && (read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
                    process(buffer, 0, read);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                Debug.WriteLine($"[TLS] Read failed: {ex.Message}");
            }
            closed();
        });

        /// <summary>Writes a record; failures surface as a closed stream on the read side.</summary>
        public static void Write(Stream stream, byte[] record)
        {
            stream.Write(record, 0, record.Length);
            stream.Flush();
        }
    }
}
