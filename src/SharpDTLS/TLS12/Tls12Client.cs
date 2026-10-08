using SharpDTLS.DTLS12;
using System.IO;

namespace SharpDTLS.TLS12
{
    /// <summary>
    /// TLS 1.2 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// DTLS 1.0/1.2 client's handshake over TLS framing, so the same settings apply; DTLS-only ones (SRTP, connection
    /// IDs) are ignored. Set <see cref="Dtls12Connection.MinimumVersion"/> to accept older TLS versions.
    /// </summary>
    public class Tls12Client : Dtls12ClientConnection
    {
        private readonly Stream _stream;

        public Tls12Client(Stream stream, bool leaveStreamOpen = false)
            : base(record => TlsStreamPump.Write(stream, record), stream: true)
        {
            _stream = stream;
            MinimumVersion = TlsVersion.Tls12;
            MaximumVersion = TlsVersion.Tls12;
            if (!leaveStreamOpen)
                Closed += (_, _) => _stream.Dispose();
            TlsStreamPump.Start(stream, this);
        }
    }
}
