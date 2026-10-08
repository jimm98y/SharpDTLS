using SharpDTLS.DTLS13;
using SharpDTLS.TLS12;
using System.IO;

namespace SharpDTLS.TLS13
{
    /// <summary>
    /// TLS 1.3 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// DTLS 1.3 client's handshake over TLS records (RFC 8446), so the same settings apply; DTLS-only ones (SRTP,
    /// connection IDs) are ignored, and 0-RTT is not offered.
    /// </summary>
    public class Tls13Client : Dtls13Client
    {
        private readonly Stream _stream;

        public Tls13Client(Stream stream, bool leaveStreamOpen = false)
            : base(record => TlsStreamPump.Write(stream, record), stream: true)
        {
            _stream = stream;
            if (!leaveStreamOpen)
                Closed += (_, _) => _stream.Dispose();
            TlsStreamPump.Start(stream, this);
        }
    }
}
