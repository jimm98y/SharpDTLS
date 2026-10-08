using SharpDTLS.DTLS13;
using SharpDTLS.TLS12;
using System.Collections.Generic;
using System.IO;

namespace SharpDTLS.TLS13
{
    /// <summary>
    /// TLS 1.3 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// shared 1.3 client handshake over TLS records (RFC 8446), so the same settings apply; DTLS-only ones (SRTP,
    /// connection IDs) are ignored. 0-RTT data (EarlyData, with a ResumptionTicket) ends with EndOfEarlyData.
    /// </summary>
    public class Tls13Client : Tls13ClientConnection
    {
        // Shares for the post-quantum hybrid that servers such as OpenSSL 3.5+ prefer, and for x25519: either way no
        // HelloRetryRequest (which also costs 0-RTT). Over a stream the larger ClientHello is no problem.
        protected override IReadOnlyList<ushort> DefaultKeyShareGroups { get; } = new[] { Dtls13Groups.X25519MlKem768, Dtls13Groups.X25519 };

        private readonly Stream _stream;

        /// <summary>For <see cref="TlsClient"/>, which reads the stream and feeds the active engine.</summary>
        internal Tls13Client(System.Action<byte[]> send)
            : base(send, stream: true)
        {
        }

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
