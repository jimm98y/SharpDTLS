using System.IO;

namespace SharpDTLS.Protocol12.TLS12
{
    /// <summary>
    /// TLS 1.2 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// DTLS 1.0/1.2 client's handshake over TLS framing, so the same settings apply; DTLS-only ones (SRTP, connection
    /// IDs) are ignored. Set <see cref="Tls12Connection.MinimumVersion"/> to also accept TLS 1.0 or 1.1 servers,
    /// and <see cref="Tls12Connection.MaximumVersion"/> to speak only those.
    /// </summary>
    internal class Tls12Client : Tls12ClientConnection
    {
        private readonly Stream _stream;

        /// <summary>For <see cref="SharpDTLS.TlsClient"/>, which reads the stream and feeds the active engine.</summary>
        internal Tls12Client(System.Action<byte[]> send)
            : base(send, stream: true)
        {
            MinimumVersion = TlsVersion.Tls12;
            MaximumVersion = TlsVersion.Tls12;
        }

        public Tls12Client(Stream stream, bool leaveStreamOpen = false)
            : base(record => TlsStreamPump.Write(stream, record), stream: true)
        {
            _stream = stream;
            MinimumVersion = TlsVersion.Tls12;
            MaximumVersion = TlsVersion.Tls12;
            if (!leaveStreamOpen)
                Closed += (_, _) => TlsStreamPump.DisposeAfterLinger(_stream);
            TlsStreamPump.Start(stream, this, ownsStream: !leaveStreamOpen);
        }
    }
}
