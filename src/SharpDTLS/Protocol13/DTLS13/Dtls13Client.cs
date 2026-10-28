using SharpDTLS.UDP;

namespace SharpDTLS.Protocol13.DTLS13
{
    /// <summary>DTLS 1.3 client (RFC 9147) over a datagram transport.</summary>
    public class Dtls13Client : Tls13ClientConnection
    {
        public IClientTransport ClientTransport { get; }

        public Dtls13Client(IClientTransport clientTransport)
            : this(clientTransport, receive: true)
        {
        }

        /// <param name="receive">False when the caller feeds received datagrams to <see cref="TlsConnectionBase.ProcessDatagram(byte[])"/>.</param>
        internal Dtls13Client(IClientTransport clientTransport, bool receive)
            : base(data => clientTransport.Send(data), stream: false)
        {
            ClientTransport = clientTransport;
            if (receive)
                ClientTransport.OnDataReceived += (_, data) => ProcessDatagram(data);
        }
    }
}
