using SharpSRTP.UDP;

namespace SharpDTLS.DTLS13
{
    /// <summary>DTLS 1.3 client (RFC 9147) over a datagram transport.</summary>
    public class Dtls13Client : Tls13ClientConnection
    {
        public IClientTransport ClientTransport { get; }

        public Dtls13Client(IClientTransport clientTransport)
            : base(data => clientTransport.Send(data), stream: false)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += (_, data) => ProcessDatagram(data);
        }
    }
}
