using SharpDTLS.DTLS12.Messages;
using SharpSRTP.UDP;
using System;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// DTLS 1.2 client. Set <see cref="Dtls12Connection.MinimumVersion"/> to <see cref="DtlsVersion.Dtls10"/>
    /// to also accept DTLS 1.0 servers.
    /// </summary>
    public class Dtls12Client : Dtls12ClientConnection
    {
        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;

        /// <summary>Negotiated parameters, populated when the handshake completes.</summary>
        public Dtls12Session Session { get; } = new Dtls12Session();

        public IClientTransport ClientTransport { get; }

        public Dtls12Client(IClientTransport clientTransport)
            : base(data => clientTransport.Send(data))
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += (_, data) => ProcessDatagram(data);

            HandshakeFinished += (_, _) =>
            {
                Session.ClientRandom = ClientRandomBytes;
                Session.ServerRandom = ServerRandomBytes;
                Session.CipherSuite = CipherSuite.Id;
                Session.NamedGroup = NamedGroup;
                Session.UseExtendedMasterSecret = ExtendedMasterSecretNegotiated;
                Session.SrtpProtectionProfile = SelectedSrtpProtectionProfile;
                Session.Epoch = 1;
            };
            NewSessionTicketMessageReceived += (_, ticket)
                => NewSessionTicketReceived?.Invoke(this, new NewSessionTicketDatagram(ticket.Ticket, ticket.LifetimeHint));
        }
    }
}
