using SharpDTLS.Protocol12;
using SharpDTLS.UDP;

namespace SharpDTLS.Protocol10.DTLS10
{
    /// <summary>
    /// DTLS 1.0 client (RFC 4347): the DTLS 1.0/1.2 engine restricted to DTLS 1.0.
    /// </summary>
    public class Dtls10Client : Tls12ClientConnection
    {
        /// <summary>Negotiated parameters, populated when the handshake completes.</summary>
        public Dtls10Session Session { get; } = new Dtls10Session();

        public IClientTransport ClientTransport { get; }

        public Dtls10Client(IClientTransport clientTransport)
            : base(data => clientTransport.Send(data))
        {
            MinimumVersion = DtlsVersion.Dtls10;
            MaximumVersion = DtlsVersion.Dtls10;
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
                Session.SrtpMki = SelectedSrtpMki;
                Session.Epoch = 1;
            };
        }
    }
}
