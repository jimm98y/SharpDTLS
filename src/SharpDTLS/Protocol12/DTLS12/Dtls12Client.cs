// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using SharpDTLS.Protocol12.Messages;
using SharpDTLS.UDP;
using System;

namespace SharpDTLS.Protocol12.DTLS12
{
    /// <summary>
    /// DTLS 1.2 client. Set <see cref="Tls12Connection.MinimumVersion"/> to <see cref="DtlsVersion.Dtls10"/>
    /// to also accept DTLS 1.0 servers.
    /// </summary>
    internal class Dtls12Client : Tls12ClientConnection
    {
        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;

        /// <summary>Negotiated parameters, populated when the handshake completes.</summary>
        public Dtls12Session Session { get; } = new Dtls12Session();

        public IClientTransport ClientTransport { get; }

        public Dtls12Client(IClientTransport clientTransport)
            : this(clientTransport, receive: true)
        {
        }

        /// <param name="receive">False when the caller feeds received datagrams to <see cref="TlsConnectionBase.ProcessDatagram(byte[])"/>.</param>
        internal Dtls12Client(IClientTransport clientTransport, bool receive)
            : base(data => clientTransport.Send(data))
        {
            ClientTransport = clientTransport;
            if (receive)
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
            NewSessionTicketMessageReceived += (_, ticket)
                => NewSessionTicketReceived?.Invoke(this, new NewSessionTicketDatagram(ticket.Ticket, ticket.LifetimeHint));
        }
    }
}
