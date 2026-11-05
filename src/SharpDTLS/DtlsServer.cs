using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS
{
    public class DtlsDataReceivedEventArgs : EventArgs
    {
        public DtlsDataReceivedEventArgs(EndPoint remoteEndPoint, TlsConnectionBase connection, byte[] data)
        {
            RemoteEndPoint = remoteEndPoint;
            Connection = connection;
            Data = data;
        }

        public EndPoint RemoteEndPoint { get; }

        /// <summary>A <see cref="Tls12ServerConnection"/> (DTLS 1.0-1.2) or <see cref="Tls13ServerConnection"/> (DTLS 1.3).</summary>
        public TlsConnectionBase Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// A DTLS server for every version on one transport: each client's ClientHello decides between DTLS 1.3 and DTLS
    /// 1.0-1.2, and its later datagrams stay with that version. A DTLS 1.2 handshake carries the RFC 9147 §5.3
    /// downgrade sentinel while DTLS 1.3 is enabled.
    /// </summary>
    public class DtlsServer : TlsServerBase
    {
        private readonly EnginePort _port12;
        private readonly EnginePort _port13;
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        public DtlsServer(IServerTransport serverTransport)
            : this(serverTransport, Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public DtlsServer(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : this(serverTransport, new EnginePort(serverTransport), new EnginePort(serverTransport), keyPair, certificate)
        {
        }

        private DtlsServer(IServerTransport serverTransport, EnginePort port12, EnginePort port13, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(new Dtls12Server(port12, keyPair, certificate), new Dtls13Server(port13, keyPair, certificate))
        {
            ServerTransport = serverTransport;
            _port12 = port12;
            _port13 = port13;
            Dtls12.AutoUpdatePeerAddress = false; // the 1.3 default (RFC 9147 §11), for every version

            Dtls12.ConnectionEstablished += c => HandshakeFinished?.Invoke(this, c);
            Dtls13.HandshakeFinished += (_, e) => HandshakeFinished?.Invoke(this, ((Dtls13ConnectionEventArgs)e).Connection);
            Dtls12.ConnectionDataReceived += (c, data) => ApplicationDataReceived?.Invoke(this, new DtlsDataReceivedEventArgs(c.RemoteEndPoint, c, data));
            Dtls13.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new DtlsDataReceivedEventArgs(e.RemoteEndPoint, e.Connection, e.Data));
            Dtls12.ConnectionEnded += c => ConnectionClosed?.Invoke(this, c);
            Dtls13.ConnectionClosed += (_, e) => ConnectionClosed?.Invoke(this, e.Connection);
            Dtls13.EarlyDataReceived += (_, e) => EarlyDataReceived?.Invoke(this, new DtlsDataReceivedEventArgs(e.RemoteEndPoint, e.Connection, e.Data));
            Dtls12.ConnectionCreated += OnConnectionCreated;
            Dtls13.ConnectionCreated += OnConnectionCreated;

            serverTransport.OnDataReceived += OnDataReceived;
        }

        private DtlsServer(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        public IServerTransport ServerTransport { get; }

        /// <summary>The DTLS 1.0-1.2 engine.</summary>
        internal Dtls12Server Dtls12 => (Dtls12Server)Engine12;

        /// <summary>The DTLS 1.3 engine.</summary>
        internal Dtls13Server Dtls13 => (Dtls13Server)Engine13;

        /// <summary>The oldest version accepted; DTLS 1.2 by default (RFC 8996 deprecates DTLS 1.0).</summary>
        public ushort MinimumVersion { get => Dtls12.MinimumVersion; set => Dtls12.MinimumVersion = value; }

        /// <summary>The newest version offered: DTLS 1.3 (the default) or DTLS 1.2 to turn DTLS 1.3 off.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls13;

        // ── DTLS settings ────────────────────────────────────────────────────────────────────

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles
        {
            get => Dtls13.SrtpProtectionProfiles;
            set { Dtls12.SrtpProtectionProfiles = value; Dtls13.SrtpProtectionProfiles = value; }
        }

        /// <summary>Answer use_srtp with an empty MKI even when the client offered one (RFC 8827 §6.5: WebRTC uses no MKI).</summary>
        public bool SrtpDisableMki
        {
            get => Dtls13.SrtpDisableMki;
            set { Dtls12.SrtpDisableMki = value; Dtls13.SrtpDisableMki = value; }
        }

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1, RFC 9147 §5.8).</summary>
        public TimeSpan InitialRetransmitTimeout
        {
            get => Dtls13.InitialRetransmitTimeout;
            set { Dtls12.InitialRetransmitTimeout = value; Dtls13.InitialRetransmitTimeout = value; }
        }

        /// <summary>
        /// Negotiate connection IDs (RFC 9147 §9) with clients that offer them: their records are then routed by CID,
        /// so the association survives an address change.
        /// </summary>
        public bool UseConnectionIds
        {
            get => Dtls13.UseConnectionIds;
            set { Dtls12.UseConnectionIds = value; Dtls13.UseConnectionIds = value; }
        }

        /// <summary>Length of the CIDs this server issues.</summary>
        public int ConnectionIdLength
        {
            get => Dtls13.ConnectionIdLength;
            set { Dtls12.ConnectionIdLength = value; Dtls13.ConnectionIdLength = value; }
        }

        /// <summary>
        /// Send to a client's new address as soon as an authenticated, newer record arrives from it. Off by default:
        /// RFC 9147 §11 requires a reachability test first, so verify the pending address and call
        /// <see cref="TlsConnectionBase.ConfirmPeerAddress"/>.
        /// </summary>
        public bool AutoUpdatePeerAddress
        {
            get => Dtls13.AutoUpdatePeerAddress;
            set { Dtls12.AutoUpdatePeerAddress = value; Dtls13.AutoUpdatePeerAddress = value; }
        }

        /// <summary>
        /// Require a cookie round trip (HelloVerifyRequest, or a HelloRetryRequest for DTLS 1.3) before keeping any state
        /// for a client (RFC 6347 §4.2.1, RFC 9147 §5.1); on by default. Without it a spoofed source address can make the
        /// server send its first flight to a victim.
        /// </summary>
        public bool RequireCookie
        {
            get => Dtls13.ShouldSendHelloRetry;
            set { Dtls12.ShouldSendHelloVerify = value; Dtls13.ShouldSendHelloRetry = value; }
        }

        public event EventHandler<TlsConnectionBase> HandshakeFinished;
        public event EventHandler<DtlsDataReceivedEventArgs> ApplicationDataReceived;

        /// <summary>0-RTT data a DTLS 1.3 client sent with its ClientHello (see <see cref="TlsServerBase.MaxEarlyDataSize"/>).</summary>
        public event EventHandler<DtlsDataReceivedEventArgs> EarlyDataReceived;

        public event EventHandler<TlsConnectionBase> ConnectionClosed;
        public event EventHandler<TlsAlertEventArgs> AlertReceived;

        /// <summary>A connection was created for a new client, before its handshake runs (e.g. to watch it fail).</summary>
        public event EventHandler<TlsConnectionBase> ConnectionCreated;

        private void OnConnectionCreated(TlsConnectionBase connection)
        {
            connection.AlertReceived += (_, alert) => AlertReceived?.Invoke(this, new TlsAlertEventArgs(connection, alert));
            ConnectionCreated?.Invoke(this, connection);
        }

        public IReadOnlyCollection<TlsConnectionBase> Connections
            => Dtls12.Connections.Cast<TlsConnectionBase>().Concat(Dtls13.Connections).ToList();

        /// <summary>The connection with <paramref name="endpoint"/>: a <see cref="Tls12ServerConnection"/> or a <see cref="Tls13ServerConnection"/>.</summary>
        public TlsConnectionBase GetConnection(EndPoint endpoint)
            => (TlsConnectionBase)Dtls13.GetConnection(endpoint) ?? Dtls12.GetConnection(endpoint);

        public void SendApplicationData(EndPoint endpoint, byte[] data)
            => (GetConnection(endpoint) ?? throw new InvalidOperationException($"No DTLS connection for {endpoint}.")).SendApplicationData(data);

        public void Close(EndPoint endpoint) => GetConnection(endpoint)?.Close();

        /// <summary>
        /// Stateless address validation of a datagram from an unknown peer (RFC 6347 §4.2.1, RFC 9147 §5.1): true when it
        /// completes a ClientHello this server would start a handshake for (one with a valid cookie), otherwise the
        /// HelloVerifyRequest or HelloRetryRequest is sent and false returned. No connection is created, and the cookie is
        /// accepted by any server of this process, so the handshake can run on another instance.
        /// </summary>
        public bool VerifyClientHello(EndPoint endpoint, byte[] datagram)
        {
            if (datagram.Length == 0)
                return false;

            try
            {
                foreach (var record in DtlsRecordSplitter.Split(datagram))
                {
                    if (record.Length < 25 || record[0] != 0x16 || record[3] != 0 || record[4] != 0 || record[13] != HandshakeType.ClientHello)
                        continue; // only a ClientHello can start an association

                    if (_clientHelloReassembler.TryAdd(endpoint.ToString(), record, out byte[] complete))
                    {
                        bool dtls13 = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13)
                                      && TlsServer.OffersVersion(complete.AsSpan(13).ToArray(), DtlsVersion.Dtls13, datagram: true);
                        return dtls13 ? Dtls13.VerifyClientHello(endpoint, complete) : Dtls12.CheckCookie(endpoint, complete, out _, out _, out _);
                    }
                }
            }
            catch (Exception ex)
            {
                // Malformed datagrams from unknown peers are dropped silently.
                Debug.WriteLine($"[DTLS Server] Dropped datagram from {endpoint}: {ex.Message}");
            }
            return false;
        }

        // ── Routing ──────────────────────────────────────────────────────────────────────────

        private void OnDataReceived(object sender, byte[] datagram)
        {
            var endpoint = (EndPoint)sender;
            if (datagram.Length == 0)
                return;

            // A known client stays with its engine; CID records (a client that moved) go by their header format.
            if (Dtls13.GetConnection(endpoint) != null || (datagram[0] & 0xE0) == 0x20)
            {
                _port13.Deliver(endpoint, datagram);
                return;
            }
            if (Dtls12.GetConnection(endpoint) != null || datagram[0] == 25)
            {
                _port12.Deliver(endpoint, datagram);
                return;
            }

            try
            {
                foreach (var record in DtlsRecordSplitter.Split(datagram))
                {
                    if (record.Length < 25 || record[0] != 0x16 || record[3] != 0 || record[4] != 0 || record[13] != HandshakeType.ClientHello)
                        continue; // only a ClientHello can start an association

                    // A ClientHello larger than the path MTU arrives fragmented: the engine gets it whole.
                    if (_clientHelloReassembler.TryAdd(endpoint.ToString(), record, out byte[] complete))
                    {
                        bool dtls13 = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13)
                                      && TlsServer.OffersVersion(complete.AsSpan(13).ToArray(), DtlsVersion.Dtls13, datagram: true);
                        if (dtls13)
                        {
                            _port13.Deliver(endpoint, complete);
                        }
                        else
                        {
                            Dtls12.SignalTls13Downgrade = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13);
                            _port12.Deliver(endpoint, complete);
                        }
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                // Malformed datagrams from unknown peers are dropped silently.
                Debug.WriteLine($"[DTLS Server] Dropped datagram from {endpoint}: {ex.Message}");
            }
        }

        /// <summary>One engine's view of the transport: the datagrams routed to it, and sending through the real one.</summary>
        private sealed class EnginePort : IServerTransport
        {
            private readonly IServerTransport _transport;

            public EnginePort(IServerTransport transport) => _transport = transport;

            public event EventHandler<byte[]> OnDataReceived;

            public void Send(EndPoint endpoint, byte[] buf) => _transport.Send(endpoint, buf);

            public void Deliver(EndPoint from, byte[] datagram) => OnDataReceived?.Invoke(from, datagram);
        }
    }
}
