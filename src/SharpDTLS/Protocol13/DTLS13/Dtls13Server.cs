using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol13.Messages;
using SharpDTLS.UDP;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS.Protocol13.DTLS13
{
    public class Dtls13ConnectionEventArgs : EventArgs
    {
        public Dtls13ConnectionEventArgs(EndPoint remoteEndPoint, Tls13ServerConnection connection)
        {
            RemoteEndPoint = remoteEndPoint;
            Connection = connection;
        }

        public EndPoint RemoteEndPoint { get; }
        public Tls13ServerConnection Connection { get; }
    }

    public class Dtls13DataReceivedEventArgs : Dtls13ConnectionEventArgs
    {
        public Dtls13DataReceivedEventArgs(EndPoint remoteEndPoint, Tls13ServerConnection connection, byte[] data)
            : base(remoteEndPoint, connection)
        {
            Data = data;
        }

        public byte[] Data { get; }
    }

    /// <summary>
    /// DTLS 1.3 server. Answers new clients statelessly (HelloRetryRequest with cookie) and keeps
    /// one <see cref="Tls13ServerConnection"/> per remote endpoint once the cookie has been verified.
    /// </summary>
    public class Dtls13Server : Tls13ServerBase
    {
        private readonly ConcurrentDictionary<string, Tls13ServerConnection> _connections = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        public IServerTransport ServerTransport { get; }

        /// <summary>Send a HelloRetryRequest with a cookie before allocating state (address validation, RFC 9147 §5.1).</summary>
        public bool ShouldSendHelloRetry { get; set; } = true;

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0007, 0x0001 };

        /// <summary>Answer use_srtp with an empty MKI even when the client offered one (RFC 8827 §6.5: WebRTC uses no MKI).</summary>
        public bool SrtpDisableMki { get; set; }

        /// <summary>
        /// Negotiate connection IDs (RFC 9147 §9) with clients that offer them: their records are then routed by CID,
        /// so the association survives an address change.
        /// </summary>
        public bool UseConnectionIds { get; set; }

        /// <summary>Length of the CIDs this server issues.</summary>
        public int ConnectionIdLength { get; set; } = 8;

        /// <summary>
        /// Send to a client's new address as soon as an authenticated, newer record arrives from it. Off by default:
        /// RFC 9147 §11 requires a reachability test first, so verify the pending address and call ConfirmPeerAddress.
        /// </summary>
        public bool AutoUpdatePeerAddress { get; set; }

        private readonly ConcurrentDictionary<string, Tls13ServerConnection> _connectionsById = new();

        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>0-RTT data accepted before the handshake completes; it may be a replay.</summary>
        public event EventHandler<Dtls13DataReceivedEventArgs> EarlyDataReceived;

        internal override void OnEarlyData(Tls13ServerConnection connection, byte[] data)
            => EarlyDataReceived?.Invoke(this, new Dtls13DataReceivedEventArgs(connection.RemoteEndPoint, connection, data));

        public event EventHandler<EventArgs> HandshakeFinished;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;
        public event EventHandler<Dtls13DataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<Dtls13ConnectionEventArgs> ConnectionClosed;

        public Dtls13Server(IServerTransport serverTransport)
            : this(serverTransport, Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        /// <param name="keyPair">The certificate key, or null with <paramref name="certificate"/> for a PSK-only server.</param>
        public Dtls13Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(keyPair, certificate)
        {
            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        private Dtls13Server(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        public IReadOnlyCollection<Tls13ServerConnection> Connections => _connections.Values.ToList();

        public Tls13ServerConnection GetConnection(EndPoint endpoint)
            => _connections.TryGetValue(endpoint.ToString(), out var connection) ? connection : null;

        public void SendApplicationData(EndPoint endpoint, byte[] data)
            => RequireConnection(endpoint).SendApplicationData(data);

        public void SendKeyUpdate(EndPoint endpoint, bool requestUpdate = false)
            => RequireConnection(endpoint).SendKeyUpdate(requestUpdate);

        public void Close(EndPoint endpoint)
            => GetConnection(endpoint)?.Close();

        private Tls13ServerConnection RequireConnection(EndPoint endpoint)
            => GetConnection(endpoint) ?? throw new InvalidOperationException($"No DTLS connection for {endpoint}.");

        private void ServerTransport_OnDataReceived(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;

            // A unified header with the C bit names its connection, whatever address it comes from.
            if (UseConnectionIds && data.Length > 1 + ConnectionIdLength && (data[0] & 0xF0) == 0x30
                && _connectionsById.TryGetValue(Convert.ToHexString(data, 1, ConnectionIdLength), out var byId))
            {
                byId.ProcessDatagram(data, endpoint);
                return;
            }

            if (_connections.TryGetValue(endpoint.ToString(), out var connection))
            {
                connection.ProcessDatagram(data, endpoint);
                return;
            }

            try
            {
                HandleNewClient(endpoint, data);
            }
            catch (DtlsException ex)
            {
                Debug.WriteLine($"[DTLS13 Server] Rejected ClientHello from {endpoint}: {ex.Message}");
                SendPlaintextAlert(endpoint, ex.Alert);
            }
            catch (Exception ex)
            {
                // Malformed datagrams from unknown peers are dropped silently.
                Debug.WriteLine($"[DTLS13 Server] Dropped datagram from {endpoint}: {ex.Message}");
            }
        }

        // ── Stateless ClientHello processing ─────────────────────────────────────────────────

        private void HandleNewClient(EndPoint endpoint, byte[] datagram)
        {
            foreach (var fragment in DtlsRecordSplitter.Split(datagram))
            {
                if (fragment.Length < 25 || fragment[0] != 0x16 || fragment[13] != 0x01)
                    continue; // only a ClientHello can start an association

                // A ClientHello larger than the path MTU arrives fragmented.
                if (_clientHelloReassembler.TryAdd(endpoint.ToString(), fragment, out byte[] record))
                {
                    HandleClientHello(endpoint, datagram, record);
                    return;
                }
            }
        }

        private void HandleClientHello(EndPoint endpoint, byte[] datagram, byte[] record)
        {
            if (!CheckCookie(endpoint, record, out ClientHelloDatagram clientHello, out ClientHelloDecision decision))
                return;

            var connection = new Tls13ServerConnection(this, endpoint);
            if (!_connections.TryAdd(endpoint.ToString(), connection))
            {
                _connections[endpoint.ToString()].ProcessDatagram(datagram);
                return;
            }

            connection.Start(record, clientHello, Dtls13CipherSuite.Get(decision.SuiteId), decision.Retry, decision.ShareGroup);
            if (connection.ConnectionId != null && !connection.IsClosed)
                _connectionsById[Convert.ToHexString(connection.ConnectionId)] = connection;
        }

        /// <summary>
        /// The stateless cookie exchange (RFC 9147 §5.1) for a whole ClientHello record: true when the handshake can start
        /// (a valid cookie, or no HelloRetryRequest needed), otherwise a HelloRetryRequest is sent. Creates no connection.
        /// </summary>
        internal bool CheckCookie(EndPoint endpoint, byte[] record, out ClientHelloDatagram clientHello, out ClientHelloDecision decision)
        {
            clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(record);

            decision = DecideClientHello(clientHello, record, endpoint, ShouldSendHelloRetry);
            if (decision.HelloRetryRequest == null)
                return true;

            // RFC 9147 §5.1: reuse the ClientHello's message and record sequence numbers, so a stateless server never repeats one.
            decision.HelloRetryRequest.SequenceNumber = clientHello.SequenceNumber;
            decision.HelloRetryRequest.RecordSequenceNumber = clientHello.RecordSequenceNumber;
            Debug.WriteLine($"[DTLS13 Server] Sending HelloRetryRequest to {endpoint}");
            ServerTransport.Send(endpoint, decision.HelloRetryRequest.ToBytes());
            return false;
        }

        /// <summary><see cref="CheckCookie"/>, answering a ClientHello the server rejects with an alert as the handshake would.</summary>
        internal bool VerifyClientHello(EndPoint endpoint, byte[] record)
        {
            try
            {
                return CheckCookie(endpoint, record, out _, out _);
            }
            catch (DtlsException ex)
            {
                Debug.WriteLine($"[DTLS13 Server] Rejected ClientHello from {endpoint}: {ex.Message}");
                SendPlaintextAlert(endpoint, ex.Alert);
                return false;
            }
        }

        internal void RegisterConnectionId(Tls13ServerConnection connection, byte[] connectionId)
            => _connectionsById[Convert.ToHexString(connectionId)] = connection;

        internal void OnPeerAddressConfirmed(Tls13ServerConnection connection, EndPoint old)
        {
            _connections.TryRemove(new KeyValuePair<string, Tls13ServerConnection>(old.ToString(), connection));
            _connections[connection.RemoteEndPoint.ToString()] = connection;
        }

        private void SendPlaintextAlert(EndPoint endpoint, AlertDescription alert)
        {
            byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, (byte)alert };
            try { ServerTransport.Send(endpoint, record); }
            catch (Exception ex) { Debug.WriteLine($"[DTLS13 Server] Failed to send alert: {ex.Message}"); }
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal override void OnConnectionEstablished(Tls13ServerConnection connection)
            => HandshakeFinished?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));

        internal override void OnApplicationData(Tls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls13DataReceivedEventArgs(connection.RemoteEndPoint, connection, data));

        internal override void OnKeyUpdate(KeyUpdateDatagram keyUpdate)
            => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal override void OnConnectionClosed(Tls13ServerConnection connection)
        {
            _connections.TryRemove(new KeyValuePair<string, Tls13ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
            foreach (var entry in _connectionsById.Where(e => e.Value == connection).ToList())
                _connectionsById.TryRemove(entry);
            ConnectionClosed?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));
        }
    }
}
