using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS.DTLS13
{
    public class Dtls13ConnectionEventArgs : EventArgs
    {
        public Dtls13ConnectionEventArgs(EndPoint remoteEndPoint, Dtls13ServerConnection connection)
        {
            RemoteEndPoint = remoteEndPoint;
            Connection = connection;
        }

        public EndPoint RemoteEndPoint { get; }
        public Dtls13ServerConnection Connection { get; }
    }

    public class Dtls13DataReceivedEventArgs : Dtls13ConnectionEventArgs
    {
        public Dtls13DataReceivedEventArgs(EndPoint remoteEndPoint, Dtls13ServerConnection connection, byte[] data)
            : base(remoteEndPoint, connection)
        {
            Data = data;
        }

        public byte[] Data { get; }
    }

    /// <summary>
    /// DTLS 1.3 server. Answers new clients statelessly (HelloRetryRequest with cookie) and keeps
    /// one <see cref="Dtls13ServerConnection"/> per remote endpoint once the cookie has been verified.
    /// </summary>
    public class Dtls13Server
    {
        private readonly ConcurrentDictionary<string, Dtls13ServerConnection> _connections = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        internal AsymmetricCipherKeyPair ServerKeyPair { get; }
        internal X509Certificate ServerCertificate { get; }

        public IServerTransport ServerTransport { get; }

        /// <summary>Send a HelloRetryRequest with a cookie before allocating state (address validation, RFC 9147 §5.1).</summary>
        public bool ShouldSendHelloRetry { get; set; } = true;

        /// <summary>Request a client certificate and abort with certificate_required if none is sent.</summary>
        public bool RequireClientCertificate { get; set; } = false;

        /// <summary>Cipher suites in server preference order: the defaults in <see cref="Dtls13CipherSuite.Supported"/>, or any of <see cref="Dtls13CipherSuite.All"/>.</summary>
        public IList<ushort> CipherSuites { get; set; } = new List<ushort>(Dtls13CipherSuite.Supported);

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0007, 0x0001 };

        /// <summary>Intermediate CA certificates sent after the server certificate, issuer of the previous one first.</summary>
        public IList<X509Certificate> IntermediateCertificates { get; set; }

        /// <summary>
        /// Chooses the credentials for the client's server_name (RFC 6066), which is null when the client sent none.
        /// Returning null uses the default certificate.
        /// </summary>
        public Func<string, ServerCredentials> CertificateSelector { get; set; }

        /// <summary>Application protocols (ALPN, RFC 7301) in server preference order; null to ignore ALPN.</summary>
        public IList<string> ApplicationProtocols { get; set; }

        /// <summary>
        /// The most payload per record we accept (64 to 16384), sent in record_size_limit (RFC 8449) to clients that
        /// offer it; null for 16384. Clients' limits (and max_fragment_length requests) are always honoured.
        /// </summary>
        public int? RecordSizeLimit { get; set; }

        /// <summary>
        /// Key exchange groups in server preference order (see <see cref="Dtls13Groups"/>). A group the client already
        /// sent a share for is preferred, to avoid a HelloRetryRequest; otherwise the server asks for its best group.
        /// </summary>
        public IList<ushort> SupportedGroups { get; set; } = new List<ushort>(Dtls13Groups.DefaultPreference);

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

        private readonly ConcurrentDictionary<string, Dtls13ServerConnection> _connectionsById = new();

        /// <summary>Optional client certificate validation. Return false to abort with bad_certificate.</summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator { get; set; }

        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format).</summary>
        public Action<string> KeyLogWriter { get; set; }

        /// <summary>
        /// Keys for session tickets (random per server by default): after each full or resumed handshake a client
        /// that offers psk_dhe_ke gets a ticket it can resume with. Null disables tickets and resumption.
        /// </summary>
        public SessionTicketKeys TicketKeys { get; set; } = new SessionTicketKeys();

        /// <summary>Maps a client's PSK identity to its external PSK (null for unknown identities); enables external PSKs.</summary>
        public Func<byte[], Dtls13ExternalPsk> ExternalPskResolver { get; set; }

        /// <summary>
        /// Accept psk_ke, PSK handshakes without (EC)DHE (RFC 8446 §4.2.9), when the client offers it. Off by default:
        /// such handshakes have no forward secrecy. psk_dhe_ke is preferred when the client offers both.
        /// </summary>
        public bool AllowPskOnlyKeyExchange { get; set; }

        /// <summary>
        /// Maximum 0-RTT data per connection advertised in tickets (RFC 8446 §4.2.10); 0 (the default) disables early
        /// data. Early data can be replayed by an attacker, so only enable it for idempotent requests. It is accepted
        /// only without a HelloRetryRequest (set <see cref="ShouldSendHelloRetry"/> to false), for a fresh ticket
        /// (<see cref="EarlyDataFreshnessWindow"/>) whose ClientHello has not been seen before.
        /// </summary>
        public uint MaxEarlyDataSize { get; set; }

        /// <summary>
        /// Anti-replay window (RFC 8446 §8.2): early data is accepted only when the client's ticket age is within this
        /// of the server's view, and each ClientHello is remembered for this long.
        /// </summary>
        public TimeSpan EarlyDataFreshnessWindow { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>0-RTT data accepted before the handshake completes; it may be a replay.</summary>
        public event EventHandler<Dtls13DataReceivedEventArgs> EarlyDataReceived;

        private readonly ConcurrentDictionary<string, DateTime> _seenEarlyDataClientHellos = new();

        /// <summary>
        /// RFC 8446 §8.2 ClientHello recording: remembers the binder of each 0-RTT ClientHello for the freshness
        /// window and refuses a second one. Older entries are outside the window and are pruned.
        /// </summary>
        internal bool RecordEarlyDataClientHello(byte[] binder)
        {
            var now = DateTime.UtcNow;
            foreach (var entry in _seenEarlyDataClientHellos)
                if (now - entry.Value > EarlyDataFreshnessWindow)
                    _seenEarlyDataClientHellos.TryRemove(entry);
            return _seenEarlyDataClientHellos.TryAdd(Convert.ToHexString(binder), now);
        }

        internal void OnEarlyData(Dtls13ServerConnection connection, byte[] data)
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
        {
            if ((keyPair == null) != (certificate == null))
                throw new ArgumentException("Pass both a key pair and a certificate, or neither (PSK-only server).");
            ServerKeyPair = keyPair;
            ServerCertificate = certificate;

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        private Dtls13Server(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        public IReadOnlyCollection<Dtls13ServerConnection> Connections => _connections.Values.ToList();

        public Dtls13ServerConnection GetConnection(EndPoint endpoint)
            => _connections.TryGetValue(endpoint.ToString(), out var connection) ? connection : null;

        public void SendApplicationData(EndPoint endpoint, byte[] data)
            => RequireConnection(endpoint).SendApplicationData(data);

        public void SendKeyUpdate(EndPoint endpoint, bool requestUpdate = false)
            => RequireConnection(endpoint).SendKeyUpdate(requestUpdate);

        public void Close(EndPoint endpoint)
            => GetConnection(endpoint)?.Close();

        private Dtls13ServerConnection RequireConnection(EndPoint endpoint)
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

            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(record);

            var versions = clientHello.Extensions.OfType<ClientSupportedVersions>().FirstOrDefault();
            if (versions == null || !versions.Versions.Contains(ClientSupportedVersions.Dtls13))
                throw new DtlsException(AlertDescription.ProtocolVersion, "Client does not support DTLS 1.3.");
            if (clientHello.LegacyCookie.Length != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "DTLS 1.3 ClientHello has a legacy_cookie.");

            // A psk_ke-only client sends no key share or groups; whether its PSK is acceptable is checked later.
            var modes = clientHello.Extensions.OfType<PskKeyExchangeModesExtension>().FirstOrDefault();
            bool pskOnly = AllowPskOnlyKeyExchange && clientHello.Extensions.OfType<ClientPreSharedKeyExtension>().Any()
                           && modes != null && modes.Modes.Contains(PskKeyExchangeModesExtension.PskKe)
                           && !modes.Modes.Contains(PskKeyExchangeModesExtension.PskDheKe);
            // Group: the server's most preferred one the client sent a share for, else its most preferred mutual
            // group, requested with a HelloRetryRequest (RFC 8446 §4.2.8).
            var offeredGroups = clientHello.Extensions.OfType<SupportedGroups>().FirstOrDefault()?.Groups ?? Array.Empty<ushort>();
            var shares = clientHello.Extensions.OfType<ClientKeyShareExtension>().FirstOrDefault();
            var mutual = SupportedGroups.Where(g => offeredGroups.Contains(g) && Dtls13Groups.IsSupported(g)).ToList();
            ushort shareGroup = mutual.FirstOrDefault(g => shares?.GetKeyShare(g) != null);
            if (!pskOnly && mutual.Count == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No supported key exchange group in common.");

            ushort suiteId = CipherSuites.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (suiteId == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common.");

            bool hasKeyShare = shareGroup != 0;
            var ipEndpoint = (IPEndPoint)endpoint;
            string ip = ipEndpoint.Address.ToString();

            HelloRetryState retry = null;
            var cookie = clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault();
            if (cookie != null && Dtls13CryptoUtils.ValidateCookie(DateTime.UtcNow, ip, ipEndpoint.Port, cookie.Cookie,
                    out ushort cookieSuite, out byte[] clientHello1Hash, out ushort requestedGroup))
            {
                if (!clientHello.CipherSuites.Contains(cookieSuite) || !CipherSuites.Contains(cookieSuite))
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 does not offer the cipher suite selected in HelloRetryRequest.");
                // ClientHello2 must carry a share for the group the HelloRetryRequest asked for (RFC 8446 §4.1.2).
                if (requestedGroup != 0)
                {
                    if (shares?.GetKeyShare(requestedGroup) == null)
                        throw new DtlsException(AlertDescription.IllegalParameter, $"ClientHello2 has no {Dtls13Groups.Name(requestedGroup)} key share.");
                    shareGroup = requestedGroup;
                }
                else if (!hasKeyShare && !pskOnly)
                {
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 has no usable key share.");
                }

                suiteId = cookieSuite;
                retry = new HelloRetryState(clientHello1Hash, cookie.Cookie, requestedGroup);
            }
            else if (ShouldSendHelloRetry || (!hasKeyShare && !pskOnly))
            {
                SendHelloRetryRequest(endpoint, record, clientHello, suiteId, requestedGroup: !hasKeyShare && !pskOnly ? mutual[0] : (ushort)0);
                return;
            }

            var connection = new Dtls13ServerConnection(this, endpoint);
            if (!_connections.TryAdd(endpoint.ToString(), connection))
            {
                _connections[endpoint.ToString()].ProcessDatagram(datagram);
                return;
            }

            connection.Start(record, clientHello, Dtls13CipherSuite.Get(suiteId), retry, shareGroup);
            if (connection.ConnectionId != null && !connection.IsClosed)
                _connectionsById[Convert.ToHexString(connection.ConnectionId)] = connection;
        }

        internal void RegisterConnectionId(Dtls13ServerConnection connection, byte[] connectionId)
            => _connectionsById[Convert.ToHexString(connectionId)] = connection;

        internal void OnPeerAddressConfirmed(Dtls13ServerConnection connection, EndPoint old)
        {
            _connections.TryRemove(new KeyValuePair<string, Dtls13ServerConnection>(old.ToString(), connection));
            _connections[connection.RemoteEndPoint.ToString()] = connection;
        }

        private void SendHelloRetryRequest(EndPoint endpoint, byte[] record, ClientHelloDatagram clientHello, ushort suiteId, ushort requestedGroup)
        {
            var suite = Dtls13CipherSuite.Get(suiteId);
            var transcript = new Dtls13Transcript();
            transcript.AddPlaintextRecord(record);

            var ipEndpoint = (IPEndPoint)endpoint;
            byte[] cookie = Dtls13CryptoUtils.CreateCookie(DateTime.UtcNow, ipEndpoint.Address.ToString(), ipEndpoint.Port,
                suiteId, transcript.Hash(suite), requestedGroup);

            // RFC 9147 §5: DTLS servers never echo legacy_session_id.
            var hrr = new HelloRetryRequest(suiteId, cookie, requestedGroup != 0 ? requestedGroup : null, Array.Empty<byte>())
            {
                SequenceNumber = clientHello.SequenceNumber,
                // RFC 9147 §5.1: reuse the ClientHello's record sequence number so a stateless server never repeats one.
                RecordSequenceNumber = clientHello.RecordSequenceNumber,
            };

            Debug.WriteLine($"[DTLS13 Server] Sending HelloRetryRequest to {endpoint}");
            ServerTransport.Send(endpoint, hrr.ToBytes());
        }

        private void SendPlaintextAlert(EndPoint endpoint, AlertDescription alert)
        {
            byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, (byte)alert };
            try { ServerTransport.Send(endpoint, record); }
            catch (Exception ex) { Debug.WriteLine($"[DTLS13 Server] Failed to send alert: {ex.Message}"); }
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal void OnConnectionEstablished(Dtls13ServerConnection connection)
            => HandshakeFinished?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));

        internal void OnApplicationData(Dtls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls13DataReceivedEventArgs(connection.RemoteEndPoint, connection, data));

        internal void OnKeyUpdate(KeyUpdateDatagram keyUpdate)
            => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal void OnConnectionClosed(Dtls13ServerConnection connection)
        {
            _connections.TryRemove(new KeyValuePair<string, Dtls13ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
            foreach (var entry in _connectionsById.Where(e => e.Value == connection).ToList())
                _connectionsById.TryRemove(entry);
            ConnectionClosed?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));
        }

        internal sealed class HelloRetryState
        {
            public HelloRetryState(byte[] clientHello1Hash, byte[] cookie, ushort requestedGroup)
            {
                ClientHello1Hash = clientHello1Hash;
                Cookie = cookie;
                RequestedGroup = requestedGroup;
            }

            public byte[] ClientHello1Hash { get; }
            public byte[] Cookie { get; }
            public ushort RequestedGroup { get; }
        }
    }

    /// <summary>
    /// Server side of one DTLS 1.3 association.
    /// </summary>
    public class Dtls13ServerConnection : Dtls13Connection
    {
        private enum State
        {
            Start,
            WaitClientCertificate,
            WaitClientCertificateVerify,
            WaitClientFinished,
            Connected,
        }

        private readonly Dtls13Server _server;
        private State _state = State.Start;
        private ClientHelloDatagram _clientHello;
        private CertificateRequestDatagram _certificateRequest;
        private X509Certificate _clientCertificate;
        private byte[] _psk;
        private int _pskIdentity;
        private ushort _group;

        /// <summary>The negotiated key exchange group, or 0 (psk_ke).</summary>
        public ushort NegotiatedGroup { get; private set; }
        private bool _pskOnly;
        private bool _helloRetried;
        private Dtls13TicketState _ticketState;
        private Dtls13CryptoContext _earlyKeys;
        private AsymmetricCipherKeyPair _keyPair;
        private X509Certificate _certificate;
        private IList<X509Certificate> _intermediates;
        private bool _serverNameUsed;
        private ITlsExtension _recordSizeResponse;
        private long _earlyDataReceived;
        private bool _earlyDataAccepted;

        private readonly PeerAddressTracker _address;

        /// <summary>Where this connection sends: the client's address, which can move with connection IDs.</summary>
        public EndPoint RemoteEndPoint => _address.Current;

        /// <summary>A newer client address awaiting <see cref="ConfirmPeerAddress"/> (when not following automatically).</summary>
        public EndPoint PendingPeerAddress => _address.Pending;

        /// <summary>
        /// The client appeared at a new address: a record carrying our CID authenticated, was newer than any before
        /// and came from elsewhere. Unless the server follows automatically, verify the address (RFC 9147 §11) and
        /// call <see cref="ConfirmPeerAddress"/>.
        /// </summary>
        public event EventHandler<(EndPoint Old, EndPoint New)> PeerAddressChanged;

        /// <summary>Sends to <paramref name="address"/> from now on, after the application has checked it can be reached.</summary>
        public void ConfirmPeerAddress(EndPoint address) => Locked(() =>
        {
            var old = _address.Current;
            _address.Confirm(address);
            if (!old.Equals(address))
                RaiseEvent(() => _server.OnPeerAddressConfirmed(this, old));
        });

        protected override void OnConnectionIdIssued(byte[] connectionId) => _server.RegisterConnectionId(this, connectionId);

        protected override void OnRecordAuthenticated(ulong epoch, ulong sequenceNumber, bool withConnectionId)
        {
            if (!_address.Observe(epoch, sequenceNumber, withConnectionId, DatagramSource, _server.AutoUpdatePeerAddress, out var old))
                return;
            var change = (old, DatagramSource);
            RaiseEvent(() => PeerAddressChanged?.Invoke(this, change));
            if (_server.AutoUpdatePeerAddress)
                RaiseEvent(() => _server.OnPeerAddressConfirmed(this, old));
        }

        /// <summary>The host name the client asked for in server_name, or null.</summary>
        public string ServerName { get; private set; }

        /// <summary>Whether the client resumed with a ticket (PSK handshake).</summary>
        public bool IsResumed => _psk != null && ExternalPskIdentity == null;

        /// <summary>Whether the handshake was authenticated with an external PSK.</summary>
        public bool IsExternalPsk => ExternalPskIdentity != null;

        /// <summary>The identity of the external PSK the client authenticated with, or null.</summary>
        public byte[] ExternalPskIdentity { get; private set; }

        /// <summary>Whether the handshake used psk_ke (no (EC)DHE, no forward secrecy).</summary>
        public bool IsPskOnlyKeyExchange => _pskOnly;

        /// <summary>Whether the client's 0-RTT data was accepted.</summary>
        public bool EarlyDataAccepted => _earlyDataAccepted;

        /// <summary>The client's certificate, when one was sent.</summary>
        public X509Certificate ClientCertificate => _clientCertificate;

        internal Dtls13ServerConnection(Dtls13Server server, EndPoint remoteEndPoint)
            : this(server, new PeerAddressTracker(remoteEndPoint))
        {
        }

        // Replies go to the tracked address, which moves with connection IDs.
        private Dtls13ServerConnection(Dtls13Server server, PeerAddressTracker address)
            : base(isClient: false, send: data => server.ServerTransport.Send(address.Current, data))
        {
            _server = server;
            _address = address;
            InitialRetransmitTimeout = server.InitialRetransmitTimeout;
            KeyLogWriter = server.KeyLogWriter;

            ApplicationDataReceived += (_, data) => _server.OnApplicationData(this, data);
            KeyUpdateReceived += (_, keyUpdate) => _server.OnKeyUpdate(keyUpdate);
            Closed += (_, _) => _server.OnConnectionClosed(this);
        }

        internal void Start(byte[] record, ClientHelloDatagram clientHello, Dtls13CipherSuite suite, Dtls13Server.HelloRetryState retry, ushort group)
        {
            Run(() =>
            {
                _clientHello = clientHello;
                _group = group;
                Session.CipherSuite = suite;

                if (retry != null)
                {
                    // Rebuild the transcript the client has: message_hash(ClientHello1) || HelloRetryRequest || ClientHello2.
                    // The HelloRetryRequest is deterministic given the cookie, so it can be recreated byte for byte.
                    var hrr = new HelloRetryRequest(suite.Id, retry.Cookie, retry.RequestedGroup != 0 ? retry.RequestedGroup : null, Array.Empty<byte>());
                    Session.Transcript.AddMessageHash(retry.ClientHello1Hash);
                    Session.Transcript.AddPlaintextRecord(hrr.ToBytes());
                }
                _helloRetried = retry != null;
                ServerName = _clientHello.Extensions.OfType<ServerNameExtension>().FirstOrDefault()?.HostName;
                var selected = _server.CertificateSelector?.Invoke(ServerName);
                _serverNameUsed = selected != null && ServerName != null;
                (_keyPair, _certificate, _intermediates) = selected != null
                    ? (selected.KeyPair, selected.Certificate, selected.IntermediateCertificates)
                    : (_server.ServerKeyPair, _server.ServerCertificate, _server.IntermediateCertificates);

                ApplicationProtocol = AlpnExtension.Select(_server.ApplicationProtocols, _clientHello.Extensions.OfType<AlpnExtension>().FirstOrDefault());

                // Record size limits apply to everything we send from the ServerHello on (0-RTT data is exempt).
                RecordSizeNegotiation.Validate(_server.RecordSizeLimit, null);
                (PeerRecordLimit, ReceiveRecordLimit, _recordSizeResponse) = RecordSizeNegotiation.Accept(
                    _clientHello.Extensions.OfType<RecordSizeLimitExtension>().FirstOrDefault(),
                    _clientHello.Extensions.OfType<MaxFragmentLengthExtension>().FirstOrDefault(), _server.RecordSizeLimit, dtls13: true);

                var offeredCid = _clientHello.Extensions.OfType<ConnectionIdExtension>().FirstOrDefault();
                if (_server.UseConnectionIds && offeredCid != null)
                {
                    WriteConnectionId = offeredCid.ConnectionId;
                    ReadConnectionId = Dtls13CryptoUtils.GenerateRandom(_server.ConnectionIdLength);
                }

                SelectPsk(record);
                if (_psk == null && (_group == 0 || _certificate == null))
                    throw new DtlsException(AlertDescription.HandshakeFailure,
                        _certificate == null ? "PSK-only server and no acceptable PSK." : "No key share and no acceptable PSK.");
                Session.Transcript.AddPlaintextRecord(record);

                // 0-RTT keys come from the ClientHello alone (RFC 8446 §7.1).
                if (AcceptEarlyData())
                {
                    _earlyKeys = Dtls13CryptoUtils.CalculateEarlyKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), _psk, suite);
                    AddReadKeys(_earlyKeys);
                    _earlyDataAccepted = true;
                }

                // Message sequence numbers continue after the stateless HelloRetryRequest (RFC 9147 §5.2).
                NextReceiveMessageSeq = clientHello.SequenceNumber + 1;
                NextSendMessageSeq = clientHello.SequenceNumber;
                SetPlaintextRecordSequence(clientHello.RecordSequenceNumber);

                SendServerFlight();
            });
        }

        /// <summary>
        /// Accepts the first offered PSK — a ticket we can open, or an external PSK the resolver knows — whose hash
        /// is the selected suite's, after checking its binder (RFC 8446 §4.2.11). Unknown identities fall back to a
        /// full handshake; a wrong binder aborts. psk_dhe_ke is used when the client offers it with a key share,
        /// psk_ke only when allowed and offered.
        /// </summary>
        private void SelectPsk(byte[] record)
        {
            var offered = _clientHello.Extensions.OfType<ClientPreSharedKeyExtension>().FirstOrDefault();
            if (offered == null)
                return;
            if (_clientHello.Extensions[^1] != offered)
                throw new DtlsException(AlertDescription.IllegalParameter, "pre_shared_key is not the last extension.");

            var modes = _clientHello.Extensions.OfType<PskKeyExchangeModesExtension>().FirstOrDefault();
            if (modes == null)
                throw new DtlsException(AlertDescription.MissingExtension, "pre_shared_key without psk_key_exchange_modes.");
            bool dhe = modes.Modes.Contains(PskKeyExchangeModesExtension.PskDheKe) && _group != 0;
            bool pskOnly = !dhe && _server.AllowPskOnlyKeyExchange && modes.Modes.Contains(PskKeyExchangeModesExtension.PskKe);
            if (!dhe && !pskOnly)
                return;

            var suite = Session.CipherSuite;
            for (int i = 0; i < offered.Identities.Count; i++)
            {
                byte[] identity = offered.Identities[i].Identity;
                byte[] psk;
                byte[] clientCertificate = null;
                bool external = false;

                var state = _server.TicketKeys != null ? Dtls13TicketState.Open(_server.TicketKeys, identity) : null;
                if (state != null)
                {
                    // RFC 8446 §4.6.1 / RFC 6066 §3: a ticket is only good for the server name it was issued under.
                    if (Dtls13CipherSuite.Get(state.CipherSuite).HashAlgorithm != suite.HashAlgorithm
                        || (_server.RequireClientCertificate && state.ClientCertificate == null)
                        || !string.Equals(state.ServerName, ServerName, StringComparison.OrdinalIgnoreCase))
                        continue;
                    psk = state.Psk;
                    clientCertificate = state.ClientCertificate;
                }
                else
                {
                    // An external PSK cannot authenticate a client certificate.
                    var externalPsk = _server.RequireClientCertificate ? null : _server.ExternalPskResolver?.Invoke(identity);
                    if (externalPsk == null || Dtls13CipherSuite.Get(externalPsk.CipherSuite).HashAlgorithm != suite.HashAlgorithm)
                        continue;
                    psk = externalPsk.Key;
                    external = true;
                }

                byte[] truncated = PskBinders.TruncatedClientHello(record, offered.BindersLength);
                byte[] expected = Dtls13CryptoUtils.CalculateBinder(psk, Session.Transcript.HashWith(suite, truncated), suite, external);
                if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, offered.Binders[i]))
                    throw new DtlsException(AlertDescription.DecryptError, "PSK binder verification failed.");

                _psk = psk;
                _pskIdentity = i;
                _pskOnly = pskOnly;
                _ticketState = state;
                if (external)
                    ExternalPskIdentity = identity;
                if (clientCertificate != null)
                {
                    _clientCertificate = new X509CertificateParser().ReadCertificate(clientCertificate);
                    Session.ClientCertificateBytes = clientCertificate;
                    Session.PeerCertificate = clientCertificate;
                }
                return;
            }
        }

        /// <summary>
        /// RFC 8446 §4.2.10: early data needs the first identity to be a ticket that allows it, the ticket's suite and
        /// no HelloRetryRequest; §8 adds the freshness check and ClientHello recording against replays.
        /// </summary>
        private bool AcceptEarlyData()
        {
            var offered = _clientHello.Extensions.OfType<ClientPreSharedKeyExtension>().FirstOrDefault();
            if (!_clientHello.Extensions.OfType<EarlyDataExtension>().Any() || offered == null)
                return false;
            if (_server.MaxEarlyDataSize == 0 || _ticketState == null || _ticketState.MaxEarlyDataSize == 0 || _pskIdentity != 0
                || _helloRetried || _ticketState.CipherSuite != Session.CipherSuite.Id
                || _ticketState.ApplicationProtocol != ApplicationProtocol)
                return false;

            uint clientAge = unchecked(offered.Identities[0].ObfuscatedAge - _ticketState.AgeAdd);
            double serverAge = (DateTime.UtcNow - _ticketState.IssuedUtc).TotalMilliseconds;
            if (Math.Abs(serverAge - clientAge) > _server.EarlyDataFreshnessWindow.TotalMilliseconds)
                return false;
            return _server.RecordEarlyDataClientHello(offered.Binders[0]);
        }

        protected override void OnEarlyData(byte[] data)
        {
            if (_earlyKeys == null)
                throw new DtlsRecordDiscardedException("Early data after the client Finished");
            _earlyDataReceived += data.Length;
            if (_earlyDataReceived > _ticketState.MaxEarlyDataSize)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Early data exceeds max_early_data_size.");
            RaiseEvent(() => _server.OnEarlyData(this, data));
        }

        private void SendServerFlight()
        {
            var suite = Session.CipherSuite;

            // The key share for the chosen group (none for psk_ke).
            byte[] share = null, sharedSecret = null;
            if (!_pskOnly)
            {
                (share, sharedSecret) = Dtls13Groups.Respond(_group,
                    _clientHello.Extensions.OfType<ClientKeyShareExtension>().First().GetKeyShare(_group));
                NegotiatedGroup = _group;
            }

            BeginFlight();

            // RFC 9147 §5: legacy_session_id_echo stays empty, whatever the client sent (no compatibility mode).
            var serverHello = new ServerHelloDatagram(Array.Empty<byte>(), suite.Id, Dtls13CryptoUtils.GenerateRandom(32));
            serverHello.Extensions.RemoveAll(e => e is ServerKeyShareExtension);
            if (!_pskOnly)
                serverHello.Extensions.Insert(0, new ServerKeyShareExtension(_group, share));
            if (_psk != null)
                serverHello.Extensions.Add(new ServerPreSharedKeyExtension((ushort)_pskIdentity));
            if (ReadConnectionId != null)
                serverHello.Extensions.Add(new ConnectionIdExtension(ReadConnectionId));
            Session.Transcript.AddPlaintextRecord(SendPlaintextHandshake(serverHello));

            var handshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), sharedSecret, suite, _psk);
            Session.ServerHandshakeKeys = handshakeKeys;
            Session.WriteKeys = handshakeKeys;
            AddReadKeys(handshakeKeys);

            SendHandshake(BuildEncryptedExtensions(), handshakeKeys);

            // A PSK handshake is authenticated by the PSK: no CertificateRequest, Certificate or CertificateVerify.
            if (_psk == null)
            {
                if (_server.RequireClientCertificate)
                {
                    _certificateRequest = new CertificateRequestDatagram();
                    SendHandshake(_certificateRequest, handshakeKeys);
                    Session.RequiresClientAuth = true;
                }

                var chain = new List<byte[]> { _certificate.GetEncoded() };
                chain.AddRange((_intermediates ?? Array.Empty<X509Certificate>()).Select(c => c.GetEncoded()));
                SendHandshake(new CertificateDatagram(chain), handshakeKeys);

                var clientSchemes = _clientHello.Extensions.OfType<ClientSignatureAlgorithms>().FirstOrDefault()?.SignatureAlgorithms;
                ushort scheme = Dtls13Signatures.SelectScheme(_keyPair.Private, clientSchemes)
                    ?? throw new DtlsException(AlertDescription.HandshakeFailure, "No signature scheme in common with the client.");
                byte[] content = Dtls13Signatures.BuildSignedContent(server: true, Session.Transcript.Hash(suite));
                SendHandshake(new CertificateVerifyDatagram(Dtls13Signatures.Sign(scheme, _keyPair.Private, content), scheme), handshakeKeys);
            }

            byte[] verifyData = Dtls13CryptoUtils.CalculateFinished(handshakeKeys.ServerSecret, Session.Transcript.Hash(suite), suite);
            SendHandshake(new FinishedDatagram { VerifyData = verifyData }, handshakeKeys);

            byte[] serverFinishedHash = Session.Transcript.Hash(suite);
            Session.ServerApplicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(_clientHello.ClientRandom, serverFinishedHash, handshakeKeys.Secret, suite);
            Session.ExporterMasterSecret = Dtls13CryptoUtils.CalculateExporterMasterSecret(Session.ServerApplicationKeys.Secret, serverFinishedHash, suite);

            ArmRetransmission();
            _state = _certificateRequest != null ? State.WaitClientCertificate : State.WaitClientFinished;
        }

        private EncryptedExtensionsDatagram BuildEncryptedExtensions()
        {
            var extensions = new EncryptedExtensionsDatagram();

            var offered = _clientHello.Extensions.OfType<UseSrtpExtension>().FirstOrDefault();
            ushort? profile = DtlsSrtp.Select(_server.SrtpProtectionProfiles, offered?.SrtpProtectionProfiles);
            if (profile.HasValue)
            {
                SelectedSrtpProtectionProfile = profile;
                extensions.Extensions.Add(new UseSrtpExtension(new[] { profile.Value }, offered.MasterKeyIdentifier));
            }
            if (_earlyKeys != null)
                extensions.Extensions.Add(new EarlyDataExtension());
            // Acknowledge a server_name that chose the certificate (RFC 6066 §3).
            if (_serverNameUsed && _psk == null)
                extensions.Extensions.Add(new ServerNameExtension());
            if (ApplicationProtocol != null)
                extensions.Extensions.Add(new AlpnExtension(new[] { ApplicationProtocol }));
            if (_recordSizeResponse != null)
                extensions.Extensions.Add(_recordSizeResponse);

            return extensions;
        }

        protected override void OnPlaintextHandshake(byte[] record)
        {
            if (record[13] != 0x01)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[13]:X2}");

            int messageSeq = (record[17] << 8) | record[18];
            if (messageSeq < NextReceiveMessageSeq && !IsHandshakeComplete)
                OnDuplicatePlaintextHandshake(record); // our flight was lost: retransmit it
        }

        protected override void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            var suite = Session.CipherSuite;

            switch (_state)
            {
                case State.WaitClientCertificate when parsed is CertificateDatagram certificate:
                    if (!certificate.RequestContext.AsSpan().SequenceEqual(_certificateRequest.RequestContext))
                        throw new DtlsException(AlertDescription.IllegalParameter, "Certificate request context does not match.");

                    if (certificate.CertificateChain.Count == 0)
                    {
                        if (_server.RequireClientCertificate)
                            throw new DtlsException(AlertDescription.CertificateRequired, "Client did not send a certificate.");
                        Session.Transcript.AddHandshake(message);
                        _state = State.WaitClientFinished;
                        break;
                    }

                    try
                    {
                        _clientCertificate = new X509CertificateParser().ReadCertificate(certificate.Certificate);
                    }
                    catch (Exception ex)
                    {
                        throw new DtlsException(AlertDescription.BadCertificate, "Client certificate could not be parsed.", ex);
                    }
                    if (_clientCertificate == null)
                        throw new DtlsException(AlertDescription.BadCertificate, "Client certificate could not be parsed.");
                    if (_server.ClientCertificateValidator != null && !_server.ClientCertificateValidator(_clientCertificate, certificate.CertificateChain))
                        throw new DtlsException(AlertDescription.BadCertificate, "Client certificate was rejected.");

                    Session.ClientCertificateBytes = certificate.Certificate;
                    Session.PeerCertificate = certificate.Certificate;
                    Session.ReceivedClientCertificate = true;
                    Session.Transcript.AddHandshake(message);
                    _state = State.WaitClientCertificateVerify;
                    break;

                case State.WaitClientCertificateVerify when parsed is CertificateVerifyDatagram certificateVerify:
                {
                    ushort scheme = (ushort)certificateVerify.SignatureType;
                    if (!_certificateRequest.SignatureAlgorithms.Contains(scheme))
                        throw new DtlsException(AlertDescription.IllegalParameter, $"Client used signature scheme 0x{scheme:X4}, which was not requested.");

                    byte[] content = Dtls13Signatures.BuildSignedContent(server: false, Session.Transcript.Hash(suite));
                    if (!Dtls13Signatures.Verify(scheme, _clientCertificate.GetPublicKey(), content, certificateVerify.Signature))
                        throw new DtlsException(AlertDescription.DecryptError, "Client CertificateVerify signature is invalid.");

                    Session.ReceivedClientCertificateVerify = true;
                    Session.Transcript.AddHandshake(message);
                    _state = State.WaitClientFinished;
                    break;
                }

                case State.WaitClientFinished when parsed is FinishedDatagram finished:
                    OnClientFinished(message, finished);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message 0x{message[0]:X2} in state {_state}.");
            }
        }

        private void OnClientFinished(byte[] message, FinishedDatagram finished)
        {
            var suite = Session.CipherSuite;
            var handshakeKeys = Session.ServerHandshakeKeys;

            byte[] expected = Dtls13CryptoUtils.CalculateFinished(handshakeKeys.ClientSecret, Session.Transcript.Hash(suite), suite);
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, finished.VerifyData))
                throw new DtlsException(AlertDescription.DecryptError, "Client Finished verification failed.");

            Session.Transcript.AddHandshake(message);
            StopRetransmission();

            // The client's Finished ends the early data epoch.
            if (_earlyKeys != null)
            {
                Session.ReadKeys.Remove(_earlyKeys);
                _earlyKeys = null;
            }

            Session.ResumptionMasterSecret = Dtls13CryptoUtils.CalculateResumptionMasterSecret(
                Session.ServerApplicationKeys.Secret, Session.Transcript.Hash(suite), suite);

            var applicationKeys = Session.ServerApplicationKeys;
            Session.WriteKeys = applicationKeys;
            AddReadKeys(applicationKeys);

            _state = State.Connected;
            IsHandshakeComplete = true;

            // ACK the client's final flight (RFC 9147 §7.1) in the application epoch.
            SendAck();

            // A client that offers a PSK mode we accept can resume: give it a ticket.
            var modes = _clientHello.Extensions.OfType<PskKeyExchangeModesExtension>().FirstOrDefault();
            if (_server.TicketKeys != null && modes != null && (modes.Modes.Contains(PskKeyExchangeModesExtension.PskDheKe)
                    || (_server.AllowPskOnlyKeyExchange && modes.Modes.Contains(PskKeyExchangeModesExtension.PskKe))))
                IssueTicket();

            WriteKeyLog(Convert.ToHexString(_clientHello.ClientRandom), handshakeKeys, applicationKeys);
            Debug.WriteLine($"[DTLS13 Server] Handshake complete with {RemoteEndPoint}");
            RaiseEvent(() => _server.OnConnectionEstablished(this));
        }

        /// <summary>Sends another session ticket (RFC 8446 §4.6.1); one is sent automatically after the handshake.</summary>
        public void SendNewSessionTicket()
        {
            Run(() =>
            {
                if (!IsHandshakeComplete)
                    throw new InvalidOperationException("The handshake has not completed.");
                if (_server.TicketKeys == null)
                    throw new InvalidOperationException("Session tickets are disabled (TicketKeys is null).");
                IssueTicket();
            });
        }

        // The ticket seals the PSK derived from the resumption master secret and a fresh nonce.
        private void IssueTicket()
        {
            var keys = _server.TicketKeys;
            var suite = Session.CipherSuite;
            byte[] nonce = Dtls13CryptoUtils.GenerateRandom(8);
            uint ageAdd = BitConverter.ToUInt32(Dtls13CryptoUtils.GenerateRandom(4), 0);
            uint lifetime = (uint)Math.Min(604800, keys.Lifetime.TotalSeconds);
            var state = new Dtls13TicketState
            {
                MaxEarlyDataSize = _server.MaxEarlyDataSize,
                ServerName = ServerName,
                ApplicationProtocol = ApplicationProtocol,
                CipherSuite = suite.Id,
                Psk = Dtls13CryptoUtils.CalculateResumptionPsk(Session.ResumptionMasterSecret, nonce, suite),
                AgeAdd = ageAdd,
                IssuedUtc = DateTime.UtcNow,
                ClientCertificate = Session.ClientCertificateBytes,
            };

            // Retransmitted until the client ACKs it (RFC 9147 §5.8).
            SendPostHandshakeFlight(() => SendHandshake(new NewSessionTicketDatagram(state.Seal(keys), nonce, lifetime, ageAdd) { MaxEarlyDataSize = state.MaxEarlyDataSize },
                Session.WriteKeys, addToTranscript: false));
        }
    }
}
