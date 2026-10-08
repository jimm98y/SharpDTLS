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
    public class Dtls13Server : Tls13ServerBase
    {
        private readonly ConcurrentDictionary<string, Dtls13ServerConnection> _connections = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        public IServerTransport ServerTransport { get; }

        /// <summary>Send a HelloRetryRequest with a cookie before allocating state (address validation, RFC 9147 §5.1).</summary>
        public bool ShouldSendHelloRetry { get; set; } = true;

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0007, 0x0001 };

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

        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>0-RTT data accepted before the handshake completes; it may be a replay.</summary>
        public event EventHandler<Dtls13DataReceivedEventArgs> EarlyDataReceived;

        internal override void OnEarlyData(Dtls13ServerConnection connection, byte[] data)
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

            var decision = DecideClientHello(clientHello, record, endpoint, ShouldSendHelloRetry);
            if (decision.HelloRetryRequest != null)
            {
                // RFC 9147 §5.1: reuse the ClientHello's message and record sequence numbers, so a stateless server never repeats one.
                decision.HelloRetryRequest.SequenceNumber = clientHello.SequenceNumber;
                decision.HelloRetryRequest.RecordSequenceNumber = clientHello.RecordSequenceNumber;
                Debug.WriteLine($"[DTLS13 Server] Sending HelloRetryRequest to {endpoint}");
                ServerTransport.Send(endpoint, decision.HelloRetryRequest.ToBytes());
                return;
            }

            var connection = new Dtls13ServerConnection(this, endpoint);
            if (!_connections.TryAdd(endpoint.ToString(), connection))
            {
                _connections[endpoint.ToString()].ProcessDatagram(datagram);
                return;
            }

            connection.Start(record, clientHello, Dtls13CipherSuite.Get(decision.SuiteId), decision.Retry, decision.ShareGroup);
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

        private void SendPlaintextAlert(EndPoint endpoint, AlertDescription alert)
        {
            byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, (byte)alert };
            try { ServerTransport.Send(endpoint, record); }
            catch (Exception ex) { Debug.WriteLine($"[DTLS13 Server] Failed to send alert: {ex.Message}"); }
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal override void OnConnectionEstablished(Dtls13ServerConnection connection)
            => HandshakeFinished?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));

        internal override void OnApplicationData(Dtls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls13DataReceivedEventArgs(connection.RemoteEndPoint, connection, data));

        internal override void OnKeyUpdate(KeyUpdateDatagram keyUpdate)
            => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal override void OnConnectionClosed(Dtls13ServerConnection connection)
        {
            _connections.TryRemove(new KeyValuePair<string, Dtls13ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
            foreach (var entry in _connectionsById.Where(e => e.Value == connection).ToList())
                _connectionsById.TryRemove(entry);
            ConnectionClosed?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));
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

        private readonly Tls13ServerBase _server;

        // The DTLS server, for its datagram-only settings (connection IDs, SRTP, address updates).
        private Dtls13Server DatagramServer => (Dtls13Server)_server;
        private State _state = State.Start;
        private ClientHelloDatagram _clientHello;
        private CertificateRequestDatagram _certificateRequest;
        private X509Certificate _clientCertificate;
        private AsymmetricKeyParameter _clientPublicKey;
        private CertificateType? _serverCertificateType;
        private CertificateType? _clientCertificateType;
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
        private byte[] _ocspResponse;
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
                RaiseEvent(() => DatagramServer.OnPeerAddressConfirmed(this, old));
        });

        protected override void OnConnectionIdIssued(byte[] connectionId) => DatagramServer.RegisterConnectionId(this, connectionId);

        protected override void OnRecordAuthenticated(ulong epoch, ulong sequenceNumber, bool withConnectionId)
        {
            if (!_address.Observe(epoch, sequenceNumber, withConnectionId, DatagramSource, DatagramServer.AutoUpdatePeerAddress, out var old))
                return;
            var change = (old, DatagramSource);
            RaiseEvent(() => PeerAddressChanged?.Invoke(this, change));
            if (DatagramServer.AutoUpdatePeerAddress)
                RaiseEvent(() => DatagramServer.OnPeerAddressConfirmed(this, old));
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

        /// <summary>The algorithm the client compressed its certificate with, or null when it was not compressed.</summary>
        public ushort? CertificateCompressionAlgorithm { get; private set; }

        /// <summary>The client's raw public key (DER SubjectPublicKeyInfo, RFC 7250), when it authenticated with one.</summary>
        public byte[] ClientRawPublicKey { get; private set; }

        /// <summary>The certificate type we authenticated with (RFC 7250).</summary>
        public CertificateType ServerCertificateType => _serverCertificateType ?? CertificateType.X509;

        internal Dtls13ServerConnection(Dtls13Server server, EndPoint remoteEndPoint)
            : this(server, new PeerAddressTracker(remoteEndPoint))
        {
        }

        /// <summary>A TLS 1.3 connection over a stream: the ClientHello arrives on it.</summary>
        internal Dtls13ServerConnection(Tls13ServerBase server, EndPoint remoteEndPoint, Action<byte[]> send)
            : base(isClient: false, send, stream: true)
        {
            _server = server;
            _address = new PeerAddressTracker(remoteEndPoint);
            KeyLogWriter = server.KeyLogWriter;

            ApplicationDataReceived += (_, data) => _server.OnApplicationData(this, data);
            KeyUpdateReceived += (_, keyUpdate) => _server.OnKeyUpdate(keyUpdate);
            Closed += (_, _) => _server.OnConnectionClosed(this);
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

        internal void Start(byte[] record, ClientHelloDatagram clientHello, Dtls13CipherSuite suite, Tls13ServerBase.HelloRetryState retry, ushort group)
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
                    var hrr = new HelloRetryRequest(suite.Id, retry.Cookie, retry.RequestedGroup != 0 ? retry.RequestedGroup : null,
                        IsDatagram ? Array.Empty<byte>() : clientHello.LegacySessionId, IsDatagram);
                    Session.Transcript.AddMessageHash(retry.ClientHello1Hash);
                    Session.Transcript.AddPlaintextRecord(hrr.ToBytes());
                }
                _helloRetried = retry != null;
                ServerName = _clientHello.Extensions.OfType<ServerNameExtension>().FirstOrDefault()?.HostName;
                var selected = _server.CredentialsSelector?.Invoke(new CertificateSelectionContext(ServerName,
                        CertificateSelectionContext.ParseNames(_clientHello.Extensions.OfType<CertificateAuthoritiesExtension>().FirstOrDefault()?.Names),
                        _clientHello.Extensions.OfType<ClientSignatureAlgorithms>().FirstOrDefault()?.SignatureAlgorithms,
                        _clientHello.Extensions.OfType<SignatureAlgorithmsCertExtension>().FirstOrDefault()?.Schemes))
                    ?? _server.CertificateSelector?.Invoke(ServerName);
                _serverNameUsed = selected != null && ServerName != null;
                (_keyPair, _certificate, _intermediates, _ocspResponse) = selected != null
                    ? (selected.KeyPair, selected.Certificate, selected.IntermediateCertificates, selected.OcspResponse)
                    : (_server.ServerKeyPair, _server.ServerCertificate, _server.IntermediateCertificates, _server.OcspResponse);
                if (_clientHello.Extensions.OfType<StatusRequestExtension>().FirstOrDefault()?.StatusType != StatusRequestExtension.Ocsp)
                    _ocspResponse = null;

                // Certificate types (RFC 7250); without one in common we cannot authenticate with a certificate.
                _serverCertificateType = RawPublicKeys.Choose(_server.ServerCertificateTypes,
                    RawPublicKeys.Find(_clientHello.Extensions, CertificateTypeExtension.ServerType),
                    t => t == CertificateType.RawPublicKey ? _keyPair != null : _certificate != null);
                _clientCertificateType = RawPublicKeys.Choose(_server.ClientCertificateTypes,
                    RawPublicKeys.Find(_clientHello.Extensions, CertificateTypeExtension.ClientType), _ => true);
                if (_serverCertificateType == CertificateType.RawPublicKey)
                    _ocspResponse = null;

                ApplicationProtocol = AlpnExtension.Select(_server.ApplicationProtocols, _clientHello.Extensions.OfType<AlpnExtension>().FirstOrDefault());

                // Record size limits apply to everything we send from the ServerHello on (0-RTT data is exempt).
                RecordSizeNegotiation.Validate(_server.RecordSizeLimit, null);
                (PeerRecordLimit, ReceiveRecordLimit, _recordSizeResponse) = RecordSizeNegotiation.Accept(
                    _clientHello.Extensions.OfType<RecordSizeLimitExtension>().FirstOrDefault(),
                    _clientHello.Extensions.OfType<MaxFragmentLengthExtension>().FirstOrDefault(), _server.RecordSizeLimit, dtls13: true);

                var offeredCid = _clientHello.Extensions.OfType<ConnectionIdExtension>().FirstOrDefault();
                if (IsDatagram && DatagramServer.UseConnectionIds && offeredCid != null)
                {
                    WriteConnectionId = offeredCid.ConnectionId;
                    ReadConnectionId = Dtls13CryptoUtils.GenerateRandom(DatagramServer.ConnectionIdLength);
                }

                SelectPsk(record);
                if (_psk == null && (_group == 0 || _serverCertificateType == null))
                    throw new DtlsException(_serverCertificateType == null && _keyPair != null ? AlertDescription.UnsupportedCertificate : AlertDescription.HandshakeFailure,
                        _keyPair == null ? "PSK-only server and no acceptable PSK."
                        : _serverCertificateType == null ? "No certificate type in common and no acceptable PSK." : "No key share and no acceptable PSK.");
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
            // TLS 0-RTT (with EndOfEarlyData) is not implemented: decline, and skip the client's early records.
            if (!IsDatagram)
            {
                if (_clientHello.Extensions.OfType<EarlyDataExtension>().Any())
                    SkipUndecryptableBytes = 64 * 1024;
                return false;
            }
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
            var serverHello = new ServerHelloDatagram(Array.Empty<byte>(), suite.Id, Dtls13CryptoUtils.GenerateRandom(32)) { Datagram = IsDatagram };
            serverHello.Extensions.RemoveAll(e => e is ServerKeyShareExtension);
            if (!IsDatagram)
            {
                serverHello.Extensions.RemoveAll(e => e is ServerSupportedVersions);
                serverHello.Extensions.Add(new ServerSupportedVersions(ClientSupportedVersions.Tls13));
                serverHello.LegacySessionIdEcho = _clientHello.LegacySessionId; // RFC 8446 §4.1.3
            }
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
                    if (_clientCertificateType == null)
                        throw new DtlsException(AlertDescription.UnsupportedCertificate, "No client certificate type in common.");
                    CertificateCompression.Validate(_server.CertificateCompressionAlgorithms);
                    _certificateRequest = new CertificateRequestDatagram
                    {
                        CompressionAlgorithms = _server.CertificateCompressionAlgorithms,
                        CertificateAuthorities = CertificateSelectionContext.Encode(_server.ClientCertificateAuthorities),
                    };
                    SendHandshake(_certificateRequest, handshakeKeys);
                    Session.RequiresClientAuth = true;
                }

                var chain = new List<byte[]>();
                if (_serverCertificateType == CertificateType.RawPublicKey)
                {
                    chain.Add(RawPublicKeys.Encode(_keyPair.Public));
                }
                else
                {
                    chain.Add(_certificate.GetEncoded());
                    chain.AddRange((_intermediates ?? Array.Empty<X509Certificate>()).Select(c => c.GetEncoded()));
                }
                var certificate = new CertificateDatagram(chain) { OcspResponse = _ocspResponse };
                CertificateCompression.Validate(_server.CertificateCompressionAlgorithms);
                ushort? compression = CertificateCompression.Select(_server.CertificateCompressionAlgorithms,
                    _clientHello.Extensions.OfType<CompressCertificateExtension>().FirstOrDefault()?.Algorithms);
                SendHandshake(compression.HasValue ? new CompressedCertificateDatagram(compression.Value, certificate) : certificate, handshakeKeys);

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
            ushort? profile = IsDatagram ? DtlsSrtp.Select(DatagramServer.SrtpProtectionProfiles, offered?.SrtpProtectionProfiles) : null;
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
            // The chosen certificate types (RFC 7250 §4.2); client_certificate_type only when a CertificateRequest can
            // follow, now or after the handshake.
            if (_psk == null && RawPublicKeys.Find(_clientHello.Extensions, CertificateTypeExtension.ServerType) != null)
                extensions.Extensions.Add(new CertificateTypeExtension(CertificateTypeExtension.ServerType, _serverCertificateType.Value));
            if (_psk == null && (_server.RequireClientCertificate || AllowsPostHandshakeAuthentication) && _clientCertificateType != null
                && RawPublicKeys.Find(_clientHello.Extensions, CertificateTypeExtension.ClientType) != null)
                extensions.Extensions.Add(new CertificateTypeExtension(CertificateTypeExtension.ClientType, _clientCertificateType.Value));

            return extensions;
        }

        protected override void OnPlaintextHandshake(byte[] record)
        {
            if (!IsDatagram)
            {
                OnTlsClientHello(record);
                return;
            }
            if (record[13] != 0x01)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[13]:X2}");

            int messageSeq = (record[17] << 8) | record[18];
            if (messageSeq < NextReceiveMessageSeq && !IsHandshakeComplete)
                OnDuplicatePlaintextHandshake(record); // our flight was lost: retransmit it
        }

        private bool _awaitingClientHello2;

        // TLS: the ClientHello (or, after a HelloRetryRequest, ClientHello2) arrives on the connection's own stream.
        private void OnTlsClientHello(byte[] record)
        {
            if (record[5] != 0x01 || _clientHello != null)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[5]:X2}");

            var clientHello = new ClientHelloDatagram { Datagram = false };
            clientHello.FromBytes(record);
            var decision = _server.DecideClientHello(clientHello, record, RemoteEndPoint, alwaysRetry: false);
            if (decision.HelloRetryRequest != null)
            {
                // RFC 8446 §4.1.4: a second HelloRetryRequest is an error.
                if (_awaitingClientHello2)
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 still needs a HelloRetryRequest.");
                _awaitingClientHello2 = true;
                SendPlaintextHandshake(decision.HelloRetryRequest);
                return;
            }
            if (_awaitingClientHello2 && decision.Retry == null)
                throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 without the HelloRetryRequest cookie.");
            Start(record, clientHello, SuiteFor(decision.SuiteId), decision.Retry, decision.ShareGroup);
        }

        protected override void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            var suite = Session.CipherSuite;

            // A CompressedCertificate stands for the Certificate; the transcript keeps the message as received.
            if (parsed is CompressedCertificateDatagram compressed && _state == State.WaitClientCertificate)
            {
                parsed = compressed.Decompress(_certificateRequest.CompressionAlgorithms);
                CertificateCompressionAlgorithm = compressed.Algorithm;
            }

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

                    if (_clientCertificateType == CertificateType.RawPublicKey)
                    {
                        if (certificate.CertificateChain.Count != 1)
                            throw new DtlsException(AlertDescription.DecodeError, "A raw public key Certificate has one entry.");
                        byte[] spki = certificate.Certificate;
                        _clientPublicKey = RawPublicKeys.Decode(spki);
                        if (_server.ClientRawPublicKeyValidator != null && !_server.ClientRawPublicKeyValidator(spki))
                            throw new DtlsException(AlertDescription.BadCertificate, "Client raw public key was rejected.");
                        ClientRawPublicKey = spki;
                        // Nothing to resume with: a later resumption that requires a certificate does a full handshake.
                        Session.ReceivedClientCertificate = true;
                        Session.Transcript.AddHandshake(message);
                        _state = State.WaitClientCertificateVerify;
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
                    _clientPublicKey = _clientCertificate.GetPublicKey();

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
                    if (!Dtls13Signatures.Verify(scheme, _clientPublicKey, content, certificateVerify.Signature))
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

        // ── Post-handshake client authentication (RFC 8446 §4.6.2) ────────────────────────────

        private sealed class PostHandshakeAuthentication
        {
            public CertificateRequestDatagram Request;
            public Dtls13Transcript Transcript;
            public bool Required;
            public int Stage; // 0 Certificate, 1 CertificateVerify, 2 Finished
            public X509Certificate Certificate;
            public byte[] RawPublicKey;
            public AsymmetricKeyParameter PublicKey;
        }

        private PostHandshakeAuthentication _postHandshakeAuthentication;

        /// <summary>Whether the client offered post_handshake_auth, so <see cref="RequestClientCertificate"/> may be used.</summary>
        public bool AllowsPostHandshakeAuthentication => _clientHello?.Extensions.OfType<PostHandshakeAuthExtension>().Any() == true;

        /// <summary>
        /// Raised when the client answered <see cref="RequestClientCertificate"/>: <see cref="ClientCertificate"/> (or
        /// <see cref="ClientRawPublicKey"/>) is then the authenticated client, or unchanged when it sent none.
        /// </summary>
        public event EventHandler PostHandshakeAuthenticationCompleted;

        /// <summary>
        /// Asks the client for its certificate after the handshake (RFC 8446 §4.6.2). The answer is checked like one in
        /// the handshake (ClientCertificateValidator or ClientRawPublicKeyValidator, CertificateVerify, Finished); with
        /// <paramref name="required"/> an answer without a certificate is a certificate_required alert.
        /// </summary>
        public void RequestClientCertificate(bool required = true) => Locked(() =>
        {
            if (!IsHandshakeComplete || IsClosed)
                throw new InvalidOperationException("The handshake has not completed.");
            if (!AllowsPostHandshakeAuthentication)
                throw new InvalidOperationException("The client did not offer post-handshake authentication.");
            if (_postHandshakeAuthentication != null)
                throw new InvalidOperationException("A post-handshake certificate request is already outstanding.");
            if (_clientCertificateType == null)
                throw new InvalidOperationException("No client certificate type in common.");

            CertificateCompression.Validate(_server.CertificateCompressionAlgorithms);
            var request = new CertificateRequestDatagram
            {
                RequestContext = Dtls13CryptoUtils.GenerateRandom(8),
                CompressionAlgorithms = _server.CertificateCompressionAlgorithms,
                CertificateAuthorities = CertificateSelectionContext.Encode(_server.ClientCertificateAuthorities),
            };
            var authentication = new PostHandshakeAuthentication { Request = request, Transcript = Session.Transcript.Clone(), Required = required };
            _postHandshakeAuthentication = authentication;
            SendPostHandshakeFlight(() => authentication.Transcript.AddHandshake(SendHandshake(request, Session.WriteKeys, addToTranscript: false)));
        });

        protected override bool OnPostHandshakeAuthMessage(byte[] message, IHandshakeDatagram parsed)
        {
            var auth = _postHandshakeAuthentication;
            if (auth == null)
                return false;
            var suite = Session.CipherSuite;
            if (parsed is CompressedCertificateDatagram compressed && auth.Stage == 0)
            {
                parsed = compressed.Decompress(auth.Request.CompressionAlgorithms);
                CertificateCompressionAlgorithm = compressed.Algorithm;
            }

            switch (parsed)
            {
                case CertificateDatagram certificate when auth.Stage == 0:
                    if (!certificate.RequestContext.AsSpan().SequenceEqual(auth.Request.RequestContext))
                        throw new DtlsException(AlertDescription.IllegalParameter, "Certificate request context does not match.");
                    if (certificate.CertificateChain.Count == 0)
                    {
                        if (auth.Required)
                            throw new DtlsException(AlertDescription.CertificateRequired, "Client did not send a certificate.");
                        auth.Stage = 2;
                    }
                    else if (_clientCertificateType == CertificateType.RawPublicKey)
                    {
                        if (certificate.CertificateChain.Count != 1)
                            throw new DtlsException(AlertDescription.DecodeError, "A raw public key Certificate has one entry.");
                        auth.PublicKey = RawPublicKeys.Decode(certificate.Certificate);
                        if (_server.ClientRawPublicKeyValidator != null && !_server.ClientRawPublicKeyValidator(certificate.Certificate))
                            throw new DtlsException(AlertDescription.BadCertificate, "Client raw public key was rejected.");
                        auth.RawPublicKey = certificate.Certificate;
                        auth.Stage = 1;
                    }
                    else
                    {
                        auth.Certificate = SharpDTLS.DTLS12.Dtls12ClientConnection.ParseCertificate(certificate.Certificate);
                        if (_server.ClientCertificateValidator != null && !_server.ClientCertificateValidator(auth.Certificate, certificate.CertificateChain))
                            throw new DtlsException(AlertDescription.BadCertificate, "Client certificate was rejected.");
                        auth.PublicKey = auth.Certificate.GetPublicKey();
                        auth.Stage = 1;
                    }
                    auth.Transcript.AddHandshake(message);
                    return true;

                case CertificateVerifyDatagram certificateVerify when auth.Stage == 1:
                {
                    ushort scheme = (ushort)certificateVerify.SignatureType;
                    if (!auth.Request.SignatureAlgorithms.Contains(scheme))
                        throw new DtlsException(AlertDescription.IllegalParameter, $"Client used signature scheme 0x{scheme:X4}, which was not requested.");
                    byte[] content = Dtls13Signatures.BuildSignedContent(server: false, auth.Transcript.Hash(suite));
                    if (!Dtls13Signatures.Verify(scheme, auth.PublicKey, content, certificateVerify.Signature))
                        throw new DtlsException(AlertDescription.DecryptError, "Client CertificateVerify signature is invalid.");
                    auth.Transcript.AddHandshake(message);
                    auth.Stage = 2;
                    return true;
                }

                case FinishedDatagram finished when auth.Stage == 2:
                {
                    var clientKeys = Session.ReadKeys[Session.ReadKeys.Count - 1];
                    byte[] expected = Dtls13CryptoUtils.CalculateFinished(clientKeys.ClientSecret, auth.Transcript.Hash(suite), suite);
                    if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, finished.VerifyData))
                        throw new DtlsException(AlertDescription.DecryptError, "Post-handshake Finished verification failed.");
                    SendAck();
                    _postHandshakeAuthentication = null;
                    if (auth.PublicKey != null)
                    {
                        (_clientCertificate, _clientPublicKey, ClientRawPublicKey) = (auth.Certificate, auth.PublicKey, auth.RawPublicKey);
                        Session.ReceivedClientCertificate = true;
                    }
                    RaiseEvent(() => PostHandshakeAuthenticationCompleted?.Invoke(this, EventArgs.Empty));
                    return true;
                }

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected message 0x{message[0]:X2} in post-handshake authentication.");
            }
        }
    }
}
