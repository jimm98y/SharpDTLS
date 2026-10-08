using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS12
{
    /// <summary>Configuration shared by all connections of a (D)TLS 1.0-1.2 server.</summary>
    public sealed class Tls12ServerSettings
    {
        public AsymmetricCipherKeyPair KeyPair { get; set; }
        public X509Certificate Certificate { get; set; }
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>Cipher suites in server preference order; null for all implemented suites.</summary>
        public IList<ushort> CipherSuites { get; set; }

        public bool RequireClientCertificate { get; set; }
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator { get; set; }

        /// <summary>Certificate types we authenticate with, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ServerCertificateTypes { get; set; }

        /// <summary>
        /// Chooses credentials from what the client said (server name, signature schemes); returning null falls back to
        /// <see cref="CertificateSelector"/> and then the default certificate.
        /// </summary>
        public Func<CertificateSelectionContext, ServerCredentials> CredentialsSelector { get; set; }

        /// <summary>CAs whose names a CertificateRequest lists, to guide the client's choice; null lists none.</summary>
        public IList<X509Certificate> ClientCertificateAuthorities { get; set; }

        /// <summary>Certificate types accepted from clients, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ClientCertificateTypes { get; set; }

        /// <summary>Checks a client's raw public key (DER SubjectPublicKeyInfo); false aborts with bad_certificate.</summary>
        public Func<byte[], bool> ClientRawPublicKeyValidator { get; set; }

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } =
            { DtlsSrtp.SRTP_AEAD_AES_128_GCM, DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80, DtlsSrtp.SRTP_AEAD_AES_256_GCM, DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_32 };

        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);
        public Action<string> KeyLogWriter { get; set; }

        /// <summary>Optional psk_identity_hint sent to PSK clients (RFC 4279 §5.2).</summary>
        public byte[] PskIdentityHint { get; set; }

        /// <summary>Maps a client's PSK identity to its key (null for unknown identities); enables the PSK suites.</summary>
        public Func<byte[], byte[]> PskIdentityResolver { get; set; }

        /// <summary>Maps an SRP username to its verifier (null for unknown users); enables the SRP suites.</summary>
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get; set; }

        /// <summary>
        /// Maps a TLS-PWD username to its credential (null for unknown users, whose handshakes are simulated
        /// and fail like a wrong password, RFC 8492 §4.5.1.1); enables the ECCPWD suites.
        /// </summary>
        public Func<string, PwdCredential> PwdCredentialProvider { get; set; }

        /// <summary>Private key for recovering pwd_protect usernames (RFC 8492 §4.3.2); null accepts only pwd_clear.</summary>
        public ECPrivateKeyParameters PwdProtectionKey { get; set; }

        /// <summary>Resumable sessions by session ID; null disables session ID resumption.</summary>
        public IDtls12SessionCache SessionCache { get; set; } = new Dtls12SessionCache();

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
        /// A DER OCSP response for <see cref="Certificate"/> to staple for clients that ask (RFC 6066 §8); null for none.
        /// Certificates from the CertificateSelector staple their own <see cref="ServerCredentials.OcspResponse"/>.
        /// </summary>
        public byte[] OcspResponse { get; set; }

        /// <summary>The server also offers (D)TLS 1.3: lower versions carry the downgrade sentinel (RFC 8446 §4.1.3).</summary>
        internal bool SignalTls13Downgrade { get; set; }

        /// <summary>
        /// Negotiate connection IDs (RFC 9146) with clients that offer them: the client then sends our CID in every
        /// encrypted record, so the association survives a change of its address (e.g. NAT rebinding).
        /// </summary>
        public bool UseConnectionIds { get; set; }

        /// <summary>Length of the CIDs this server issues (fixed, so records can be routed by CID).</summary>
        public int ConnectionIdLength { get; set; } = 8;

        /// <summary>
        /// Send to a client's new address as soon as an authenticated, newer record arrives from it (RFC 9146 §6).
        /// When false the address stays pending until the application verifies it and calls ConfirmPeerAddress.
        /// </summary>
        public bool AutoUpdatePeerAddress { get; set; } = true;

        /// <summary>Keys for RFC 5077 session tickets (random per server by default); null disables tickets.</summary>
        public SessionTicketKeys TicketKeys { get; set; } = new SessionTicketKeys();
    }

    /// <summary>
    /// Server side of one (D)TLS 1.0-1.2 connection: over datagrams created once the ClientHello has passed the
    /// cookie exchange (RFC 6347 §4.2.1), over a stream reading the ClientHello itself.
    /// </summary>
    public class Tls12ServerConnection : Tls12Connection
    {
        private enum State
        {
            Start,
            WaitClientCertificate,
            WaitClientKeyExchange,
            WaitCertificateVerify,
            WaitFinished,
            Connected,
        }

        private readonly Tls12ServerSettings _settings;
        private ITlsExtension _recordSizeResponse;
        private State _state = State.Start;
        private ClientHelloMessage _clientHello;
        private CertificateRequestMessage _certificateRequest;
        private IServerKeyExchange _keyExchange;
        private X509Certificate _clientCertificate;
        private AsymmetricKeyParameter _clientPublicKey;
        private CertificateType? _serverCertificateType;
        private CertificateType? _clientCertificateType;
        private Dtls12SessionState _resumedSession;
        private byte[] _sessionId = Array.Empty<byte>();
        private bool _issueTicket;
        private AsymmetricCipherKeyPair _keyPair;
        private X509Certificate _certificate;
        private IList<X509Certificate> _intermediates;
        private byte[] _ocspResponse;
        private bool _serverNameUsed;

        public event EventHandler<EventArgs> HandshakeFinished;

        public Tls12ServerConnection(Tls12ServerSettings settings, EndPoint remoteEndPoint, Action<byte[]> send)
            : this(settings, remoteEndPoint, send, stream: false)
        {
        }

        /// <param name="stream">TLS over a reliable byte stream: the ClientHello arrives on it (no cookie exchange).</param>
        internal Tls12ServerConnection(Tls12ServerSettings settings, EndPoint remoteEndPoint, Action<byte[]> send, bool stream)
            : base(isClient: false, send, stream)
        {
            _settings = settings;
            _address = new PeerAddressTracker(remoteEndPoint);
            MinimumVersion = settings.MinimumVersion;
            MaximumVersion = settings.MaximumVersion;
            InitialRetransmitTimeout = settings.InitialRetransmitTimeout;
            KeyLogWriter = settings.KeyLogWriter;
        }

        private readonly PeerAddressTracker _address;

        /// <summary>Where this connection sends: the client's address, which can move with connection IDs.</summary>
        public EndPoint RemoteEndPoint => _address.Current;

        /// <summary>A newer client address awaiting <see cref="ConfirmPeerAddress"/> (when not following automatically).</summary>
        public EndPoint PendingPeerAddress => _address.Pending;

        /// <summary>
        /// The client appeared at a new address (RFC 9146 §6): a record carrying our CID authenticated, was newer than
        /// any before and came from elsewhere. With AutoUpdatePeerAddress replies already go there; otherwise the
        /// address is pending until <see cref="ConfirmPeerAddress"/>.
        /// </summary>
        public event EventHandler<(EndPoint Old, EndPoint New)> PeerAddressChanged;

        /// <summary>Sends to <paramref name="address"/> from now on, after the application has checked it can be reached.</summary>
        public void ConfirmPeerAddress(EndPoint address) => Locked(() =>
        {
            var old = _address.Current;
            _address.Confirm(address);
            if (!old.Equals(address))
                RaiseEvent(() => PeerAddressConfirmed?.Invoke(this, (old, address)));
        });

        internal event EventHandler<(EndPoint Old, EndPoint New)> PeerAddressConfirmed;

        protected override void OnRecordAuthenticated(ushort epoch, ulong sequenceNumber, bool withConnectionId)
        {
            if (!_address.Observe(epoch, sequenceNumber, withConnectionId, DatagramSource, _settings.AutoUpdatePeerAddress, out var old))
                return;
            var change = (old, DatagramSource);
            Debug.WriteLine($"{LogPrefix} Peer address {(_settings.AutoUpdatePeerAddress ? "changed" : "pending")}: {old} -> {DatagramSource}");
            RaiseEvent(() => PeerAddressChanged?.Invoke(this, change));
            if (_settings.AutoUpdatePeerAddress)
                RaiseEvent(() => PeerAddressConfirmed?.Invoke(this, change));
        }

        /// <summary>The host name the client asked for in server_name, or null.</summary>
        public string ServerName { get; private set; }

        /// <summary>The client's certificate, when one was sent.</summary>
        public X509Certificate ClientCertificate => _clientCertificate;

        /// <summary>The client's raw public key (DER SubjectPublicKeyInfo, RFC 7250), when it authenticated with one.</summary>
        public byte[] ClientRawPublicKey { get; private set; }

        /// <summary>The certificate type we authenticated with (RFC 7250).</summary>
        public CertificateType ServerCertificateType => _serverCertificateType ?? CertificateType.X509;

        /// <summary>The negotiated (EC)DHE group, or 0 (RSA key exchange).</summary>
        public ushort NamedGroup => _keyExchange?.Group ?? 0;
        public bool ExtendedMasterSecretNegotiated => UseExtendedMasterSecret;
        public bool EncryptThenMacNegotiated => UseEncryptThenMac;
        public byte[] ClientRandomBytes => ClientRandom;
        public byte[] ServerRandomBytes => ServerRandom;

        /// <summary>Whether this handshake resumed a previous session (abbreviated handshake).</summary>
        public bool IsResumed => _resumedSession != null;

        // In an abbreviated handshake the client sends the final flight (RFC 6347 §4.2.4).
        protected override bool ResendFinalFlightOnPeerRetransmit => !IsResumed;

        /// <summary>
        /// Starts the handshake from a (cookie-verified, defragmented) ClientHello.
        /// <paramref name="message"/> is the ClientHello in DTLS handshake form.
        /// </summary>
        internal void Start(ClientHelloMessage clientHello, byte[] message, ulong recordSequenceNumber) => Run(() =>
        {
            _clientHello = clientHello;
            int messageSeq = (message[4] << 8) | message[5];

            // Message and record sequence numbers continue after a stateless HelloVerifyRequest (RFC 6347 §4.2.2).
            NextReceiveMessageSeq = messageSeq + 1;
            NextSendMessageSeq = messageSeq;
            SetInitialRecordSequence(recordSequenceNumber);
            OnClientHello(message);
        });

        private void OnClientHello(byte[] message)
        {
            Negotiate();

            ResetTranscript();
            AddToTranscript(message);
            SendServerFlight();
        }

        private void Negotiate()
        {
            var ch = _clientHello;

            // Highest version both sides support (DTLS version numbers count down).
            ushort version = ProtocolVersions.Legacy(IsDatagram)
                .FirstOrDefault(v => ProtocolVersions.IsAtLeast(MaximumVersion, v) && ProtocolVersions.IsAtLeast(v, MinimumVersion)
                                     && ProtocolVersions.IsAtLeast(ch.ClientVersion, v));
            if (version == 0)
                throw new DtlsException(AlertDescription.ProtocolVersion, $"Client version {ProtocolVersions.Name(ch.ClientVersion)} is not supported.");
            NegotiatedVersion = version;

            // RFC 7507 §3: a client that fell back below our highest version is being downgraded.
            if (ch.CipherSuites.Contains(SharpDTLS.CipherSuites.TLS_FALLBACK_SCSV) && ch.ClientVersion != MaximumVersion
                && ProtocolVersions.IsAtLeast(MaximumVersion, ch.ClientVersion))
                throw new DtlsException(AlertDescription.InappropriateFallback, $"Client fell back to {ProtocolVersions.Name(ch.ClientVersion)}.");

            if (!ch.CompressionMethods.Contains((byte)0))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client does not offer null compression.");

            var renegotiationInfo = ch.Extension<RenegotiationInfoExtension>();
            if (renegotiationInfo != null && renegotiationInfo.RenegotiatedConnection.Length != 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Non-empty renegotiation_info in initial handshake.");

            ClientRandom = ch.Random;
            ServerRandom = Dtls12CryptoUtils.GenerateRandom(32);
            // RFC 8446 §4.1.3, RFC 9147 §5.3: a server that also speaks (D)TLS 1.3 marks a lower version in its random, so
            // a 1.3 client can detect a downgrade.
            if (_settings.SignalTls13Downgrade)
                Downgrade.Mark(ServerRandom, version);
            SelectedSrtpProtectionProfile = IsDatagram ? DtlsSrtp.Select(_settings.SrtpProtectionProfiles, ch.Extension<UseSrtpExtension>()?.ProtectionProfiles) : null;

            // Credentials for the requested name come first: the certificate key decides which suites are possible.
            ServerName = ch.Extension<ServerNameExtension>()?.HostName;
            var selected = _settings.CredentialsSelector?.Invoke(new CertificateSelectionContext(ServerName,
                    CertificateSelectionContext.ParseNames(ch.Extension<CertificateAuthoritiesExtension>()?.Names),
                    ch.Extension<SignatureAlgorithmsExtension>()?.Algorithms, ch.Extension<SignatureAlgorithmsCertExtension>()?.Schemes))
                ?? _settings.CertificateSelector?.Invoke(ServerName);
            _serverNameUsed = selected != null && ServerName != null;
            (_keyPair, _certificate, _intermediates, _ocspResponse) = selected != null
                ? (selected.KeyPair, selected.Certificate, selected.IntermediateCertificates, selected.OcspResponse)
                : (_settings.KeyPair, _settings.Certificate, _settings.IntermediateCertificates, _settings.OcspResponse);
            if (ch.Extension<StatusRequestExtension>()?.StatusType != StatusRequestExtension.Ocsp)
                _ocspResponse = null;

            // Certificate types (RFC 7250): without one in common that side cannot use a certificate-based suite.
            _serverCertificateType = RawPublicKeys.Choose(_settings.ServerCertificateTypes,
                RawPublicKeys.Find(ch.Extensions, CertificateTypeExtension.ServerType),
                t => t == CertificateType.RawPublicKey ? _keyPair != null : _certificate != null);
            _clientCertificateType = RawPublicKeys.Choose(_settings.ClientCertificateTypes,
                RawPublicKeys.Find(ch.Extensions, CertificateTypeExtension.ClientType), _ => true);
            if (_serverCertificateType == CertificateType.RawPublicKey)
                _ocspResponse = null;

            // Connection IDs are negotiated afresh in every handshake, resumed ones included (RFC 9146 §3).
            var offeredCid = ch.Extension<ConnectionIdExtension>();
            if (IsDatagram && _settings.UseConnectionIds && offeredCid != null)
            {
                WriteConnectionId = offeredCid.ConnectionId;
                ReadConnectionId = Dtls12CryptoUtils.GenerateRandom(_settings.ConnectionIdLength);
            }

            // ALPN is negotiated per connection, also when resuming (RFC 7301 §3.1).
            ApplicationProtocol = AlpnExtension.Select(_settings.ApplicationProtocols, ch.Extension<AlpnExtension>());

            // Record size limits too, applying to everything we send from the ServerHello on.
            RecordSizeNegotiation.Validate(_settings.RecordSizeLimit, null);
            (PeerRecordLimit, ReceiveRecordLimit, _recordSizeResponse) = RecordSizeNegotiation.Accept(
                ch.Extension<RecordSizeLimitExtension>(), ch.Extension<MaxFragmentLengthExtension>(), _settings.RecordSizeLimit, dtls13: false);

            if (TryResume(ch, version))
                return;

            var serverKey = _keyPair?.Private;
            // Without explicit configuration weak suites (export, DES, NULL, anonymous...) are never selected.
            var preference = _settings.CipherSuites
                ?? SharpDTLS.CipherSuites.All.Where(s => s.Security != CipherSuiteSecurity.Weak).Select(s => s.Id).ToList();
            CipherSuite = preference
                .Where(id => ch.CipherSuites.Contains(id))
                .Select(id => SharpDTLS.CipherSuites.TryGet(id, out var s) ? s : null)
                .FirstOrDefault(s => s != null && s.IsUsableWith(version)
                    && (s.ServerCertificateType == CertificateKeyType.None
                        || (serverKey != null && _serverCertificateType != null && Tls12ClientConnection.KeyMatches(s.ServerCertificateType, serverKey)))
                    && (!s.IsStaticKeyAgreement
                        || (_serverCertificateType == CertificateType.X509 && Tls12ClientConnection.SignedWith(_certificate, s.RequiredCertificateSigner)))
                    && (!s.RequiresPsk || _settings.PskIdentityResolver != null)
                    && (!s.RequiresSrp || (_settings.SrpVerifierProvider != null && ch.Extension<SrpExtension>() != null))
                    && (!s.RequiresPwd || (_settings.PwdCredentialProvider != null && EccPwd.HasUsername(ch, _settings.PwdProtectionKey)
                                           && EccPwd.SelectGroup(ch) != 0)))
                ?? throw (_serverCertificateType == null && serverKey != null
                    ? new DtlsException(AlertDescription.UnsupportedCertificate, "No certificate type in common.")
                    : new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common."));

            _keyExchange = KeyExchanges.CreateServer(CipherSuite, new ServerKeyExchangeContext
            {
                ClientHello = ch,
                ServerPrivateKey = serverKey,
                PskIdentityHint = _settings.PskIdentityHint,
                PskResolver = _settings.PskIdentityResolver,
                SrpVerifierProvider = _settings.SrpVerifierProvider,
                PwdCredentialProvider = _settings.PwdCredentialProvider,
                PwdProtectionKey = _settings.PwdProtectionKey,
                PwdContext = () => Concat(ClientRandom, ServerRandom),
            });

            UseExtendedMasterSecret = ch.Extension<ExtendedMasterSecretExtension>() != null;
            UseEncryptThenMac = CipherSuite.IsCbc && ch.Extension<EncryptThenMacExtension>() != null;

            // A new session is resumable only with the extended master secret (RFC 7627 §5.3): by ticket when the
            // client supports them (RFC 5077, keeping the server stateless), otherwise by session ID.
            _issueTicket = _settings.TicketKeys != null && UseExtendedMasterSecret && ch.Extension<SessionTicketExtension>() != null;
            if (!_issueTicket && _settings.SessionCache != null && UseExtendedMasterSecret)
                _sessionId = Dtls12CryptoUtils.GenerateRandom(32);
        }

        /// <summary>
        /// Accepts the session the client offers by ID when it is cached, uses the negotiated version, a suite
        /// the client still offers and we still allow, and the same encrypt-then-MAC setting (RFC 5246 §7.4.1.2).
        /// </summary>
        private bool TryResume(ClientHelloMessage ch, ushort version)
        {
            // A ticket takes precedence over the session ID; the client generates the ID to detect acceptance
            // (RFC 5077 §3.4).
            Dtls12SessionState session = null;
            bool renewTicket = false;
            byte[] ticket = ch.Extension<SessionTicketExtension>()?.Ticket;
            if (ticket is { Length: > 0 } && _settings.TicketKeys != null)
                session = Dtls12SessionState.Open(_settings.TicketKeys, ticket, out renewTicket);
            if (session == null && ch.SessionId.Length != 0 && _settings.SessionCache != null)
                session = _settings.SessionCache.Find(ch.SessionId);
            if (session == null)
                return false;

            // RFC 6066 §3: never resume a session for another server name.
            if (!string.Equals(session.ServerName, ServerName, StringComparison.OrdinalIgnoreCase))
                return false;

            // RFC 7627 §5.3: an EMS session offered without the extension must not be resumed.
            bool clientEms = ch.Extension<ExtendedMasterSecretExtension>() != null;
            if (!clientEms)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Resumption of an extended master secret session without the extension.");

            if (session.Version != version || !ch.CipherSuites.Contains(session.CipherSuite)
                || !SharpDTLS.CipherSuites.TryGet(session.CipherSuite, out var suite)
                || (_settings.CipherSuites != null ? !_settings.CipherSuites.Contains(session.CipherSuite) : suite.Security == CipherSuiteSecurity.Weak)
                || session.EncryptThenMac != (suite.IsCbc && ch.Extension<EncryptThenMacExtension>() != null)
                || (_settings.RequireClientCertificate && suite.ServerCertificateType != CertificateKeyType.None && session.PeerCertificate == null))
                return false;

            _resumedSession = session;
            _sessionId = ch.SessionId;
            _issueTicket = renewTicket;
            CipherSuite = suite;
            UseExtendedMasterSecret = true;
            UseEncryptThenMac = session.EncryptThenMac;
            if (session.PeerCertificate != null)
                _clientCertificate = Tls12ClientConnection.ParseCertificate(session.PeerCertificate);
            return true;
        }

        private void SendServerFlight()
        {
            var ch = _clientHello;
            BeginFlight();

            var sh = new ServerHelloMessage
            {
                ServerVersion = NegotiatedVersion,
                Random = ServerRandom,
                SessionId = _sessionId,
                CipherSuite = CipherSuite.Id,
            };
            if (ch.Extension<RenegotiationInfoExtension>() != null || ch.CipherSuites.Contains(SharpDTLS.CipherSuites.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                sh.Extensions.Add(new RenegotiationInfoExtension());
            if (UseExtendedMasterSecret)
                sh.Extensions.Add(new ExtendedMasterSecretExtension());
            if (UseEncryptThenMac)
                sh.Extensions.Add(new EncryptThenMacExtension());
            if (ch.Extension<EcPointFormatsExtension>() != null)
                sh.Extensions.Add(new ServerEcPointFormatsExtension());
            if (SelectedSrtpProtectionProfile.HasValue)
                sh.Extensions.Add(new ServerUseSrtpExtension(SelectedSrtpProtectionProfile.Value, ch.Extension<UseSrtpExtension>().MasterKeyIdentifier));
            if (_issueTicket)
                sh.Extensions.Add(new SessionTicketExtension());
            // Acknowledge a server_name we acted on, except when resuming (RFC 6066 §3).
            if (_serverNameUsed && !IsResumed)
                sh.Extensions.Add(new ServerNameExtension());
            if (ApplicationProtocol != null)
                sh.Extensions.Add(new AlpnExtension(new[] { ApplicationProtocol }));
            if (ReadConnectionId != null)
                sh.Extensions.Add(new ConnectionIdExtension(ReadConnectionId));
            if (_recordSizeResponse != null)
                sh.Extensions.Add(_recordSizeResponse);
            // The chosen certificate types, answering the client's lists (RFC 7250 §4.2); client_certificate_type only
            // with a CertificateRequest.
            bool withCertificate = !IsResumed && CipherSuite.ServerCertificateType != CertificateKeyType.None;
            if (withCertificate && RawPublicKeys.Find(ch.Extensions, CertificateTypeExtension.ServerType) != null)
                sh.Extensions.Add(new CertificateTypeExtension(CertificateTypeExtension.ServerType, _serverCertificateType.Value));
            if (withCertificate && _settings.RequireClientCertificate)
            {
                if (_clientCertificateType == null)
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "No client certificate type in common.");
                if (RawPublicKeys.Find(ch.Extensions, CertificateTypeExtension.ClientType) != null)
                    sh.Extensions.Add(new CertificateTypeExtension(CertificateTypeExtension.ClientType, _clientCertificateType.Value));
            }
            // A staple goes with a Certificate, so not when resuming or without one.
            if (IsResumed || CipherSuite.ServerCertificateType == CertificateKeyType.None)
                _ocspResponse = null;
            if (_ocspResponse != null)
                sh.Extensions.Add(new StatusRequestExtension(request: false));
            SendHandshake(HandshakeType.ServerHello, sh.Encode());

            if (IsResumed)
            {
                // Abbreviated handshake: ServerHello, [NewSessionTicket], ChangeCipherSpec, Finished; the client
                // answers with its own ChangeCipherSpec and Finished.
                DeriveKeysFromMasterSecret(_resumedSession.MasterSecret);
                if (_issueTicket)
                    SendNewSessionTicket(_resumedSession);
                SendChangeCipherSpec();
                SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: false));
                ArmRetransmission();
                _state = State.WaitFinished;
                Debug.WriteLine($"{LogPrefix} Resuming session: {ProtocolVersions.Name(NegotiatedVersion)}, {CipherSuite}");
                return;
            }

            bool certificateBased = CipherSuite.ServerCertificateType != CertificateKeyType.None;
            if (certificateBased)
            {
                if (_serverCertificateType == CertificateType.RawPublicKey)
                {
                    SendHandshake(HandshakeType.Certificate, RawPublicKeys.EncodeCertificate(RawPublicKeys.Encode(_keyPair.Public)));
                }
                else
                {
                    var certificate = new CertificateMessage();
                    certificate.Chain.Add(_certificate.GetEncoded());
                    foreach (var intermediate in _intermediates ?? Array.Empty<X509Certificate>())
                        certificate.Chain.Add(intermediate.GetEncoded());
                    SendHandshake(HandshakeType.Certificate, certificate.Encode());
                }
                if (_ocspResponse != null)
                    SendHandshake(HandshakeType.CertificateStatus, StatusRequestExtension.EncodeCertificateStatus(_ocspResponse));
            }

            byte[] serverParams = _keyExchange.CreateServerParams();
            if (serverParams != null)
            {
                var ske = new TlsWriter().WriteBytes(serverParams);
                if (_keyExchange.SignsParams)
                {
                    byte[] signed = Concat(Concat(ClientRandom, ServerRandom), serverParams);
                    byte[] signature = Sign(_keyPair.Private, signed, ch.Extension<SignatureAlgorithmsExtension>()?.Algorithms, out ushort? scheme);
                    if (scheme.HasValue)
                        ske.WriteUInt16(scheme.Value);
                    ske.WriteOpaque16(signature);
                }
                SendHandshake(HandshakeType.ServerKeyExchange, ske.ToArray());
            }

            if (_settings.RequireClientCertificate && certificateBased)
            {
                _certificateRequest = new CertificateRequestMessage { CertificateAuthorities = CertificateSelectionContext.Encode(_settings.ClientCertificateAuthorities) };
                if (CipherSuite.IsStaticKeyAgreement)
                    _certificateRequest.CertificateTypes = new byte[] { 1, 2, 64, 3, 4, 65, 66 }; // also the fixed (EC)DH types
                SendHandshake(HandshakeType.CertificateRequest, _certificateRequest.Encode(NegotiatedVersion));
            }

            SendHandshake(HandshakeType.ServerHelloDone, Array.Empty<byte>());
            ArmRetransmission();
            _state = _certificateRequest != null ? State.WaitClientCertificate : State.WaitClientKeyExchange;
            Debug.WriteLine($"{LogPrefix} Sent server flight: {ProtocolVersions.Name(NegotiatedVersion)}, {CipherSuite}");
        }

        protected override void OnHandshakeMessage(byte type, byte[] body, byte[] message, ushort epoch)
        {
            if (IsHandshakeComplete)
            {
                // A ClientHello after the handshake asks for renegotiation, which is not supported (RFC 5746 §4.4).
                if (type == HandshakeType.ClientHello)
                    SendAlert(AlertDescription.NoRenegotiation, fatal: false);
                else
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected post-handshake message {type}.");
                return;
            }

            switch (_state)
            {
                case State.Start when type == HandshakeType.ClientHello && !IsDatagram:
                    _clientHello = ClientHelloMessage.Decode(body, datagram: false);
                    OnClientHello(message);
                    break;

                case State.WaitClientCertificate when type == HandshakeType.Certificate:
                    StopRetransmission();
                    OnClientCertificate(body, message);
                    break;

                case State.WaitClientKeyExchange when type == HandshakeType.ClientKeyExchange:
                    StopRetransmission();
                    AddToTranscript(message);

                    // An empty ClientKeyExchange with a key agreement certificate is fixed (EC)DH client
                    // authentication: no CertificateVerify follows (RFC 5246 §7.4.8, RFC 8422 §3).
                    bool fixedKeyAgreement = body.Length == 0 && _clientCertificate != null && CipherSuite.IsStaticKeyAgreement;
                    DeriveKeys(fixedKeyAgreement
                        ? _keyExchange.ProcessFixedClientKeyExchange(_clientCertificate.GetPublicKey())
                        : _keyExchange.ProcessClientKeyExchange(body));
                    _state = _clientPublicKey != null && !fixedKeyAgreement ? State.WaitCertificateVerify : State.WaitFinished;
                    break;

                case State.WaitCertificateVerify when type == HandshakeType.CertificateVerify:
                    var cv = CertificateVerifyMessage.Decode(body, NegotiatedVersion);
                    if (!Verify(_clientPublicKey, TranscriptBytes(), cv.SignatureScheme, cv.Signature, _certificateRequest.SignatureAlgorithms))
                        throw new DtlsException(AlertDescription.DecryptError, "Client CertificateVerify signature is invalid.");
                    AddToTranscript(message);
                    _state = State.WaitFinished;
                    break;

                case State.WaitFinished when type == HandshakeType.Finished:
                    OnClientFinished(body, message);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message {type} in state {_state}.");
            }
        }

        private void OnClientCertificate(byte[] body, byte[] message)
        {
            if (_clientCertificateType == CertificateType.RawPublicKey)
            {
                OnClientRawPublicKey(body, message);
                return;
            }

            var certificate = CertificateMessage.Decode(body);
            if (certificate.Chain.Count == 0)
            {
                if (_settings.RequireClientCertificate)
                    throw new DtlsException(AlertDescription.HandshakeFailure, "Client did not send a certificate.");
            }
            else
            {
                _clientCertificate = Tls12ClientConnection.ParseCertificate(certificate.Chain[0]);
                if (!Tls12ClientConnection.CertificateTypeAccepted(_certificateRequest, _clientCertificate.GetPublicKey())
                    && !(CipherSuite.IsStaticKeyAgreement && Tls12ClientConnection.FixedTypeAccepted(_certificateRequest, _clientCertificate)))
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "Client certificate type was not requested.");
                if (_settings.ClientCertificateValidator != null && !_settings.ClientCertificateValidator(_clientCertificate, certificate.Chain))
                    throw new DtlsException(AlertDescription.BadCertificate, "Client certificate was rejected.");
                _clientPublicKey = _clientCertificate.GetPublicKey();
            }

            AddToTranscript(message);
            _state = State.WaitClientKeyExchange;
        }

        private void OnClientRawPublicKey(byte[] body, byte[] message)
        {
            byte[] spki = RawPublicKeys.DecodeCertificate(body);
            if (spki == null)
            {
                if (_settings.RequireClientCertificate)
                    throw new DtlsException(AlertDescription.HandshakeFailure, "Client did not send a raw public key.");
            }
            else
            {
                var key = RawPublicKeys.Decode(spki);
                if (!Tls12ClientConnection.CertificateTypeAccepted(_certificateRequest, key))
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "Client key type was not requested.");
                if (_settings.ClientRawPublicKeyValidator != null && !_settings.ClientRawPublicKeyValidator(spki))
                    throw new DtlsException(AlertDescription.BadCertificate, "Client raw public key was rejected.");
                (_clientPublicKey, ClientRawPublicKey) = (key, spki);
            }

            AddToTranscript(message);
            _state = State.WaitClientKeyExchange;
        }

        private void OnClientFinished(byte[] body, byte[] message)
        {
            if (!IsReadEpochProtected)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Finished before ChangeCipherSpec.");

            if (!CryptographicOperations.FixedTimeEquals(ComputeVerifyData(fromClient: true), body))
                throw new DtlsException(AlertDescription.DecryptError, "Client Finished verification failed.");
            AddToTranscript(message);

            if (IsResumed)
            {
                StopRetransmission();
            }
            else
            {
                // Final flight: not retransmitted on a timer, only when the client retransmits (RFC 6347 §4.2.4).
                BeginFlight();
                if (_issueTicket)
                    SendNewSessionTicket(new Dtls12SessionState(Array.Empty<byte>(), NegotiatedVersion, CipherSuite.Id, MasterSecret,
                        UseEncryptThenMac, _clientCertificate?.GetEncoded(), serverName: ServerName));
                SendChangeCipherSpec();
                SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: false));

                if (_sessionId.Length != 0)
                    _settings.SessionCache.Store(new Dtls12SessionState(_sessionId, NegotiatedVersion, CipherSuite.Id, MasterSecret,
                        UseEncryptThenMac, _clientCertificate?.GetEncoded(), serverName: ServerName));
            }

            _state = State.Connected;
            IsHandshakeComplete = true;
            Debug.WriteLine($"{LogPrefix} Handshake complete with {RemoteEndPoint}");
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        // NewSessionTicket comes right before the server's ChangeCipherSpec (RFC 5077 §3.3).
        private void SendNewSessionTicket(Dtls12SessionState session)
        {
            var keys = _settings.TicketKeys;
            SendHandshake(HandshakeType.NewSessionTicket, new NewSessionTicketMessage
            {
                LifetimeHint = (uint)Math.Min(uint.MaxValue, keys.Lifetime.TotalSeconds),
                Ticket = session.Seal(keys),
            }.Encode());
        }
    }
}
