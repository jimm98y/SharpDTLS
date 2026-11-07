using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol12.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// Client side of a (D)TLS 1.0-1.2 connection (RFC 5246 §7.3, RFC 6347 §4.2): <see cref="Dtls12Client"/> over
    /// datagrams, <see cref="SharpDTLS.Protocol12.TLS12.Tls12Client"/> over a stream.
    /// </summary>
    internal class Tls12ClientConnection : Tls12Connection
    {
        private const int MaxHelloVerifyRequests = 3;

        private enum State
        {
            Start,
            WaitServerHello,
            WaitCertificate,
            WaitServerKeyExchange,
            WaitOptionalServerKeyExchange,
            WaitCertificateRequestOrDone,
            WaitServerHelloDone,
            WaitFinished,
            Connected,
        }

        private State _state = State.Start;
        private ClientHelloMessage _clientHello;
        private int _helloVerifyRequests;
        private X509Certificate _serverCertificate;
        private AsymmetricKeyParameter _serverPublicKey;
        private CertificateType _clientCertificateType;
        private IReadOnlyList<byte[]> _serverChain;
        private bool _statusExpected;
        private bool _statusChecked;
        private IClientKeyExchange _keyExchange;
        private CertificateRequestMessage _certificateRequest;
        private Dtls12SessionState _offeredSession;
        private byte[] _offeredSessionId;
        private byte[] _newSessionId;
        private bool _ticketExpected;
        private NewSessionTicketMessage _newTicket;

        public event EventHandler<EventArgs> HandshakeFinished;
        /// <summary>Raised when the server issues an RFC 5077 session ticket during the handshake.</summary>
        public event EventHandler<NewSessionTicketMessage> NewSessionTicketMessageReceived;

        public Tls12ClientConnection(Action<byte[]> send) : base(isClient: true, send)
        {
        }

        /// <param name="stream">TLS over a reliable byte stream instead of DTLS over datagrams.</param>
        protected Tls12ClientConnection(Action<byte[]> send, bool stream) : base(isClient: true, send, stream)
        {
        }

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        /// <summary>Intermediate CA certificates sent after <see cref="ClientCertificate"/>.</summary>
        public IList<X509Certificate> ClientIntermediateCertificates { get; set; }

        /// <summary>
        /// Chooses the client credentials for a CertificateRequest (the CAs and signature schemes the server accepts);
        /// returning null uses <see cref="ClientCertificate"/> and <see cref="ClientCertificateKeyPair"/>.
        /// </summary>
        public Func<CertificateSelectionContext, CertificateCredentials> ClientCredentialsSelector { get; set; }

        /// <summary>Signature schemes we accept in certificates (signature_algorithms_cert, RFC 8446 §4.2.3); null to not send it.</summary>
        public IList<ushort> SignatureAlgorithmsCert { get; set; }

        /// <summary>Cipher suites to offer in preference order; null for the defaults of the version range.</summary>
        public IList<ushort> CipherSuites { get; set; }

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80, DtlsSrtp.SRTP_AEAD_AES_128_GCM };

        /// <summary>SRTP Master Key Identifier offered in use_srtp (RFC 5764 §4.1.1); null or empty for none, at most 255 bytes.</summary>
        public byte[] SrtpMasterKeyIdentifier { get => _srtpMki; set => _srtpMki = DtlsSrtp.CheckMki(value); }
        private byte[] _srtpMki;

        /// <summary>
        /// Optional server certificate validation. Return false to abort with bad_certificate.
        /// When null, any certificate is accepted (only proof of key possession is checked).
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator { get; set; }

        /// <summary>The server's end-entity certificate once received.</summary>
        public X509Certificate ServerCertificate => _serverCertificate;

        public override X509Certificate PeerCertificate => _serverCertificate;

        /// <summary>
        /// Certificate types we accept from the server, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> the server may authenticate with a bare public key, which
        /// <see cref="ServerRawPublicKeyValidator"/> must then vouch for.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes { get; set; }

        /// <summary>
        /// Certificate types we can authenticate with, in preference order (RFC 7250); null for X.509 only. A raw public key
        /// needs only <see cref="ClientCertificateKeyPair"/>.
        /// </summary>
        public IList<CertificateType> ClientCertificateTypes { get; set; }

        /// <summary>
        /// Checks the server's raw public key (DER SubjectPublicKeyInfo), e.g. against a pinned key; false aborts with
        /// bad_certificate. When null, any key is accepted (only proof of possession is checked).
        /// </summary>
        public Func<byte[], bool> ServerRawPublicKeyValidator { get; set; }

        /// <summary>The server's raw public key (DER SubjectPublicKeyInfo), when it authenticated with one.</summary>
        public byte[] ServerRawPublicKey { get; private set; }

        /// <summary>The negotiated (EC)DHE group, or 0 (RSA key exchange, or custom DH parameters).</summary>
        public ushort NamedGroup => _keyExchange?.Group ?? 0;

        public override ushort NegotiatedGroup => NamedGroup;

        public override byte[] PeerRawPublicKey => ServerRawPublicKey;

        /// <summary>PSK identity for the PSK cipher suites (RFC 4279); setting it enables those suites.</summary>
        public byte[] PskIdentity { get; set; }

        /// <summary>The pre-shared key that goes with <see cref="PskIdentity"/>.</summary>
        public byte[] PskKey { get; set; }

        /// <summary>
        /// Alternative to <see cref="PskIdentity"/>/<see cref="PskKey"/>: maps the server's identity hint
        /// (empty when none was sent) to an identity and key.
        /// </summary>
        public Func<byte[], (byte[] Identity, byte[] Key)> PskProvider { get; set; }

        private Func<byte[], (byte[] Identity, byte[] Key)> EffectivePskProvider
            => PskProvider ?? (PskIdentity != null && PskKey != null ? _ => (PskIdentity, PskKey) : null);

        /// <summary>SRP username (RFC 5054); setting it with <see cref="SrpPassword"/> enables the SRP suites.</summary>
        public byte[] SrpIdentity { get; set; }

        /// <summary>The SRP password that goes with <see cref="SrpIdentity"/>.</summary>
        public byte[] SrpPassword { get; set; }

        private bool HaveSrp => SrpIdentity != null && SrpPassword != null;

        /// <summary>TLS-PWD username (RFC 8492), sent in the clear; setting it with <see cref="PwdPassword"/> enables the ECCPWD suites.</summary>
        public string PwdUsername { get; set; }

        /// <summary>The TLS-PWD password that goes with <see cref="PwdUsername"/>.</summary>
        public string PwdPassword { get; set; }

        /// <summary>
        /// The server's username-protection public key (RFC 8492 §4.3). When set the username is sent
        /// encrypted in pwd_protect instead of in the clear.
        /// </summary>
        public ECPublicKeyParameters PwdProtectionKey { get; set; }

        private bool HavePwd => PwdUsername != null && PwdPassword != null;

        /// <summary>
        /// A session from an earlier handshake to resume (abbreviated handshake, RFC 5246 §7.3). The server may
        /// decline, in which case a full handshake follows.
        /// </summary>
        public Dtls12SessionState ResumptionSession { get; set; }

        /// <summary>The resumable session after the handshake, or null when the server did not make it resumable.</summary>
        public Dtls12SessionState SessionState { get; private set; }

        /// <summary>Whether the server resumed <see cref="ResumptionSession"/>.</summary>
        public override bool IsResumed => _isResumed;
        private bool _isResumed;

        /// <summary>Application protocols to offer with ALPN (RFC 7301), in preference order; null to not offer any.</summary>
        public IList<string> ApplicationProtocols { get; set; }

        /// <summary>Ask the server to staple an OCSP response for its certificate (status_request, RFC 6066 §8).</summary>
        public bool RequestOcspStapling { get; set; }

        /// <summary>
        /// Checks the server's stapled OCSP response once the certificate and the response are known: (DER response, or
        /// null when the server stapled none, and the server's chain as received). Returning false or throwing aborts
        /// the handshake; <see cref="OcspStapleValidator"/> provides one.
        /// </summary>
        public Func<byte[], IReadOnlyList<byte[]>, bool> ServerCertificateStatusValidator { get; set; }

        /// <summary>
        /// Offer record_size_limit (RFC 8449): the most payload per record we accept, 64 to 16384; null to not offer it.
        /// Lets a constrained endpoint keep the server's records small.
        /// </summary>
        public int? RecordSizeLimit { get; set; }

        /// <summary>
        /// Request max_fragment_length (RFC 6066 §4): 512, 1024, 2048 or 4096 bytes per record in both directions; null
        /// to not request it. A server that also supports record_size_limit uses that instead.
        /// </summary>
        public int? MaxFragmentLength { get; set; }

        /// <summary>
        /// Offer connection IDs (RFC 9146) so the association survives our address changing (e.g. NAT rebinding):
        /// a server that agrees gives us a CID to send in every encrypted record.
        /// </summary>
        public bool UseConnectionId { get; set; }

        /// <summary>
        /// Length of the CID we ask the server to send us; 0 (the default) when only our address may change.
        /// </summary>
        public int ConnectionIdLength { get; set; }

        private byte[] _offeredConnectionId;

        /// <summary>Advertise RFC 5077 session tickets (and present the ticket of <see cref="ResumptionSession"/>).</summary>
        public bool UseSessionTickets { get; set; } = true;

        // In an abbreviated handshake the client sends the final flight (RFC 6347 §4.2.4).
        protected override bool ResendFinalFlightOnPeerRetransmit => IsResumed;

        /// <summary>
        /// Set when this handshake is a retry at a lower version after a failed one: sends TLS_FALLBACK_SCSV
        /// so a server supporting a higher version detects the downgrade (RFC 7507 §4).
        /// </summary>
        public bool IsFallback { get; set; }

        /// <summary>Smallest finite-field Diffie-Hellman prime, or SRP group modulus, accepted from a server.</summary>
        public int MinimumDhPrimeBits { get; set; } = 1024;

        public bool ExtendedMasterSecretNegotiated => UseExtendedMasterSecret;
        public bool EncryptThenMacNegotiated => UseEncryptThenMac;
        public byte[] ClientRandomBytes => ClientRandom;
        public byte[] ServerRandomBytes => ServerRandom;

        public void BeginHandshake() => Locked(() =>
        {
            if (_state != State.Start)
                throw new InvalidOperationException("The handshake has already started.");

            ClientRandom = Dtls12CryptoUtils.GenerateRandom(32);
            SendClientHello(Array.Empty<byte>());
        });

        private void SendClientHello(byte[] cookie)
        {
            var ch = BuildClientHello(cookie);

            // The initial ClientHello and HelloVerifyRequest are not part of the transcript (RFC 6347 §4.2.6).
            ResetTranscript();
            BeginFlight();
            SendHandshake(HandshakeType.ClientHello, ch.Encode(IsDatagram));
            ArmRetransmission();
            _state = State.WaitServerHello;
            Debug.WriteLine($"{LogPrefix} Sent ClientHello (cookie {cookie.Length} bytes)");
        }

        /// <summary>
        /// For a client that also offers (D)TLS 1.3: the ClientHello this engine would send, for merging into the 1.3 one.
        /// <see cref="AdoptClientHello"/> (TLS) or <see cref="AdoptHandoff"/> (DTLS) then takes the merged message as the
        /// one sent.
        /// </summary>
        internal ClientHelloMessage PrepareClientHello()
        {
            if (_state != State.Start)
                throw new InvalidOperationException("The handshake has already started.");
            ClientRandom = Dtls12CryptoUtils.GenerateRandom(32);
            return BuildClientHello(Array.Empty<byte>());
        }

        /// <summary>The ClientHello actually sent (TLS form, 4-byte header): it is ours from now on.</summary>
        internal void AdoptClientHello(byte[] message) => Locked(() =>
        {
            _clientHello = ClientHelloMessage.Decode(message.AsSpan(4).ToArray(), datagram: false);
            ClientRandom = _clientHello.Random; // the one sent, also when an inspector replaced it
            ResetTranscript();
            AddToTranscript(message);
            _state = State.WaitServerHello;
        });

        /// <summary>
        /// DTLS: the 1.3 engine sent the merged ClientHello and got a DTLS 1.2-or-lower ServerHello. Continues from its
        /// last ClientHello (12-byte header) and sequence numbers; the handoff's records are then processed.
        /// </summary>
        internal void AdoptHandoff(SharpDTLS.Protocol13.LegacyDatagramHandoff handoff) => Locked(() =>
        {
            _clientHello = ClientHelloMessage.Decode(handoff.ClientHello.AsSpan(12).ToArray(), datagram: true);
            ClientRandom = _clientHello.Random;
            // The 1.3 engine's connection ID went out; it is the one the server answers.
            _offeredConnectionId = _clientHello.Extension<ConnectionIdExtension>()?.ConnectionId;
            SetInitialRecordSequence((ulong)handoff.NextRecordSequence);
            NextSendMessageSeq = handoff.NextSendMessageSeq;
            NextReceiveMessageSeq = handoff.ServerHelloMessageSeq;
            ResetTranscript();
            AddToTranscript(handoff.ClientHello);
            _state = State.WaitServerHello;
        });

        /// <summary>An inspector edited our ClientHello: the random, session ID and offered suites are the ones sent.</summary>
        private protected override void OnSentHandshakeEdited(byte type, byte[] body)
        {
            if (type != HandshakeType.ClientHello)
                return;
            var sent = ClientHelloMessage.Decode(body, IsDatagram);
            _clientHello = sent;
            ClientRandom = sent.Random;
            if (_offeredSessionId != null)
                _offeredSessionId = sent.SessionId;
        }

        private ClientHelloMessage BuildClientHello(byte[] cookie)
        {
            bool havePsk = EffectivePskProvider != null;
            var offered = (CipherSuites ?? SharpDTLS.CipherSuites.DefaultFor(MinimumVersion, MaximumVersion, includePsk: havePsk, includeSrp: HaveSrp, includePwd: HavePwd))
                .Where(id => SharpDTLS.CipherSuites.TryGet(id, out var s) && (s.IsUsableWith(MaximumVersion) || s.IsUsableWith(MinimumVersion))
                             && (havePsk || !s.RequiresPsk) && (HaveSrp || !s.RequiresSrp) && (HavePwd || !s.RequiresPwd))
                .ToList();
            var offeredSuites = offered.Select(id => SharpDTLS.CipherSuites.Get(id)).ToList();
            if (offered.Count == 0)
                throw new InvalidOperationException("No configured cipher suite is usable with the configured versions.");

            // Offer a session only within the version range and with its suite still offered. A ticket goes with a
            // client-generated session ID, which the server echoes when it accepts the ticket (RFC 5077 §3.4).
            // The ID is kept across a HelloVerifyRequest so both ClientHellos offer the same session.
            var resumable = ResumptionSession;
            if (resumable != null && !string.Equals(resumable.ServerName, ServerName, StringComparison.OrdinalIgnoreCase))
                resumable = null; // RFC 6066 §3: a session belongs to one server name
            bool presentTicket = resumable?.Ticket != null && UseSessionTickets;
            _offeredSession = resumable != null && (presentTicket || resumable.SessionId.Length != 0) && offered.Contains(resumable.CipherSuite)
                              && ProtocolVersions.IsAtLeast(resumable.Version, MinimumVersion) && ProtocolVersions.IsAtLeast(MaximumVersion, resumable.Version)
                ? resumable : null;
            if (_offeredSession == null)
                _offeredSessionId = null;
            else if (_offeredSessionId == null)
                _offeredSessionId = presentTicket ? Dtls12CryptoUtils.GenerateRandom(32) : _offeredSession.SessionId;

            var ch = new ClientHelloMessage
            {
                ClientVersion = MaximumVersion,
                Random = ClientRandom,
                SessionId = _offeredSessionId ?? Array.Empty<byte>(),
                Cookie = cookie,
                CipherSuites = IsFallback ? offered.Append(SharpDTLS.CipherSuites.TLS_FALLBACK_SCSV).ToList() : offered,
            };

            // Supported groups: elliptic curves, plus the RFC 7919 FFDHE groups when DHE suites are offered.
            var groups = EcdheGroups.Supported.ToList();
            if (offeredSuites.Any(s => s.KeyExchange is KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_DSS
                                      or KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE))
                groups.AddRange(FfdheGroups.Supported);
            if (offeredSuites.Any(s => s.RequiresPwd))
                groups.AddRange(EccPwd.Groups.Where(g => !groups.Contains(g)));
            ch.Extensions.Add(new SupportedGroupsExtension(groups.ToArray()));
            ch.Extensions.Add(new EcPointFormatsExtension(new byte[] { 0 })); // uncompressed
            if (ProtocolVersions.Level(MaximumVersion) >= 3)
                ch.Extensions.Add(new SignatureAlgorithmsExtension(Dtls12Signatures.Supported));
            if (offeredSuites.Any(s => s.IsCbc))
                ch.Extensions.Add(new EncryptThenMacExtension());
            ch.Extensions.Add(new ExtendedMasterSecretExtension());
            ch.Extensions.Add(new RenegotiationInfoExtension());
            if (IsDatagram && SrtpProtectionProfiles != null && SrtpProtectionProfiles.Length > 0)
                ch.Extensions.Add(new UseSrtpExtension(SrtpProtectionProfiles, SrtpMasterKeyIdentifier));
            if (ServerName != null)
                ch.Extensions.Add(new ServerNameExtension(ServerName));
            if (ApplicationProtocols is { Count: > 0 })
                ch.Extensions.Add(new AlpnExtension(ApplicationProtocols));
            ch.Extensions.AddRange(RecordSizeNegotiation.Offer(RecordSizeLimit, MaxFragmentLength, dtls13: false));
            if (RequestOcspStapling)
                ch.Extensions.Add(new StatusRequestExtension(request: true));
            if (RawPublicKeys.Offer(CertificateTypeExtension.ServerType, ServerCertificateTypes) is { } serverTypes)
                ch.Extensions.Add(serverTypes);
            if (SignatureAlgorithmsCert is { Count: > 0 })
                ch.Extensions.Add(new SignatureAlgorithmsCertExtension(SignatureAlgorithmsCert));
            if (RawPublicKeys.Offer(CertificateTypeExtension.ClientType, ClientCertificateTypes) is { } clientTypes)
                ch.Extensions.Add(clientTypes);
            if (UseConnectionId && IsDatagram)
            {
                _offeredConnectionId ??= Dtls12CryptoUtils.GenerateRandom(ConnectionIdLength);
                ch.Extensions.Add(new ConnectionIdExtension(_offeredConnectionId));
            }
            if (UseSessionTickets)
                ch.Extensions.Add(new SessionTicketExtension(presentTicket && _offeredSession != null ? _offeredSession.Ticket : null));
            if (offeredSuites.Any(s => s.RequiresSrp))
                ch.Extensions.Add(new SrpExtension(SrpIdentity));
            if (offeredSuites.Any(s => s.RequiresPwd))
                ch.Extensions.Add(PwdProtectionKey != null
                    ? new PwdProtectExtension(EccPwd.ProtectUsername(PwdUsername, PwdProtectionKey, new Org.BouncyCastle.Security.SecureRandom()))
                    : new PwdClearExtension(EccPwd.PrepareOpaqueString(PwdUsername)));

            _clientHello = ch;
            return ch;
        }

        protected override void OnHandshakeMessage(byte type, byte[] body, byte[] message, ushort epoch)
        {
            if (IsHandshakeComplete)
            {
                OnPostHandshakeMessage(type, body);
                return;
            }

            if (type == HandshakeType.CertificateStatus)
            {
                // Only right after the Certificate, and only when the ServerHello announced it.
                if (!_statusExpected || _serverChain == null || _statusChecked)
                    throw new DtlsException(AlertDescription.UnexpectedMessage, "Unexpected CertificateStatus.");
                OcspResponse = StatusRequestExtension.DecodeCertificateStatus(body);
                AddToTranscript(message);
                CheckCertificateStatus();
                return;
            }
            // The server may announce a CertificateStatus and still send none.
            if (_serverChain != null && !_statusChecked)
                CheckCertificateStatus();

            switch (_state)
            {
                case State.WaitServerHello when type == HandshakeType.HelloVerifyRequest && IsDatagram:
                    OnHelloVerifyRequest(body);
                    break;

                case State.WaitServerHello when type == HandshakeType.ServerHello:
                    OnServerHello(body, message);
                    break;

                case State.WaitCertificate when type == HandshakeType.Certificate:
                    OnCertificate(body, message);
                    break;

                case State.WaitServerKeyExchange when type == HandshakeType.ServerKeyExchange:
                case State.WaitOptionalServerKeyExchange when type == HandshakeType.ServerKeyExchange:
                    OnServerKeyExchange(body, message);
                    break;

                case State.WaitCertificateRequestOrDone when type == HandshakeType.CertificateRequest:
                case State.WaitOptionalServerKeyExchange when type == HandshakeType.CertificateRequest:
                    _certificateRequest = CertificateRequestMessage.Decode(body, NegotiatedVersion);
                    AddToTranscript(message);
                    _state = State.WaitServerHelloDone;
                    break;

                case State.WaitCertificateRequestOrDone when type == HandshakeType.ServerHelloDone:
                case State.WaitOptionalServerKeyExchange when type == HandshakeType.ServerHelloDone:
                case State.WaitServerHelloDone when type == HandshakeType.ServerHelloDone:
                    if (body.Length != 0)
                        throw new DtlsException(AlertDescription.DecodeError, "ServerHelloDone must be empty.");
                    AddToTranscript(message);
                    SendFinalFlight();
                    break;

                case State.WaitFinished when type == HandshakeType.NewSessionTicket && _ticketExpected && _newTicket == null:
                    _newTicket = NewSessionTicketMessage.Decode(body);
                    AddToTranscript(message);
                    break;

                case State.WaitFinished when type == HandshakeType.Finished:
                    OnServerFinished(body, message);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message {type} in state {_state}.");
            }
        }

        private void OnHelloVerifyRequest(byte[] body)
        {
            if (++_helloVerifyRequests > MaxHelloVerifyRequests)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Too many HelloVerifyRequests.");

            StopRetransmission();
            var hvr = HelloVerifyRequestMessage.Decode(body);
            if ((hvr.ServerVersion >> 8) != 0xFE)
                throw new DtlsException(AlertDescription.ProtocolVersion, "HelloVerifyRequest is not DTLS.");

            Debug.WriteLine($"{LogPrefix} Received HelloVerifyRequest (cookie {hvr.Cookie.Length} bytes)");
            SendClientHello(hvr.Cookie);
        }

        private void OnServerHello(byte[] body, byte[] message)
        {
            StopRetransmission();
            var sh = ServerHelloMessage.Decode(body);

            // The server's version must lie within [MinimumVersion, MaximumVersion].
            if (!ProtocolVersions.Legacy(IsDatagram).Contains(sh.ServerVersion)
                || !ProtocolVersions.IsAtLeast(sh.ServerVersion, MinimumVersion)
                || !ProtocolVersions.IsAtLeast(MaximumVersion, sh.ServerVersion))
                throw new DtlsException(AlertDescription.ProtocolVersion, $"Server selected unsupported version {ProtocolVersions.Name(sh.ServerVersion)}.");

            if (!_clientHello.CipherSuites.Contains(sh.CipherSuite)
                || !SharpDTLS.CipherSuites.TryGet(sh.CipherSuite, out var suite)
                || !suite.IsUsableWith(sh.ServerVersion))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected cipher suite 0x{sh.CipherSuite:X4}, which was not offered.");

            if (sh.CompressionMethod != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Server selected compression.");

            var renegotiationInfo = sh.Extension<RenegotiationInfoExtension>();
            if (renegotiationInfo != null && renegotiationInfo.RenegotiatedConnection.Length != 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Non-empty renegotiation_info in initial handshake.");

            if (sh.Extension<EncryptThenMacExtension>() != null)
            {
                // RFC 7366 §3: only for CBC suites, and only if offered.
                if (!suite.IsCbc || _clientHello.Extension<EncryptThenMacExtension>() == null)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Unexpected encrypt_then_mac.");
                UseEncryptThenMac = true;
            }

            UseExtendedMasterSecret = sh.Extension<ExtendedMasterSecretExtension>() != null;

            if (sh.Extension<ServerNameExtension>() != null && ServerName == null)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited server_name extension.");
            ApplicationProtocol = AlpnExtension.Accept(ApplicationProtocols, sh.Extension<AlpnExtension>());
            (PeerRecordLimit, ReceiveRecordLimit) = RecordSizeNegotiation.Complete(sh.Extension<RecordSizeLimitExtension>(),
                sh.Extension<MaxFragmentLengthExtension>(), RecordSizeLimit, MaxFragmentLength, dtls13: false);

            var serverCid = sh.Extension<ConnectionIdExtension>();
            if (serverCid != null)
            {
                if (_offeredConnectionId == null)
                    throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited connection_id extension.");
                WriteConnectionId = serverCid.ConnectionId;
                ReadConnectionId = _offeredConnectionId;
            }

            // Certificate types (RFC 7250): no answer means X.509.
            // Checked against our list when a Certificate arrives: resumption and PSK suites have none.
            ServerCertificateType = RawPublicKeys.Accept(ServerCertificateTypes, RawPublicKeys.Find(sh.Extensions, CertificateTypeExtension.ServerType), requireSupport: false);
            _clientCertificateType = RawPublicKeys.Accept(ClientCertificateTypes, RawPublicKeys.Find(sh.Extensions, CertificateTypeExtension.ClientType), requireSupport: false);

            // An empty status_request announces a CertificateStatus after the Certificate (RFC 6066 §8).
            _statusExpected = sh.Extension<StatusRequestExtension>() != null;
            (_serverChain, _statusChecked, OcspResponse) = (null, false, null);
            if (_statusExpected && !RequestOcspStapling)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited status_request extension.");

            // An empty SessionTicket extension announces a NewSessionTicket before the server's ChangeCipherSpec.
            _ticketExpected = sh.Extension<SessionTicketExtension>() != null;
            if (_ticketExpected && _clientHello.Extension<SessionTicketExtension>() == null)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited SessionTicket extension.");

            var srtp = sh.Extension<ServerUseSrtpExtension>();
            if (srtp != null)
            {
                if (!IsDatagram || SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SelectedProfile))
                    throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected SRTP profile 0x{srtp.SelectedProfile:X4}, which was not offered.");
                SelectedSrtpMki = DtlsSrtp.AcceptServerMki(SrtpMasterKeyIdentifier, srtp.MasterKeyIdentifier);
                SelectedSrtpProtectionProfile = srtp.SelectedProfile;
            }

            NegotiatedVersion = sh.ServerVersion;
            CipherSuite = suite;
            ServerRandom = sh.Random;
            AddToTranscript(message);
            Debug.WriteLine($"{LogPrefix} ServerHello: {ProtocolVersions.Name(NegotiatedVersion)}, {suite}");

            if (_offeredSession != null && sh.SessionId.AsSpan().SequenceEqual(_offeredSessionId))
            {
                // Abbreviated handshake: the server's ChangeCipherSpec and Finished follow (RFC 5246 §7.3).
                var session = _offeredSession;
                if (sh.ServerVersion != session.Version || sh.CipherSuite != session.CipherSuite || UseEncryptThenMac != session.EncryptThenMac)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Server resumed the session with different parameters.");
                // RFC 7627 §5.3: resumable sessions use the extended master secret, so the ServerHello must too.
                if (!UseExtendedMasterSecret)
                    throw new DtlsException(AlertDescription.HandshakeFailure, "Server resumed without the extended master secret.");

                _isResumed = true;
                SessionState = session;
                if (session.PeerCertificate != null)
                {
                    _serverCertificate = ParseCertificate(session.PeerCertificate);
                    _serverPublicKey = _serverCertificate.GetPublicKey();
                }
                DeriveKeysFromMasterSecret(session.MasterSecret);
                _state = State.WaitFinished;
                return;
            }

            if (sh.SessionId.Length != 0 && UseExtendedMasterSecret)
                _newSessionId = sh.SessionId;

            // Suites authenticated by a pre-shared key alone send no Certificate.
            if (suite.ServerCertificateType == CertificateKeyType.None)
                CreateKeyExchange();
            else
                _state = State.WaitCertificate;
        }

        private void OnCertificate(byte[] body, byte[] message)
        {
            if (ServerCertificateType == CertificateType.RawPublicKey)
            {
                OnServerRawPublicKey(body, message);
                return;
            }

            if (ServerCertificateTypes != null && !ServerCertificateTypes.Contains(CertificateType.X509))
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "The server did not agree to a raw public key.");
            var certificate = CertificateMessage.Decode(body);
            if (certificate.Chain.Count == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Server sent an empty Certificate.");

            _serverCertificate = ParseCertificate(certificate.Chain[0]);
            _serverPublicKey = _serverCertificate.GetPublicKey();
            if (!KeyMatches(CipherSuite.ServerCertificateType, _serverPublicKey))
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "Server certificate key does not match the cipher suite.");
            if (ServerCertificateValidator != null && !ServerCertificateValidator(_serverCertificate, certificate.Chain))
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate was rejected.");
            _serverChain = certificate.Chain;

            AddToTranscript(message);
            CreateKeyExchange();
        }

        private void OnServerRawPublicKey(byte[] body, byte[] message)
        {
            byte[] spki = RawPublicKeys.DecodeCertificate(body)
                ?? throw new DtlsException(AlertDescription.DecodeError, "Server sent an empty raw public key.");
            _serverPublicKey = RawPublicKeys.Decode(spki);
            if (!KeyMatches(CipherSuite.ServerCertificateType, _serverPublicKey) || CipherSuite.IsStaticKeyAgreement)
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "Server key does not match the cipher suite.");
            if (ServerRawPublicKeyValidator != null && !ServerRawPublicKeyValidator(spki))
                throw new DtlsException(AlertDescription.BadCertificate, "Server raw public key was rejected.");
            ServerRawPublicKey = spki;

            AddToTranscript(message);
            CreateKeyExchange();
        }

        private void CheckCertificateStatus()
        {
            _statusChecked = true;
            if (ServerCertificateStatusValidator != null && !ServerCertificateStatusValidator(OcspResponse, _serverChain))
                throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The server's certificate status was rejected.");
        }

        private void CreateKeyExchange()
        {
            _keyExchange = KeyExchanges.CreateClient(CipherSuite, new ClientKeyExchangeContext
            {
                ClientHelloVersion = _clientHello.ClientVersion,
                ServerPublicKey = _serverPublicKey,
                MinimumDhPrimeBits = MinimumDhPrimeBits,
                PskProvider = EffectivePskProvider,
                SrpIdentity = SrpIdentity,
                SrpPassword = SrpPassword,
                PwdUsername = PwdUsername,
                PwdPassword = PwdPassword,
                PwdContext = () => Concat(ClientRandom, ServerRandom),
            });

            _state = _keyExchange.ServerKeyExchange switch
            {
                ServerKeyExchangeRequirement.Required => State.WaitServerKeyExchange,
                ServerKeyExchangeRequirement.Optional => State.WaitOptionalServerKeyExchange,
                _ => State.WaitCertificateRequestOrDone,
            };
        }

        private void OnServerKeyExchange(byte[] body, byte[] message)
        {
            var r = new TlsReader(body);
            _keyExchange.ReadServerParams(r);
            byte[] serverParams = body.AsSpan(0, r.Position).ToArray();

            if (_keyExchange.ServerParamsSigned)
            {
                // digitally-signed struct: [SignatureAndHashAlgorithm (DTLS 1.2)] signature<0..2^16-1>
                ushort? scheme = IsDtls12 ? r.ReadUInt16() : null;
                byte[] signature = r.ReadOpaque16();
                byte[] signed = Concat(Concat(ClientRandom, ServerRandom), serverParams);
                if (!Verify(_serverPublicKey, signed, scheme, signature, Dtls12Signatures.Supported))
                    throw new DtlsException(AlertDescription.DecryptError, "ServerKeyExchange signature is invalid.");
            }
            r.EnsureEnd();

            AddToTranscript(message);
            _state = State.WaitCertificateRequestOrDone;
        }

        // The credentials for the server's CertificateRequest: the selector's choice, or the configured ones.
        private (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate, IList<X509Certificate> Intermediates) ResolveClientCredentials()
        {
            if (_certificateRequest != null && ClientCredentialsSelector != null)
            {
                var chosen = ClientCredentialsSelector(new CertificateSelectionContext(null,
                    CertificateSelectionContext.ParseNames(_certificateRequest.CertificateAuthorities), _certificateRequest.SignatureAlgorithms, null));
                if (chosen != null)
                    return (chosen.KeyPair, chosen.Certificate, chosen.IntermediateCertificates);
            }
            return (ClientCertificateKeyPair, ClientCertificate, ClientIntermediateCertificates);
        }

        private void SendFinalFlight()
        {
            BeginFlight();

            // Certificate (only when requested). Send ours only if its type and a signature scheme are accepted,
            // or, with static (EC)DH, if it holds a key agreement key on the server's parameters (fixed (EC)DH).
            bool authenticate = false;
            var (keyPair, clientCertificate, intermediates) = ResolveClientCredentials();
            bool fixedKeyAgreement = false;
            bool rawPublicKey = _clientCertificateType == CertificateType.RawPublicKey;
            if (_certificateRequest != null && rawPublicKey && keyPair != null)
            {
                var key = keyPair.Private;
                authenticate = CertificateTypeAccepted(_certificateRequest, key)
                    && (!IsDtls12 || Dtls12Signatures.SelectScheme(key, _certificateRequest.SignatureAlgorithms) != null);
            }
            else if (_certificateRequest != null && !rawPublicKey && clientCertificate != null && keyPair != null)
            {
                var key = keyPair.Private;
                fixedKeyAgreement = _keyExchange is IFixedDhClientKeyExchange fixedDh && fixedDh.SupportsFixedClientKey(key)
                    && FixedTypeAccepted(_certificateRequest, clientCertificate);
                authenticate = !fixedKeyAgreement && CertificateTypeAccepted(_certificateRequest, key)
                    && (!IsDtls12 || Dtls12Signatures.SelectScheme(key, _certificateRequest.SignatureAlgorithms) != null);
            }

            if (_certificateRequest != null && rawPublicKey)
            {
                SendHandshake(HandshakeType.Certificate, RawPublicKeys.EncodeCertificate(authenticate ? RawPublicKeys.Encode(keyPair.Public) : null));
            }
            else if (_certificateRequest != null)
            {
                var certificate = new CertificateMessage();
                if (authenticate || fixedKeyAgreement)
                {
                    certificate.Chain.Add(clientCertificate.GetEncoded());
                    LocalCertificate = clientCertificate;
                    foreach (var intermediate in intermediates ?? Array.Empty<X509Certificate>())
                        certificate.Chain.Add(intermediate.GetEncoded());
                }
                SendHandshake(HandshakeType.Certificate, certificate.Encode());
            }

            byte[] preMasterSecret;
            byte[] clientKeyExchange = fixedKeyAgreement
                ? ((IFixedDhClientKeyExchange)_keyExchange).CreateFixedClientKeyExchange(keyPair.Private, out preMasterSecret)
                : _keyExchange.CreateClientKeyExchange(out preMasterSecret);
            SendHandshake(HandshakeType.ClientKeyExchange, clientKeyExchange);
            DeriveKeys(preMasterSecret);

            if (authenticate)
            {
                byte[] signature = Sign(keyPair.Private, TranscriptBytes(), _certificateRequest.SignatureAlgorithms, out ushort? scheme);
                SendHandshake(HandshakeType.CertificateVerify, new CertificateVerifyMessage { SignatureScheme = scheme, Signature = signature }.Encode(NegotiatedVersion));
            }

            SendChangeCipherSpec();
            SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: true));

            // Retransmitted until the server's Finished arrives (its ChangeCipherSpec alone is not enough).
            ArmRetransmission();
            _state = State.WaitFinished;
        }

        private void OnServerFinished(byte[] body, byte[] message)
        {
            if (!IsReadEpochProtected)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Finished before ChangeCipherSpec.");

            if (!CryptographicOperations.FixedTimeEquals(ComputeVerifyData(fromClient: false), body))
                throw new DtlsException(AlertDescription.DecryptError, "Server Finished verification failed.");

            AddToTranscript(message);
            StopRetransmission();

            if (_ticketExpected && _newTicket == null)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Missing NewSessionTicket.");

            if (IsResumed)
            {
                // Final flight of an abbreviated handshake: resent only when the server retransmits.
                BeginFlight();
                SendChangeCipherSpec();
                SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: true));
            }
            else if (_newSessionId != null || (_newTicket is { Ticket.Length: > 0 } && UseExtendedMasterSecret))
            {
                SessionState = new Dtls12SessionState(_newSessionId ?? Array.Empty<byte>(), NegotiatedVersion, CipherSuite.Id, MasterSecret,
                    UseEncryptThenMac, _serverCertificate?.GetEncoded(), serverName: ServerName);
            }

            // A zero-length ticket means the server changed its mind (RFC 5077 §3.3).
            if (SessionState != null && _newTicket is { Ticket.Length: > 0 })
            {
                SessionState = SessionState.WithTicket(_newTicket.Ticket, _newTicket.LifetimeHint);
                var ticket = _newTicket;
                RaiseEvent(() => NewSessionTicketMessageReceived?.Invoke(this, ticket));
            }

            _state = State.Connected;
            IsHandshakeComplete = true;
            Debug.WriteLine($"{LogPrefix} Handshake complete{(IsResumed ? " (resumed)" : "")}");
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        private void OnPostHandshakeMessage(byte type, byte[] body)
        {
            switch (type)
            {
                case HandshakeType.HelloRequest:
                    // Renegotiation is not supported (RFC 5746 §4.5): decline with a warning.
                    SendAlert(AlertDescription.NoRenegotiation, fatal: false);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected post-handshake message {type}.");
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────────────────────

        internal static X509Certificate ParseCertificate(byte[] der)
        {
            try
            {
                return new X509CertificateParser().ReadCertificate(der)
                    ?? throw new DtlsException(AlertDescription.BadCertificate, "Certificate could not be parsed.");
            }
            catch (DtlsException) { throw; }
            catch (Exception ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "Certificate could not be parsed.", ex);
            }
        }

        internal static bool KeyMatches(CertificateKeyType type, AsymmetricKeyParameter key) => type switch
        {
            CertificateKeyType.Rsa => key is RsaKeyParameters,
            CertificateKeyType.Ecdsa => key is ECKeyParameters,
            CertificateKeyType.Dsa => key is DsaKeyParameters,
            CertificateKeyType.Dh => key is DHKeyParameters,
            CertificateKeyType.Ecdh => key is ECKeyParameters,
            _ => true,
        };

        /// <summary>Whether <paramref name="certificate"/> is signed with the algorithm family <paramref name="signer"/>.</summary>
        internal static bool SignedWith(X509Certificate certificate, CertificateKeyType signer)
        {
            string algorithm = certificate.SigAlgName.ToUpperInvariant();
            return signer switch
            {
                CertificateKeyType.None => true,
                CertificateKeyType.Ecdsa => algorithm.Contains("ECDSA"),
                CertificateKeyType.Dsa => algorithm.Contains("DSA") && !algorithm.Contains("ECDSA"),
                CertificateKeyType.Rsa => algorithm.Contains("RSA"),
                _ => false,
            };
        }

        // RFC 5246 §7.4.4 / RFC 8422 §5.5 fixed key agreement certificate types:
        // rsa_fixed_dh(3), dss_fixed_dh(4), rsa_fixed_ecdh(65), ecdsa_fixed_ecdh(66), chosen by key and issuer signature.
        internal static bool FixedTypeAccepted(CertificateRequestMessage request, X509Certificate certificate)
        {
            var key = certificate.GetPublicKey();
            byte type = key switch
            {
                DHKeyParameters when SignedWith(certificate, CertificateKeyType.Rsa) => 3,
                DHKeyParameters when SignedWith(certificate, CertificateKeyType.Dsa) => 4,
                ECKeyParameters when SignedWith(certificate, CertificateKeyType.Rsa) => 65,
                ECKeyParameters when SignedWith(certificate, CertificateKeyType.Ecdsa) => 66,
                _ => 0,
            };
            return type != 0 && request.CertificateTypes.Contains(type);
        }

        // RFC 5246 §7.4.4 ClientCertificateType: rsa_sign(1), dss_sign(2), ecdsa_sign(64)
        internal static bool CertificateTypeAccepted(CertificateRequestMessage request, AsymmetricKeyParameter key)
            => key is RsaKeyParameters ? request.CertificateTypes.Contains((byte)1)
             : key is DsaKeyParameters ? request.CertificateTypes.Contains((byte)2)
             : key is ECKeyParameters ? request.CertificateTypes.Contains((byte)64)
             : false;
    }
}
