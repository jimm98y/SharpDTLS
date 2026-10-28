using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.Protocol13.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// The (D)TLS 1.3 client handshake (RFC 8446, RFC 9147), over datagrams (<see cref="Dtls13Client"/>) or a stream
    /// (<see cref="SharpDTLS.Protocol13.TLS13.Tls13Client"/>).
    /// </summary>
    internal abstract class Tls13ClientConnection : Tls13Connection
    {
        private readonly Dictionary<ushort, Dtls13Groups.ClientKeyShare> _keyShares = new();

        private enum State
        {
            Start,
            HandedOff, // a (D)TLS 1.2-or-lower ServerHello: the legacy engine took over
            WaitServerHello,
            WaitEncryptedExtensions,
            WaitCertificateOrCertificateRequest,
            WaitCertificate,
            WaitCertificateVerify,
            WaitFinished,
            Connected,
        }

        private State _state = State.Start;
        private ClientHelloDatagram _clientHello;
        private bool _receivedHelloRetryRequest;
        private ushort _hrrCipherSuite;
        private CertificateRequestDatagram _certificateRequest;
        private X509Certificate _serverCertificate;
        private AsymmetricKeyParameter _serverPublicKey;
        private CertificateType _clientCertificateType;
        private readonly List<OfferedPsk> _offeredPsks = new();
        private OfferedPsk _selectedPsk;
        private bool _earlyDataOffered;

        /// <summary>A PSK offered in pre_shared_key: a resumption ticket or the external PSK.</summary>
        private sealed record OfferedPsk(byte[] Identity, uint ObfuscatedAge, byte[] Key, Dtls13CipherSuite HashSuite,
            Dtls13SessionTicket Ticket);

        public event EventHandler<EventArgs> HandshakeFinished;

        /// <summary>Application protocols to offer with ALPN (RFC 7301), in preference order; null to not offer any.</summary>
        public IList<string> ApplicationProtocols { get; set; }

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
        /// Certificate compression algorithms we accept (RFC 8879), in preference order, e.g.
        /// <see cref="CertificateCompression.Supported"/>; null to not offer compression. Also used to compress our own
        /// certificate when the server's CertificateRequest allows it.
        /// </summary>
        public IList<ushort> CertificateCompressionAlgorithms { get; set; }

        /// <summary>
        /// Let the server ask for our certificate after the handshake (post_handshake_auth, RFC 8446 §4.6.2). Requests are
        /// answered with <see cref="ClientCertificate"/> (or a raw public key) and its key, or with no certificate.
        /// </summary>
        public bool AllowPostHandshakeAuthentication { get; set; }

        /// <summary>The server asked for our certificate after the handshake; raised after the answer was sent.</summary>
        public event EventHandler PostHandshakeCertificateRequested;

        /// <summary>Ask the server to staple an OCSP response for its certificate (status_request, RFC 8446 §4.4.2.1).</summary>
        public bool RequestOcspStapling { get; set; }

        /// <summary>
        /// Checks the server's stapled OCSP response after its certificate: (DER response, or null when the server
        /// stapled none, and the server's chain as received). Returning false or throwing aborts the handshake;
        /// <see cref="OcspStapleValidator"/> provides one.
        /// </summary>
        public Func<byte[], IReadOnlyList<byte[]>, bool> ServerCertificateStatusValidator { get; set; }

        /// <summary>
        /// Offer connection IDs (RFC 9147 §9) so the association survives our address changing: a server that agrees
        /// gives us a CID to send in every record.
        /// </summary>
        public bool UseConnectionId { get; set; }

        /// <summary>Length of the CID we ask the server to send us; 0 (the default) when only our address may change.</summary>
        public int ConnectionIdLength { get; set; }

        private byte[] _offeredConnectionId;

        /// <summary>
        /// Groups to send key shares for in the first ClientHello, in preference order (each must be in
        /// <see cref="SupportedGroups"/>). More shares avoid a HelloRetryRequest but enlarge the ClientHello. Null (the
        /// default) sends <see cref="DefaultKeyShareGroups"/> that are supported, else the first supported group.
        /// </summary>
        public IList<ushort> KeyShareGroups { get; set; }

        /// <summary>
        /// The automatic key shares: x25519 over DTLS, where a ClientHello should fit one datagram (a post-quantum share
        /// is a kilobyte); TLS clients add the X25519MLKEM768 hybrid that current servers prefer.
        /// </summary>
        protected virtual IReadOnlyList<ushort> DefaultKeyShareGroups => new[] { Dtls13Groups.X25519 };

        /// <summary>Groups offered in supported_groups, in preference order (see <see cref="Dtls13Groups"/>).</summary>
        public IList<ushort> SupportedGroups { get; set; } = new List<ushort>(Dtls13Groups.DefaultPreference);

        /// <summary>A ticket from an earlier connection to resume with (PSK resumption, RFC 8446 §2.2).</summary>
        public Dtls13SessionTicket ResumptionTicket { get; set; }

        /// <summary>Advertise psk_dhe_ke so the server issues tickets, and offer <see cref="ResumptionTicket"/>.</summary>
        public bool UseSessionTickets { get; set; } = true;

        /// <summary>The most recent ticket the server issued on this connection, or null.</summary>
        public Dtls13SessionTicket SessionTicket { get; private set; }

        /// <summary>Whether the server accepted <see cref="ResumptionTicket"/>.</summary>
        public override bool IsResumed => _isResumed;
        private bool _isResumed;

        /// <summary>
        /// An externally provisioned PSK to authenticate with (RFC 8446 §4.2.11), offered after any resumption ticket.
        /// The server is then not authenticated by a certificate.
        /// </summary>
        public TlsExternalPsk ExternalPsk { get; set; }

        /// <summary>
        /// PSK key exchange modes to offer (RFC 8446 §4.2.9). The default psk_dhe_ke keeps forward secrecy; offering
        /// only psk_ke drops the key share entirely, for peers that cannot afford (EC)DHE.
        /// </summary>
        public byte[] PskKeyExchangeModes { get; set; } = { PskKeyExchangeModesExtension.PskDheKe };

        private bool OffersPskDhe => PskKeyExchangeModes.Contains(PskKeyExchangeModesExtension.PskDheKe);

        /// <summary>
        /// 0-RTT data to send right after the ClientHello when resuming with a ticket that allows it (RFC 8446 §2.3).
        /// It is sent at most once, may be replayed by an attacker, and is lost when the server declines it
        /// (<see cref="TlsConnectionBase.EarlyDataAccepted"/> false): send it again after the handshake in that case.
        /// </summary>
        public byte[] EarlyData { get; set; }

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

        /// <summary>CAs we trust, named in certificate_authorities (RFC 8446 §4.2.4) so the server can pick a matching chain.</summary>
        public IList<X509Certificate> CertificateAuthorities { get; set; }

        /// <summary>Signature schemes we accept in certificates (signature_algorithms_cert, RFC 8446 §4.2.3); null to not send it.</summary>
        public IList<ushort> SignatureAlgorithmsCert { get; set; }

        /// <summary>Cipher suites to offer, in preference order: the defaults in <see cref="Dtls13CipherSuite.Supported"/>, or any of <see cref="Dtls13CipherSuite.All"/>.</summary>
        public IList<ushort> CipherSuites { get; set; } = new List<ushort>(Dtls13CipherSuite.Supported);

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0001, 0x0007 };

        /// <summary>SRTP Master Key Identifier offered in use_srtp (RFC 5764 §4.1.1); null or empty for none, at most 255 bytes.</summary>
        public byte[] SrtpMasterKeyIdentifier { get => _srtpMki; set => _srtpMki = DtlsSrtp.CheckMki(value); }
        private byte[] _srtpMki;

        /// <summary>The server's end-entity certificate once the handshake has progressed past Certificate.</summary>
        public X509Certificate ServerCertificate => _serverCertificate;

        public override X509Certificate PeerCertificate => _serverCertificate;

        /// <summary>
        /// Optional server certificate validation. Return false to abort with bad_certificate.
        /// When null, any certificate is accepted (only proof of key possession is checked).
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator { get; set; }

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

        public override byte[] PeerRawPublicKey => ServerRawPublicKey;

        /// <param name="stream">TLS 1.3 over a reliable byte stream instead of DTLS 1.3 over datagrams.</param>
        protected Tls13ClientConnection(Action<byte[]> send, bool stream)
            : base(isClient: true, send, stream)
        {
        }

        public void BeginHandshake() => Run(() => StartHandshake(Dtls13CryptoUtils.GenerateRandom(32)));

        /// <summary>
        /// For a client that also offers (D)TLS 1.2 and below: one ClientHello for both engines, this one's merged with
        /// <paramref name="legacyHello"/> (its suites, versions down to <paramref name="minimumVersion"/>, and extensions). A
        /// ServerHello below 1.3 is then handed to <see cref="LegacyServerHello"/> (TLS) or
        /// <see cref="LegacyDatagramServerHello"/> (DTLS). Returns the ClientHello sent (TLS form, 4-byte header; DTLS
        /// form, 12-byte header).
        /// </summary>
        internal byte[] BeginMergedHandshake(SharpDTLS.Protocol12.ClientHelloMessage legacyHello, ushort minimumVersion)
        {
            _legacyHello = legacyHello;
            _legacyMinimumVersion = minimumVersion;
            Locked(() => StartHandshake(legacyHello.Random));
            return _sentClientHello.AsSpan(IsDatagram ? 13 : 5).ToArray();
        }

        /// <summary>A TLS 1.2-or-lower ServerHello arrived after a merged ClientHello: the received bytes from it on.</summary>
        internal event Action<byte[]> LegacyServerHello;

        /// <summary>
        /// A DTLS 1.2-or-lower ServerHello arrived after a merged ClientHello. Called under this connection's lock, before
        /// the next datagram is read, so the legacy engine is in place for it.
        /// </summary>
        internal Action<LegacyDatagramHandoff> LegacyDatagramServerHello { get; set; }

        private SharpDTLS.Protocol12.ClientHelloMessage _legacyHello;
        private ushort _legacyMinimumVersion;
        private byte[] _sentClientHello; // the last ClientHello record sent
        private int _helloVerifyRequests;

        // A DTLS 1.2 server's flight can overtake its ServerHello: kept for the legacy engine.
        private readonly List<byte[]> _overtakingLegacyRecords = new();
        private const int MaxOvertakingLegacyRecords = 16;

        private byte[] StartHandshake(byte[] random)
        {
            byte[] record;
                if (_state != State.Start)
                throw new InvalidOperationException("The handshake has already started.");

            foreach (var suite in CipherSuites)
                if (!Dtls13CipherSuite.IsSupported(suite))
                    throw new InvalidOperationException($"Cipher suite 0x{suite:X4} is not supported.");

            foreach (ushort group in SupportedGroups)
                if (!Dtls13Groups.IsSupported(group))
                    throw new InvalidOperationException($"Group {Dtls13Groups.Name(group)} is not supported.");
            var shareGroups = KeyShareGroups ?? DefaultKeyShareGroups.Where(SupportedGroups.Contains).DefaultIfEmpty(SupportedGroups[0]).ToList();
            foreach (ushort group in shareGroups)
            {
                if (!SupportedGroups.Contains(group))
                    throw new InvalidOperationException($"Key share group {Dtls13Groups.Name(group)} is not in SupportedGroups.");
                _keyShares[group] = Dtls13Groups.Generate(group);
            }

            _clientHello = BuildClientHello(random, cookie: null);

            BeginFlight();
            record = SendPlaintextHandshake(_clientHello);
            _sentClientHello = record;
            Session.Transcript.AddPlaintextRecord(record);
            if (_earlyDataOffered)
                SendEarlyData();
            _state = State.WaitServerHello;
            ArmRetransmission();
            return record;
        }

        private ClientHelloDatagram BuildClientHello(byte[] random, byte[] cookie)
        {
            ClientRandom = random;
            var clientHello = new ClientHelloDatagram(Array.Empty<byte>()) { ClientRandom = random, Datagram = IsDatagram, AfterHelloRetryRequest = _receivedHelloRetryRequest };
            if (!IsDatagram)
            {
                clientHello.Extensions.RemoveAll(e => e is ClientSupportedVersions);
                clientHello.Extensions.Add(new ClientSupportedVersions(ClientSupportedVersions.Tls13));
            }
            clientHello.CipherSuites = new List<ushort>(CipherSuites);

            // Advertise only what is implemented, and the configured groups with a share for each key share group.
            clientHello.Extensions.RemoveAll(e => e is ClientSignatureAlgorithms || e is EncryptThenMac || e is ClientKeyShareExtension || e is SupportedGroups);
            clientHello.Extensions.Add(new ClientSignatureAlgorithms(Dtls13Signatures.Supported));
            clientHello.Extensions.Add(new SupportedGroups(SupportedGroups.ToArray()));

            if (ServerName != null)
                clientHello.Extensions.Add(new ServerNameExtension(ServerName));
            if (ApplicationProtocols is { Count: > 0 })
                clientHello.Extensions.Add(new AlpnExtension(ApplicationProtocols));
            clientHello.Extensions.AddRange(RecordSizeNegotiation.Offer(RecordSizeLimit, MaxFragmentLength, dtls13: true));
            if (RequestOcspStapling)
                clientHello.Extensions.Add(new StatusRequestExtension(request: true));
            if (AllowPostHandshakeAuthentication)
                clientHello.Extensions.Add(new PostHandshakeAuthExtension());
            if (CertificateAuthorities is { Count: > 0 })
                clientHello.Extensions.Add(new CertificateAuthoritiesExtension(CertificateSelectionContext.Encode(CertificateAuthorities)));
            if (SignatureAlgorithmsCert is { Count: > 0 })
                clientHello.Extensions.Add(new SignatureAlgorithmsCertExtension(SignatureAlgorithmsCert));
            CertificateCompression.Validate(CertificateCompressionAlgorithms);
            if (CertificateCompressionAlgorithms is { Count: > 0 })
                clientHello.Extensions.Add(new CompressCertificateExtension(CertificateCompressionAlgorithms));
            if (RawPublicKeys.Offer(CertificateTypeExtension.ServerType, ServerCertificateTypes) is { } serverTypes)
                clientHello.Extensions.Add(serverTypes);
            if (RawPublicKeys.Offer(CertificateTypeExtension.ClientType, ClientCertificateTypes) is { } clientTypes)
                clientHello.Extensions.Add(clientTypes);
            if (UseConnectionId && IsDatagram)
            {
                _offeredConnectionId ??= Dtls13CryptoUtils.GenerateRandom(ConnectionIdLength);
                clientHello.Extensions.Add(new ConnectionIdExtension(_offeredConnectionId));
            }
            if (IsDatagram && SrtpProtectionProfiles != null && SrtpProtectionProfiles.Length > 0)
                clientHello.Extensions.Add(new UseSrtpExtension(SrtpProtectionProfiles, SrtpMasterKeyIdentifier));
            if (cookie != null)
                clientHello.Extensions.Add(new CookieExtension(cookie));

            // key_share goes last (before pre_shared_key): with post-quantum shares the ClientHello is fragmented, and
            // a server can then still read the small extensions (supported_versions, cookie) from the first fragment.
            var keyShare = new ClientKeyShareExtension();
            foreach (var share in _keyShares.Values)
                keyShare.Entries.Add((share.Group, share.Share));
            clientHello.Extensions.Add(keyShare);

            if (_legacyHello != null)
                MergeLegacyHello(clientHello);

            if (UseSessionTickets || ExternalPsk != null)
            {
                // psk_ke only: no (EC)DHE at all, so no key share (the handshake then needs the PSK to be accepted).
                if (!OffersPskDhe && (ExternalPsk != null || (UseSessionTickets && ResumptionTicket is { IsExpired: false })))
                {
                    clientHello.Extensions.RemoveAll(e => e is ClientKeyShareExtension || e is SupportedGroups);
                    _keyShares.Clear();
                }
                clientHello.Extensions.Add(new PskKeyExchangeModesExtension(PskKeyExchangeModes));
                OfferPsks(clientHello);
            }

            return clientHello;
        }

        /// <summary>
        /// Adds pre_shared_key (last, RFC 8446 §4.2.11) with a usable resumption ticket and the external PSK, and
        /// computes each binder over the ClientHello up to the binders, after any message_hash || HelloRetryRequest
        /// already in the transcript.
        /// </summary>
        private void OfferPsks(ClientHelloDatagram clientHello)
        {
            _offeredPsks.Clear();
            _earlyDataOffered = false;

            // A PSK's hash must match the suite: after a HelloRetryRequest that is the selected one.
            bool Compatible(Dtls13CipherSuite hashSuite) => _receivedHelloRetryRequest
                ? SuiteFor(_hrrCipherSuite).HashAlgorithm == hashSuite.HashAlgorithm
                : CipherSuites.Any(id => SuiteFor(id).HashAlgorithm == hashSuite.HashAlgorithm);

            var ticket = ResumptionTicket;
            if (UseSessionTickets && ticket != null && !ticket.IsExpired && string.Equals(ticket.ServerName, ServerName, StringComparison.OrdinalIgnoreCase) && Dtls13CipherSuite.IsSupported(ticket.CipherSuite)
                && Compatible(SuiteFor(ticket.CipherSuite)))
                _offeredPsks.Add(new OfferedPsk(ticket.Ticket, ticket.ObfuscatedAge, ticket.Psk, SuiteFor(ticket.CipherSuite), ticket));

            // External PSKs have no age: obfuscated_ticket_age is 0 (RFC 8446 §4.2.11).
            if (ExternalPsk != null && Compatible(SuiteFor(ExternalPsk.CipherSuite)))
                _offeredPsks.Add(new OfferedPsk(ExternalPsk.Identity, 0, ExternalPsk.Key, SuiteFor(ExternalPsk.CipherSuite), null));

            if (_offeredPsks.Count == 0)
                return;

            // 0-RTT only with the ticket as the first identity, within its limit and with its suite offered
            // (the server must select it), and never after a HelloRetryRequest (RFC 8446 §4.2.10).
            var first = _offeredPsks[0];
            _earlyDataOffered = EarlyData != null && first.Ticket != null && !_receivedHelloRetryRequest
                                && first.Ticket.MaxEarlyDataSize >= EarlyData.Length && CipherSuites.Contains(first.Ticket.CipherSuite)
                                && (first.Ticket.ApplicationProtocol == null || (ApplicationProtocols?.Contains(first.Ticket.ApplicationProtocol) ?? false));
            if (_earlyDataOffered)
                clientHello.Extensions.Add(new EarlyDataExtension());

            var extension = new ClientPreSharedKeyExtension();
            foreach (var offered in _offeredPsks)
            {
                extension.Identities.Add((offered.Identity, offered.ObfuscatedAge));
                extension.Binders.Add(new byte[offered.HashSuite.HashLength]);
            }
            clientHello.Extensions.Add(extension);

            byte[] truncated = PskBinders.TruncatedClientHello(clientHello.ToBytes(), extension.BindersLength);
            for (int i = 0; i < _offeredPsks.Count; i++)
            {
                var offered = _offeredPsks[i];
                extension.Binders[i] = Dtls13CryptoUtils.CalculateBinder(offered.Key, Session.Transcript.HashWith(offered.HashSuite, truncated),
                    offered.HashSuite, external: offered.Ticket == null);
            }
        }

        private Dtls13CryptoContext _earlyKeys;

        // Epoch 1, under client_early_traffic_secret of the ticket's suite; not part of any flight.
        private void SendEarlyData()
        {
            var ticketSuite = SuiteFor(_offeredPsks[0].Ticket.CipherSuite);
            _earlyKeys = Dtls13CryptoUtils.CalculateEarlyKeys(_clientHello.ClientRandom, Session.Transcript.Hash(ticketSuite), _offeredPsks[0].Key, ticketSuite);
            SendProtected(_earlyKeys, new ApplicationDataDatagram(EarlyData).ToBytes());
        }

        // TLS 1.3 and the legacy engine's offer in one ClientHello: TLS 1.3 first in suites, versions, groups and schemes.
        private void MergeLegacyHello(ClientHelloDatagram clientHello)
        {
            foreach (ushort suite in _legacyHello.CipherSuites)
                if (!clientHello.CipherSuites.Contains(suite))
                    clientHello.CipherSuites.Add(suite);

            var versions = new List<ushort> { IsDatagram ? ClientSupportedVersions.Dtls13 : ClientSupportedVersions.Tls13 };
            var legacyVersions = IsDatagram ? new[] { DtlsVersion.Dtls12, DtlsVersion.Dtls10 } : new[] { TlsVersion.Tls12, TlsVersion.Tls11, TlsVersion.Tls10 };
            versions.AddRange(legacyVersions.Where(v => ProtocolVersions.IsAtLeast(v, _legacyMinimumVersion)));
            clientHello.Extensions.RemoveAll(e => e is ClientSupportedVersions);
            clientHello.Extensions.Add(new ClientSupportedVersions(versions.ToArray()));
            clientHello.LegacySessionId = _legacyHello.SessionId; // 1.2 session resumption; echoed by a TLS 1.3 server

            var types = clientHello.Extensions.Select(ExtensionType).ToHashSet();
            foreach (var extension in _legacyHello.Extensions)
            {
                ushort type = ExtensionType(extension);
                if (type == 0x000a) // supported_groups
                {
                    var groups = clientHello.Extensions.OfType<SupportedGroups>().First();
                    var merged = groups.Groups.Concat(ListOf(extension).Where(g => !groups.Groups.Contains(g))).ToArray();
                    clientHello.Extensions[clientHello.Extensions.IndexOf(groups)] = new SupportedGroups(merged);
                }
                else if (type == 0x000d) // signature_algorithms
                {
                    var schemes = clientHello.Extensions.OfType<ClientSignatureAlgorithms>().First();
                    var merged = schemes.SignatureAlgorithms.Concat(ListOf(extension).Where(a => !schemes.SignatureAlgorithms.Contains(a))).ToArray();
                    clientHello.Extensions[clientHello.Extensions.IndexOf(schemes)] = new ClientSignatureAlgorithms(merged);
                }
                else if (types.Add(type))
                {
                    // Before key_share, which stays last (but before pre_shared_key).
                    int keyShare = clientHello.Extensions.FindIndex(e => e is ClientKeyShareExtension);
                    clientHello.Extensions.Insert(keyShare < 0 ? clientHello.Extensions.Count : keyShare, extension);
                }
            }
        }

        private static ushort ExtensionType(ITlsExtension extension)
        {
            byte[] bytes = new byte[extension.CalculateLength()];
            extension.Write(0, bytes);
            return (ushort)((bytes[0] << 8) | bytes[1]);
        }

        // The uint16 list of a supported_groups or signature_algorithms extension.
        private static ushort[] ListOf(ITlsExtension extension)
        {
            byte[] bytes = new byte[extension.CalculateLength()];
            extension.Write(0, bytes);
            return new TlsReader(bytes.AsSpan(4).ToArray()).ReadUInt16List16();
        }

        // ── ServerHello / HelloRetryRequest ──────────────────────────────────────────────────

        protected override void OnPlaintextHandshake(byte[] record)
        {
            byte type = record[IsDatagram ? 13 : 5];
            bool mergedDatagram = IsDatagram && _legacyHello != null && _state == State.WaitServerHello;
            if (mergedDatagram && type == 0x03)
            {
                OnHelloVerifyRequest(record);
                return;
            }
            if (type != 0x02)
            {
                if (mergedDatagram && _overtakingLegacyRecords.Count < MaxOvertakingLegacyRecords)
                {
                    _overtakingLegacyRecords.Add(record);
                    return;
                }
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{type:X2}");
            }

            // Retransmitted ServerHello/HelloRetryRequest (e.g. answering a retransmitted ClientHello): ignore.
            int messageSeq = IsDatagram ? (record[17] << 8) | record[18] : NextReceiveMessageSeq;
            if (_state != State.WaitServerHello || messageSeq < NextReceiveMessageSeq)
            {
                if (!IsDatagram)
                    throw new DtlsException(AlertDescription.UnexpectedMessage, "Unexpected ServerHello.");
                return;
            }

            var serverHello = new ServerHelloDatagram { Datagram = IsDatagram };
            serverHello.FromBytes(record);

            // After a merged ClientHello, a server that chose 1.2 or lower is the legacy engine's (RFC 8446 §4.1.3,
            // RFC 9147 §5.3: unless the server also speaks 1.3 and marked the random, which means someone downgraded us).
            ushort version13 = IsDatagram ? ClientSupportedVersions.Dtls13 : ClientSupportedVersions.Tls13;
            if (_legacyHello != null && serverHello.Extensions.OfType<ServerSupportedVersions>().FirstOrDefault()?.Version != version13)
            {
                if (Downgrade.IsMarked(serverHello.ServerRandom))
                    throw new DtlsException(AlertDescription.IllegalParameter, "The ServerHello carries the 1.3 downgrade sentinel.");
                StopRetransmission();
                _state = State.HandedOff;
                if (IsDatagram)
                {
                    // The ServerHello whole (it may have come in fragments), what overtook it, and the rest of its datagram.
                    InputDetached = true;
                    var records = new List<byte[]> { record };
                    records.AddRange(_overtakingLegacyRecords);
                    records.Add(CurrentDatagram);
                    LegacyDatagramServerHello?.Invoke(new LegacyDatagramHandoff(_sentClientHello.AsSpan(13).ToArray(), records,
                        PlaintextRecordSequence, NextSendMessageSeq, messageSeq));
                    return;
                }
                byte[] pending = DetachTlsInput(record);
                RaiseEvent(() => LegacyServerHello?.Invoke(pending));
                return;
            }
            ValidateServerHello(serverHello);

            if (HelloRetryRequest.IsHelloRetryRequest(serverHello))
                OnHelloRetryRequest(record, serverHello);
            else
                OnServerHello(record, serverHello);
        }

        // A DTLS 1.2 server checks our address first (RFC 6347 §4.2.1): the same ClientHello again, with its cookie.
        private void OnHelloVerifyRequest(byte[] record)
        {
            int messageSeq = (record[17] << 8) | record[18];
            if (messageSeq < NextReceiveMessageSeq)
                return; // retransmitted
            if (++_helloVerifyRequests > 3)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Too many HelloVerifyRequests.");

            int length = (record[14] << 16) | (record[15] << 8) | record[16];
            var hvr = SharpDTLS.Protocol12.HelloVerifyRequestMessage.Decode(record.AsSpan(25, length).ToArray());
            if ((hvr.ServerVersion >> 8) != 0xFE)
                throw new DtlsException(AlertDescription.ProtocolVersion, "HelloVerifyRequest is not DTLS.");
            Debug.WriteLine($"{LogPrefix} Received HelloVerifyRequest (cookie {hvr.Cookie.Length} bytes)");

            StopRetransmission();
            NextReceiveMessageSeq = messageSeq + 1;
            _clientHello.LegacyCookie = hvr.Cookie;
            BeginFlight();
            _sentClientHello = SendPlaintextHandshake(_clientHello);
            Session.Transcript.Clear();
            Session.Transcript.AddPlaintextRecord(_sentClientHello);
            ArmRetransmission();
        }

        private void ValidateServerHello(ServerHelloDatagram serverHello)
        {
            int h = IsDatagram ? 25 : 9;
            if (serverHello.Bytes[h] != (IsDatagram ? 0xFE : 0x03) || serverHello.Bytes[h + 1] != (IsDatagram ? 0xFD : 0x03))
                throw new DtlsException(AlertDescription.ProtocolVersion, IsDatagram ? "ServerHello legacy_version must be DTLS 1.2." : "ServerHello legacy_version must be TLS 1.2.");

            var versions = serverHello.Extensions.OfType<ServerSupportedVersions>().FirstOrDefault();
            if (versions == null || versions.Version != (IsDatagram ? ClientSupportedVersions.Dtls13 : ClientSupportedVersions.Tls13))
                throw new DtlsException(AlertDescription.ProtocolVersion, IsDatagram ? "Server did not negotiate DTLS 1.3." : "Server did not negotiate TLS 1.3.");

            if (!CipherSuites.Contains(serverHello.SelectedCipherSuite))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected a cipher suite that was not offered (0x{serverHello.SelectedCipherSuite:X4}).");

            // RFC 9147 §5.4: DTLS 1.3 servers must not echo legacy_session_id; TLS 1.3 servers echo ours (RFC 8446 §4.1.3).
            if (!serverHello.LegacySessionIdEcho.AsSpan().SequenceEqual(IsDatagram ? Array.Empty<byte>() : _clientHello.LegacySessionId))
                throw new DtlsException(AlertDescription.IllegalParameter, "ServerHello legacy_session_id_echo does not match.");
        }

        private void OnHelloRetryRequest(byte[] record, ServerHelloDatagram hrr)
        {
            if (_receivedHelloRetryRequest)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Received a second HelloRetryRequest.");

            _receivedHelloRetryRequest = true;
            _hrrCipherSuite = hrr.SelectedCipherSuite;
            var suite = SuiteFor(hrr.SelectedCipherSuite);

            var keyShare = hrr.Extensions.OfType<ServerKeyShareExtension>().FirstOrDefault();
            var cookie = hrr.Extensions.OfType<CookieExtension>().FirstOrDefault();

            // RFC 8446 §4.1.4: the HRR must change something, and may only ask for a group we offered but have not
            // sent a share for; ClientHello2 then carries a share for that group alone.
            if (keyShare != null)
            {
                if (!SupportedGroups.Contains(keyShare.KeyType) || _keyShares.ContainsKey(keyShare.KeyType))
                    throw new DtlsException(AlertDescription.IllegalParameter,
                        $"HelloRetryRequest selected group {Dtls13Groups.Name(keyShare.KeyType)}, which was not offered or already had a key share.");
                _keyShares.Clear();
                _keyShares[keyShare.KeyType] = Dtls13Groups.Generate(keyShare.KeyType);
            }
            else if (cookie == null)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "HelloRetryRequest would not change the ClientHello.");
            }

            // RFC 8446 §4.4.1: Transcript = message_hash(Hash(ClientHello1)) || HelloRetryRequest || ...
            Session.Transcript.ReplaceWithMessageHash(suite);
            Session.Transcript.AddPlaintextRecord(record);
            NextReceiveMessageSeq = hrr.SequenceNumber + 1;

            _clientHello = BuildClientHello(_clientHello.ClientRandom, cookie?.Cookie);

            BeginFlight();
            byte[] clientHello2 = SendPlaintextHandshake(_clientHello);
            _sentClientHello = clientHello2;
            Session.Transcript.AddPlaintextRecord(clientHello2);
            ArmRetransmission();
        }

        private void OnServerHello(byte[] record, ServerHelloDatagram serverHello)
        {
            if (_receivedHelloRetryRequest && serverHello.SelectedCipherSuite != _hrrCipherSuite)
                throw new DtlsException(AlertDescription.IllegalParameter, "ServerHello cipher suite differs from HelloRetryRequest.");

            // Without a key_share the server chose psk_ke, which needs an accepted PSK and our offer of that mode.
            var keyShare = serverHello.Extensions.OfType<ServerKeyShareExtension>().FirstOrDefault();
            bool pskOnly = keyShare == null && serverHello.Extensions.OfType<ServerPreSharedKeyExtension>().Any()
                           && PskKeyExchangeModes.Contains(PskKeyExchangeModesExtension.PskKe);
            if (!pskOnly && (keyShare == null || keyShare.PublicKey == null))
                throw new DtlsException(AlertDescription.MissingExtension, "ServerHello has no key_share.");
            if (keyShare != null && !_keyShares.ContainsKey(keyShare.KeyType))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected group {Dtls13Groups.Name(keyShare.KeyType)}, which had no key share.");
            NegotiatedGroup = keyShare?.KeyType ?? 0;

            StopRetransmission();

            var suite = SuiteFor(serverHello.SelectedCipherSuite);
            Session.CipherSuite = suite;
            NegotiatedVersion = IsDatagram ? DtlsVersion.Dtls13 : TlsVersion.Tls13;
            ServerRandom = serverHello.ServerRandom;

            // RFC 8446 §4.2.11: the server may only select an identity we offered, with a suite of the same hash.
            byte[] psk = null;
            var selectedPsk = serverHello.Extensions.OfType<ServerPreSharedKeyExtension>().FirstOrDefault();
            if (selectedPsk != null)
            {
                if (selectedPsk.SelectedIdentity >= _offeredPsks.Count)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Server selected a PSK that was not offered.");
                _selectedPsk = _offeredPsks[selectedPsk.SelectedIdentity];
                if (_selectedPsk.HashSuite.HashAlgorithm != suite.HashAlgorithm)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Server selected a cipher suite incompatible with the PSK.");
                psk = _selectedPsk.Key;
                _isResumed = _selectedPsk.Ticket != null;
                IsExternalPsk = _selectedPsk.Ticket == null;
                if (_selectedPsk.Ticket?.ServerCertificate != null)
                {
                    _serverCertificate = new X509CertificateParser().ReadCertificate(_selectedPsk.Ticket.ServerCertificate);
                    Session.PeerCertificate = _selectedPsk.Ticket.ServerCertificate;
                }
            }
            else if (pskOnly)
            {
                throw new DtlsException(AlertDescription.MissingExtension, "ServerHello has neither key_share nor pre_shared_key.");
            }

            var serverCid = serverHello.Extensions.OfType<ConnectionIdExtension>().FirstOrDefault();
            if (serverCid != null)
            {
                if (_offeredConnectionId == null)
                    throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited connection_id extension.");
                WriteConnectionId = serverCid.ConnectionId;
                ReadConnectionId = _offeredConnectionId;
            }

            Session.Transcript.AddPlaintextRecord(record);
            NextReceiveMessageSeq = serverHello.SequenceNumber + 1;

            byte[] sharedSecret = keyShare == null ? null : _keyShares[keyShare.KeyType].Complete(keyShare.PublicKey);
            var handshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), sharedSecret, suite, psk);

            Session.ServerHandshakeKeys = handshakeKeys;
            Session.WriteKeys = handshakeKeys;
            AddReadKeys(handshakeKeys);

            _state = State.WaitEncryptedExtensions;
            Debug.WriteLine($"[DTLS13 Client] ServerHello: suite 0x{suite.Id:X4}");
        }

        // ── Encrypted handshake ──────────────────────────────────────────────────────────────

        protected override void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            var suite = Session.CipherSuite;

            // A CompressedCertificate stands for the Certificate; the transcript keeps the message as received.
            if (parsed is CompressedCertificateDatagram compressed && _state is State.WaitCertificate or State.WaitCertificateOrCertificateRequest)
            {
                parsed = compressed.Decompress(CertificateCompressionAlgorithms);
                CertificateCompressionAlgorithm = compressed.Algorithm;
            }

            switch (_state)
            {
                case State.WaitEncryptedExtensions when parsed is EncryptedExtensionsDatagram encryptedExtensions:
                    // RFC 8446 §4.2.10: early_data may only be accepted when offered, with the first PSK and its suite.
                    if (encryptedExtensions.Extensions.OfType<EarlyDataExtension>().Any())
                    {
                        if (!_earlyDataOffered || _selectedPsk != _offeredPsks[0] || Session.CipherSuite.Id != _offeredPsks[0].Ticket.CipherSuite)
                            throw new DtlsException(AlertDescription.IllegalParameter, "Server accepted early data that was not offered.");
                        EarlyDataAccepted = true;
                    }

                    if (encryptedExtensions.Extensions.OfType<ServerNameExtension>().Any() && ServerName == null)
                        throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited server_name extension.");
                    ApplicationProtocol = AlpnExtension.Accept(ApplicationProtocols, encryptedExtensions.Extensions.OfType<AlpnExtension>().FirstOrDefault());
                    // Certificate types (RFC 7250): no answer means X.509, checked when a Certificate arrives.
                    ServerCertificateType = RawPublicKeys.Accept(ServerCertificateTypes,
                        RawPublicKeys.Find(encryptedExtensions.Extensions, CertificateTypeExtension.ServerType), requireSupport: false);
                    _clientCertificateType = RawPublicKeys.Accept(ClientCertificateTypes,
                        RawPublicKeys.Find(encryptedExtensions.Extensions, CertificateTypeExtension.ClientType), requireSupport: false);

                    (PeerRecordLimit, ReceiveRecordLimit) = RecordSizeNegotiation.Complete(
                        encryptedExtensions.Extensions.OfType<RecordSizeLimitExtension>().FirstOrDefault(),
                        encryptedExtensions.Extensions.OfType<MaxFragmentLengthExtension>().FirstOrDefault(), RecordSizeLimit, MaxFragmentLength, dtls13: true);
                    if (EarlyDataAccepted && ApplicationProtocol != _offeredPsks[0].Ticket.ApplicationProtocol)
                        throw new DtlsException(AlertDescription.IllegalParameter, "Early data accepted with another application protocol.");

                    var srtp = encryptedExtensions.Extensions.OfType<UseSrtpExtension>().FirstOrDefault();
                    if (srtp != null)
                    {
                        // RFC 5764 §4.1.1: exactly one profile, and one we offered
                        if (!IsDatagram || srtp.SrtpProtectionProfiles.Length != 1 || SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SrtpProtectionProfiles[0]))
                            throw new DtlsException(AlertDescription.IllegalParameter, "Server selected an SRTP profile that was not offered.");
                        SelectedSrtpMki = DtlsSrtp.AcceptServerMki(SrtpMasterKeyIdentifier, srtp.MasterKeyIdentifier);
                        SelectedSrtpProtectionProfile = srtp.SrtpProtectionProfiles[0];
                    }
                    Session.Transcript.AddHandshake(message);
                    // A PSK handshake authenticates with the PSK: no Certificate or CertificateVerify follows.
                    _state = _selectedPsk != null ? State.WaitFinished : State.WaitCertificateOrCertificateRequest;
                    break;

                case State.WaitCertificateOrCertificateRequest when parsed is CertificateRequestDatagram certificateRequest:
                    Session.Transcript.AddHandshake(message);
                    _certificateRequest = certificateRequest;
                    _state = State.WaitCertificate;
                    break;

                case State.WaitCertificateOrCertificateRequest when parsed is CertificateDatagram:
                case State.WaitCertificate when parsed is CertificateDatagram:
                    OnServerCertificate((CertificateDatagram)parsed);
                    Session.Transcript.AddHandshake(message);
                    _state = State.WaitCertificateVerify;
                    break;

                case State.WaitCertificateVerify when parsed is CertificateVerifyDatagram certificateVerify:
                {
                    byte[] content = Dtls13Signatures.BuildSignedContent(server: true, Session.Transcript.Hash(suite));
                    ushort scheme = (ushort)certificateVerify.SignatureType;
                    if (!Dtls13Signatures.Supported.Contains(scheme))
                        throw new DtlsException(AlertDescription.IllegalParameter, $"Server used signature scheme 0x{scheme:X4}, which was not offered.");
                    if (!Dtls13Signatures.Verify(scheme, _serverPublicKey, content, certificateVerify.Signature))
                        throw new DtlsException(AlertDescription.DecryptError, "Server CertificateVerify signature is invalid.");

                    Session.Transcript.AddHandshake(message);
                    _state = State.WaitFinished;
                    break;
                }

                case State.WaitFinished when parsed is FinishedDatagram finished:
                    OnServerFinished(message, finished);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message 0x{message[0]:X2} in state {_state}.");
            }
        }

        private void OnServerCertificate(CertificateDatagram certificate)
        {
            if (certificate.CertificateChain.Count == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Server sent an empty Certificate.");
            if (certificate.RequestContext.Length != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Server Certificate has a non-empty request context.");

            if (ServerCertificateType == CertificateType.RawPublicKey)
            {
                // RFC 7250 §3: a single entry holding the SubjectPublicKeyInfo.
                if (certificate.CertificateChain.Count != 1)
                    throw new DtlsException(AlertDescription.DecodeError, "A raw public key Certificate has one entry.");
                if (certificate.OcspResponse != null)
                    throw new DtlsException(AlertDescription.UnsupportedExtension, "OCSP staple for a raw public key.");
                byte[] spki = certificate.Certificate;
                _serverPublicKey = RawPublicKeys.Decode(spki);
                if (ServerRawPublicKeyValidator != null && !ServerRawPublicKeyValidator(spki))
                    throw new DtlsException(AlertDescription.BadCertificate, "Server raw public key was rejected.");
                ServerRawPublicKey = spki;
                return;
            }
            if (ServerCertificateTypes != null && !ServerCertificateTypes.Contains(CertificateType.X509))
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "The server did not agree to a raw public key.");

            try
            {
                _serverCertificate = new X509CertificateParser().ReadCertificate(certificate.Certificate);
            }
            catch (Exception ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate could not be parsed.", ex);
            }

            if (_serverCertificate == null)
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate could not be parsed.");
            _serverPublicKey = _serverCertificate.GetPublicKey();

            Session.PeerCertificate = certificate.Certificate;
            if (ServerCertificateValidator != null && !ServerCertificateValidator(_serverCertificate, certificate.CertificateChain))
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate was rejected.");

            // RFC 8446 §4.4.2: CertificateEntry extensions must answer ClientHello extensions.
            if (certificate.OcspResponse != null && !RequestOcspStapling)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited OCSP staple.");
            OcspResponse = certificate.OcspResponse;
            if (ServerCertificateStatusValidator != null && !ServerCertificateStatusValidator(OcspResponse, certificate.CertificateChain))
                throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The server's certificate status was rejected.");
        }

        private void OnServerFinished(byte[] message, FinishedDatagram finished)
        {
            var suite = Session.CipherSuite;
            var handshakeKeys = Session.ServerHandshakeKeys;

            byte[] expected = Dtls13CryptoUtils.CalculateFinished(handshakeKeys.ServerSecret, Session.Transcript.Hash(suite), suite);
            if (!CryptographicOperations.FixedTimeEquals(expected, finished.VerifyData))
                throw new DtlsException(AlertDescription.DecryptError, "Server Finished verification failed.");

            Session.Transcript.AddHandshake(message);

            // Application secrets are derived from the transcript up to the server Finished.
            byte[] serverFinishedHash = Session.Transcript.Hash(suite);
            var applicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(_clientHello.ClientRandom, serverFinishedHash, handshakeKeys.Secret, suite);
            Session.ServerApplicationKeys = applicationKeys;
            Session.ExporterMasterSecret = Dtls13CryptoUtils.CalculateExporterMasterSecret(applicationKeys.Secret, serverFinishedHash, suite);

            // Client's final flight: [Certificate, CertificateVerify,] Finished in the handshake epoch.
            BeginFlight();
            // TLS (not DTLS, RFC 9147 §5.6): accepted 0-RTT data ends with EndOfEarlyData under the early keys.
            if (!IsDatagram && EarlyDataAccepted)
                SendHandshake(new EndOfEarlyDataDatagram(), _earlyKeys);
            if (_certificateRequest != null)
                SendClientCertificate();

            byte[] verifyData = Dtls13CryptoUtils.CalculateFinished(handshakeKeys.ClientSecret, Session.Transcript.Hash(suite), suite);
            SendHandshake(new FinishedDatagram { VerifyData = verifyData }, handshakeKeys);
            Session.ResumptionMasterSecret = Dtls13CryptoUtils.CalculateResumptionMasterSecret(applicationKeys.Secret, Session.Transcript.Hash(suite), suite);

            // Switch to the application epoch. The server's ACK (or its first application record) ends retransmission.
            Session.WriteKeys = applicationKeys;
            AddReadKeys(applicationKeys);
            ClearReceivedHandshakeRecords();
            ArmRetransmission();

            _state = State.Connected;
            IsHandshakeComplete = true;
            WriteKeyLog(Convert.ToHexString(_clientHello.ClientRandom), handshakeKeys, applicationKeys);
            Debug.WriteLine("[DTLS13 Client] Handshake complete");
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        protected override void OnNewSessionTicket(NewSessionTicketDatagram nst)
        {
            // A zero lifetime means the ticket must not be used (RFC 8446 §4.6.1).
            if (Session.ResumptionMasterSecret == null || nst.TicketLifetime == 0 || nst.Ticket == null || nst.Ticket.Length == 0)
                return;
            var suite = Session.CipherSuite;
            byte[] psk = Dtls13CryptoUtils.CalculateResumptionPsk(Session.ResumptionMasterSecret, nst.TicketNonce ?? Array.Empty<byte>(), suite);
            SessionTicket = new Dtls13SessionTicket(nst.Ticket, Math.Min(nst.TicketLifetime, 604800u), nst.TicketAgeAdd, suite.Id, psk,
                Session.PeerCertificate, nst.MaxEarlyDataSize, ServerName, ApplicationProtocol);
        }

        private void SendClientCertificate() => SendClientCertificate(_certificateRequest, Session.ServerHandshakeKeys, Session.Transcript);

        /// <summary>
        /// Certificate and, when we can sign with a scheme the server accepts, CertificateVerify over
        /// <paramref name="transcript"/>: the handshake's, or a copy for post-handshake authentication.
        /// </summary>
        private void SendClientCertificate(CertificateRequestDatagram request, Dtls13CryptoContext keys, Dtls13Transcript transcript)
        {
            var suite = Session.CipherSuite;
            bool inHandshake = transcript == Session.Transcript;
            var chosen = ClientCredentialsSelector?.Invoke(new CertificateSelectionContext(null,
                CertificateSelectionContext.ParseNames(request.CertificateAuthorities), request.SignatureAlgorithms, request.SignatureAlgorithmsCert));
            var (keyPair, clientCertificate, intermediates) = chosen != null
                ? (chosen.KeyPair, chosen.Certificate, chosen.IntermediateCertificates)
                : (ClientCertificateKeyPair, ClientCertificate, ClientIntermediateCertificates);

            // Send our certificate only if we can sign with a scheme the server accepts.
            bool rawPublicKey = _clientCertificateType == CertificateType.RawPublicKey;
            ushort? scheme = null;
            if ((clientCertificate != null || rawPublicKey) && keyPair != null)
                scheme = Dtls13Signatures.SelectScheme(keyPair.Private, request.SignatureAlgorithms);

            var chain = !scheme.HasValue ? Array.Empty<byte[]>()
                : rawPublicKey ? new[] { RawPublicKeys.Encode(keyPair.Public) }
                : new[] { clientCertificate.GetEncoded() }.Concat((intermediates ?? Array.Empty<X509Certificate>()).Select(c => c.GetEncoded())).ToArray();
            if (scheme.HasValue && !rawPublicKey)
                LocalCertificate = clientCertificate;
            var certificate = new CertificateDatagram(chain, request.RequestContext);
            ushort? compression = chain.Length > 0 ? CertificateCompression.Select(CertificateCompressionAlgorithms, request.CompressionAlgorithms) : null;
            byte[] sent = SendHandshake(compression.HasValue ? new CompressedCertificateDatagram(compression.Value, certificate) : certificate, keys, inHandshake);
            if (!inHandshake)
                transcript.AddHandshake(sent);

            if (scheme.HasValue)
            {
                byte[] content = Dtls13Signatures.BuildSignedContent(server: false, transcript.Hash(suite));
                byte[] signature = Dtls13Signatures.Sign(scheme.Value, keyPair.Private, content);
                sent = SendHandshake(new CertificateVerifyDatagram(signature, scheme.Value), keys, inHandshake);
                if (!inHandshake)
                    transcript.AddHandshake(sent);
            }

            Debug.WriteLine($"[DTLS13 Client] Sent Certificate ({chain.Length} entries)");
        }

        // RFC 8446 §4.6.2: Certificate, CertificateVerify and Finished over the handshake transcript (through our Finished)
        // plus the CertificateRequest, with the current application traffic secret as the Finished base key.
        protected override bool OnPostHandshakeAuthMessage(byte[] message, IHandshakeDatagram parsed)
        {
            if (parsed is not CertificateRequestDatagram request)
                return false;
            if (!AllowPostHandshakeAuthentication)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "CertificateRequest without post_handshake_auth.");
            if (request.RequestContext.Length == 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Post-handshake CertificateRequest with an empty context.");

            var transcript = Session.Transcript.Clone();
            transcript.AddHandshake(message);
            SendAck();
            SendPostHandshakeFlight(() =>
            {
                var suite = Session.CipherSuite;
                var keys = Session.WriteKeys;
                SendClientCertificate(request, keys, transcript);
                byte[] verifyData = Dtls13CryptoUtils.CalculateFinished(keys.ClientSecret, transcript.Hash(suite), suite);
                SendHandshake(new FinishedDatagram { VerifyData = verifyData }, keys, addToTranscript: false);
            });
            RaiseEvent(() => PostHandshakeCertificateRequested?.Invoke(this, EventArgs.Empty));
            return true;
        }
    }

    /// <summary>
    /// What the DTLS 1.0-1.2 engine needs to continue a handshake that a merged ClientHello started: the ClientHello
    /// last sent (12-byte header), the records to process (the ServerHello first), and where the epoch-0 record and
    /// message sequence numbers stand.
    /// </summary>
    internal sealed record LegacyDatagramHandoff(byte[] ClientHello, IReadOnlyList<byte[]> Records, int NextRecordSequence,
        int NextSendMessageSeq, int ServerHelloMessageSeq);
}
