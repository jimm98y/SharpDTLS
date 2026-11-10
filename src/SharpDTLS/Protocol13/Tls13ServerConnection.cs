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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.Protocol13.Messages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// Server side of one (D)TLS 1.3 connection: from a <see cref="Dtls13Server"/> or a
    /// <see cref="SharpDTLS.Protocol13.TLS13.Tls13Server"/>.
    /// </summary>
    internal class Tls13ServerConnection : Tls13Connection
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
        public override EndPoint RemoteEndPoint => _address.Current;

        /// <summary>A newer client address awaiting <see cref="ConfirmPeerAddress"/> (when not following automatically).</summary>
        public override EndPoint PendingPeerAddress => _address.Pending;

        /// <summary>Sends to <paramref name="address"/> from now on, after the application has checked it can be reached.</summary>
        public override void ConfirmPeerAddress(EndPoint address) => Locked(() =>
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
            RaisePeerAddressChanged(change);
            if (DatagramServer.AutoUpdatePeerAddress)
                RaiseEvent(() => DatagramServer.OnPeerAddressConfirmed(this, old));
        }

        /// <summary>Whether the client resumed with a ticket (PSK handshake).</summary>
        public override bool IsResumed => _psk != null && ExternalPskIdentity == null;

        /// <summary>Whether the handshake was authenticated with an external PSK.</summary>
        public override bool IsExternalPsk => ExternalPskIdentity != null;

        /// <summary>Whether the handshake used psk_ke (no (EC)DHE, no forward secrecy).</summary>
        public override bool IsPskOnlyKeyExchange => _pskOnly;

        /// <summary>Whether the client's 0-RTT data was accepted.</summary>
        public override bool EarlyDataAccepted => _earlyDataAccepted;

        /// <summary>The client's certificate, when one was sent.</summary>
        public X509Certificate ClientCertificate => _clientCertificate;

        public override X509Certificate PeerCertificate => _clientCertificate;

        /// <summary>The client's raw public key (DER SubjectPublicKeyInfo, RFC 7250), when it authenticated with one.</summary>
        public byte[] ClientRawPublicKey { get; private set; }

        public override byte[] PeerRawPublicKey => ClientRawPublicKey;

        /// <summary>The certificate type we authenticated with (RFC 7250).</summary>
        public override CertificateType ServerCertificateType => _serverCertificateType ?? CertificateType.X509;

        internal Tls13ServerConnection(Dtls13Server server, EndPoint remoteEndPoint)
            : this(server, new PeerAddressTracker(remoteEndPoint))
        {
        }

        /// <summary>The handshake completed (after the server's own HandshakeFinished).</summary>
        public event EventHandler<EventArgs> HandshakeFinished;

        /// <summary>A TLS 1.3 connection over a stream: the ClientHello arrives on it.</summary>
        internal Tls13ServerConnection(Tls13ServerBase server, EndPoint remoteEndPoint, Action<byte[]> send)
            : base(isClient: false, send, stream: true)
        {
            _server = server;
            _address = new PeerAddressTracker(remoteEndPoint);
            KeyLogWriter = server.KeyLogWriter;

            ApplicationDataReceived += (_, data) => _server.OnApplicationData(this, data);
            KeyUpdateMessageReceived += (_, keyUpdate) => _server.OnKeyUpdate(keyUpdate);
            Closed += (_, _) => _server.OnConnectionClosed(this);
        }

        // Replies go to the tracked address, which moves with connection IDs.
        private Tls13ServerConnection(Dtls13Server server, PeerAddressTracker address)
            : base(isClient: false, send: data => server.ServerTransport.Send(address.Current, data))
        {
            _server = server;
            _address = address;
            InitialRetransmitTimeout = server.InitialRetransmitTimeout;
            KeyLogWriter = server.KeyLogWriter;

            ApplicationDataReceived += (_, data) => _server.OnApplicationData(this, data);
            KeyUpdateMessageReceived += (_, keyUpdate) => _server.OnKeyUpdate(keyUpdate);
            Closed += (_, _) => _server.OnConnectionClosed(this);
        }

        internal void Start(byte[] record, ClientHelloDatagram clientHello, Dtls13CipherSuite suite, Tls13ServerBase.HelloRetryState retry, ushort group)
        {
            Run(() =>
            {
                if (IsDatagram)
                    InspectReceivedRecord(record); // a TLS ClientHello was reported as it arrived on the stream
                _clientHello = clientHello;
                _group = group;
                Session.CipherSuite = suite;
                NegotiatedVersion = IsDatagram ? DtlsVersion.Dtls13 : TlsVersion.Tls13;
                ClientRandom = clientHello.ClientRandom;

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
                    InspectSecret(TlsInspector.ClientEarlyTrafficSecret, _earlyKeys.ClientSecret);
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
            // Over TLS, declined 0-RTT data still arrives and must be skipped (RFC 8446 §4.2.10).
            if (!IsDatagram && _clientHello.Extensions.OfType<EarlyDataExtension>().Any())
                SkipUndecryptableBytes = 64 * 1024;
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
            ServerRandom = Dtls13CryptoUtils.GenerateRandom(32);
            var serverHello = new ServerHelloDatagram(Array.Empty<byte>(), suite.Id, ServerRandom) { Datagram = IsDatagram };
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
            suite = Session.CipherSuite; // an inspector may have changed the ServerHello's suite

            var handshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), sharedSecret, suite, _psk);
            if (TlsInspector.Current != null)
            {
                InspectSecret(TlsInspector.Psk, _psk);
                InspectSecret(TlsInspector.SharedSecret, sharedSecret);
                InspectSecret(TlsInspector.HelloHash, Session.Transcript.Hash(suite));
                InspectKeys(handshakeKeys);
            }
            Session.ServerHandshakeKeys = handshakeKeys;
            Session.WriteKeys = handshakeKeys;
            AddReadKeys(handshakeKeys);
            if (!IsDatagram && _earlyKeys != null)
            {
                // TLS: the client's early data and EndOfEarlyData come first, under the early keys.
                TlsReadKeysOverride = _earlyKeys;
                SkipUndecryptableBytes = 0;
            }

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
                    LocalCertificate = _certificate;
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
            if (TlsInspector.Current != null)
            {
                InspectSecret(TlsInspector.HandshakeHash, serverFinishedHash);
                InspectKeys(Session.ServerApplicationKeys);
                InspectSecret(TlsInspector.ExporterMasterSecret, Session.ExporterMasterSecret);
            }

            ArmRetransmission();
            _state = _certificateRequest != null ? State.WaitClientCertificate : State.WaitClientFinished;
        }

        /// <summary>
        /// An inspector edited our ServerHello: its random is the one sent, and a different suite is used when implemented
        /// (the handshake keys are derived after the ServerHello, with the suite's hash).
        /// </summary>
        protected override void OnSentHelloEdited(byte[] record)
        {
            var sent = new ServerHelloDatagram { Datagram = IsDatagram };
            sent.FromBytes(record);
            ServerRandom = sent.ServerRandom;
            if (sent.SelectedCipherSuite != Session.CipherSuite.Id && Dtls13CipherSuite.IsSupported(sent.SelectedCipherSuite))
                Session.CipherSuite = SuiteFor(sent.SelectedCipherSuite);
        }

        private EncryptedExtensionsDatagram BuildEncryptedExtensions()
        {
            var extensions = new EncryptedExtensionsDatagram();

            var offered = _clientHello.Extensions.OfType<UseSrtpExtension>().FirstOrDefault();
            ushort? profile = IsDatagram ? DtlsSrtp.Select(DatagramServer.SrtpProtectionProfiles, offered?.SrtpProtectionProfiles) : null;
            if (profile.HasValue)
            {
                SelectedSrtpProtectionProfile = profile;
                SelectedSrtpMki = DatagramServer.SrtpDisableMki ? Array.Empty<byte>() : offered.MasterKeyIdentifier;
                extensions.Extensions.Add(new UseSrtpExtension(new[] { profile.Value }, SelectedSrtpMki));
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

        // TLS: EndOfEarlyData ends the early data, and the client's handshake keys apply from the next record on.
        private bool OnEndOfEarlyData(byte[] message, IHandshakeDatagram parsed)
        {
            if (parsed is not EndOfEarlyDataDatagram)
                return false;
            if (IsDatagram || _earlyKeys == null || TlsReadKeysOverride != _earlyKeys)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Unexpected EndOfEarlyData.");
            Session.Transcript.AddHandshake(message);
            TlsReadKeysOverride = null;
            return true;
        }

        // TLS: the ClientHello (or, after a HelloRetryRequest, ClientHello2) arrives on the connection's own stream.
        private void OnTlsClientHello(byte[] record)
        {
            if (record[5] != 0x01 || _clientHello != null)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[5]:X2}");
            InspectReceivedRecord(record);

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
            if (OnEndOfEarlyData(message, parsed))
                return;
            if (TlsReadKeysOverride != null)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Handshake message before EndOfEarlyData.");

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
            InspectSecret(TlsInspector.ResumptionMasterSecret, Session.ResumptionMasterSecret);

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
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        /// <summary>Sends another session ticket (RFC 8446 §4.6.1); one is sent automatically after the handshake.</summary>
        public override void SendNewSessionTicket()
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
        public override bool AllowsPostHandshakeAuthentication => _clientHello?.Extensions.OfType<PostHandshakeAuthExtension>().Any() == true;

        /// <summary>
        /// Asks the client for its certificate after the handshake (RFC 8446 §4.6.2). The answer is checked like one in
        /// the handshake (ClientCertificateValidator or ClientRawPublicKeyValidator, CertificateVerify, Finished); with
        /// <paramref name="required"/> an answer without a certificate is a certificate_required alert.
        /// </summary>
        public override void RequestClientCertificate(bool required = true) => Locked(() =>
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
                        auth.Certificate = SharpDTLS.Protocol12.Tls12ClientConnection.ParseCertificate(certificate.Certificate);
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
                    RaisePostHandshakeAuthenticationCompleted();
                    return true;
                }

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected message 0x{message[0]:X2} in post-handshake authentication.");
            }
        }
    }
}
