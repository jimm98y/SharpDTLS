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
    /// <summary>Configuration shared by all associations of a DTLS 1.0/1.2 server.</summary>
    public sealed class Dtls12ServerSettings
    {
        public AsymmetricCipherKeyPair KeyPair { get; set; }
        public X509Certificate Certificate { get; set; }
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>Cipher suites in server preference order; null for all implemented suites.</summary>
        public IList<ushort> CipherSuites { get; set; }

        public bool RequireClientCertificate { get; set; }
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator { get; set; }

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
    }

    /// <summary>
    /// Server side of one DTLS 1.0/1.2 association, created once the ClientHello has passed the cookie
    /// exchange (RFC 6347 §4.2.1).
    /// </summary>
    public class Dtls12ServerConnection : Dtls12Connection
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

        private readonly Dtls12ServerSettings _settings;
        private State _state = State.Start;
        private ClientHelloMessage _clientHello;
        private CertificateRequestMessage _certificateRequest;
        private IServerKeyExchange _keyExchange;
        private X509Certificate _clientCertificate;
        private Dtls12SessionState _resumedSession;
        private byte[] _sessionId = Array.Empty<byte>();

        public event EventHandler<EventArgs> HandshakeFinished;

        public Dtls12ServerConnection(Dtls12ServerSettings settings, EndPoint remoteEndPoint, Action<byte[]> send)
            : base(isClient: false, send)
        {
            _settings = settings;
            RemoteEndPoint = remoteEndPoint;
            MinimumVersion = settings.MinimumVersion;
            MaximumVersion = settings.MaximumVersion;
            InitialRetransmitTimeout = settings.InitialRetransmitTimeout;
            KeyLogWriter = settings.KeyLogWriter;
        }

        public EndPoint RemoteEndPoint { get; }

        /// <summary>The client's certificate, when one was sent.</summary>
        public X509Certificate ClientCertificate => _clientCertificate;

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

            Negotiate();

            ResetTranscript();
            AddToTranscript(message);
            SendServerFlight();
        });

        private void Negotiate()
        {
            var ch = _clientHello;

            // Highest version both sides support (DTLS version numbers count down).
            ushort version = new[] { DtlsVersion.Dtls12, DtlsVersion.Dtls10 }
                .FirstOrDefault(v => DtlsVersion.IsAtLeast(MaximumVersion, v) && DtlsVersion.IsAtLeast(v, MinimumVersion)
                                     && DtlsVersion.IsAtLeast(ch.ClientVersion, v));
            if (version == 0)
                throw new DtlsException(AlertDescription.ProtocolVersion, $"Client version {DtlsVersion.Name(ch.ClientVersion)} is not supported.");
            NegotiatedVersion = version;

            // RFC 7507 §3: a client that fell back below our highest version is being downgraded.
            if (ch.CipherSuites.Contains(SharpDTLS.CipherSuites.TLS_FALLBACK_SCSV) && ch.ClientVersion != MaximumVersion
                && DtlsVersion.IsAtLeast(MaximumVersion, ch.ClientVersion))
                throw new DtlsException(AlertDescription.InappropriateFallback, $"Client fell back to {DtlsVersion.Name(ch.ClientVersion)}.");

            if (!ch.CompressionMethods.Contains((byte)0))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client does not offer null compression.");

            var renegotiationInfo = ch.Extension<RenegotiationInfoExtension>();
            if (renegotiationInfo != null && renegotiationInfo.RenegotiatedConnection.Length != 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Non-empty renegotiation_info in initial handshake.");

            ClientRandom = ch.Random;
            ServerRandom = Dtls12CryptoUtils.GenerateRandom(32);
            SelectedSrtpProtectionProfile = DtlsSrtp.Select(_settings.SrtpProtectionProfiles, ch.Extension<UseSrtpExtension>()?.ProtectionProfiles);

            if (TryResume(ch, version))
                return;

            var serverKey = _settings.KeyPair?.Private;
            // Without explicit configuration weak suites (export, DES, NULL, anonymous...) are never selected.
            var preference = _settings.CipherSuites
                ?? SharpDTLS.CipherSuites.All.Where(s => s.Security != CipherSuiteSecurity.Weak).Select(s => s.Id).ToList();
            CipherSuite = preference
                .Where(id => ch.CipherSuites.Contains(id))
                .Select(id => SharpDTLS.CipherSuites.TryGet(id, out var s) ? s : null)
                .FirstOrDefault(s => s != null && s.IsUsableWith(version)
                    && (s.ServerCertificateType == CertificateKeyType.None || (serverKey != null && Dtls12ClientConnection.KeyMatches(s.ServerCertificateType, serverKey)))
                    && (!s.IsStaticKeyAgreement || Dtls12ClientConnection.SignedWith(_settings.Certificate, s.RequiredCertificateSigner))
                    && (!s.RequiresPsk || _settings.PskIdentityResolver != null)
                    && (!s.RequiresSrp || (_settings.SrpVerifierProvider != null && ch.Extension<SrpExtension>() != null))
                    && (!s.RequiresPwd || (_settings.PwdCredentialProvider != null && EccPwd.HasUsername(ch, _settings.PwdProtectionKey)
                                           && EccPwd.SelectGroup(ch) != 0)))
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common.");

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

            // A new session gets an ID only when it will be resumable (RFC 7627 §5.3: EMS sessions only).
            if (_settings.SessionCache != null && UseExtendedMasterSecret)
                _sessionId = Dtls12CryptoUtils.GenerateRandom(32);
        }

        /// <summary>
        /// Accepts the session the client offers by ID when it is cached, uses the negotiated version, a suite
        /// the client still offers and we still allow, and the same encrypt-then-MAC setting (RFC 5246 §7.4.1.2).
        /// </summary>
        private bool TryResume(ClientHelloMessage ch, ushort version)
        {
            if (ch.SessionId.Length == 0 || _settings.SessionCache == null)
                return false;
            var session = _settings.SessionCache.Find(ch.SessionId);
            if (session == null)
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
            _sessionId = session.SessionId;
            CipherSuite = suite;
            UseExtendedMasterSecret = true;
            UseEncryptThenMac = session.EncryptThenMac;
            if (session.PeerCertificate != null)
                _clientCertificate = Dtls12ClientConnection.ParseCertificate(session.PeerCertificate);
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
            SendHandshake(HandshakeType.ServerHello, sh.Encode());

            if (IsResumed)
            {
                // Abbreviated handshake: ServerHello, ChangeCipherSpec, Finished; the client answers with its own.
                DeriveKeysFromMasterSecret(_resumedSession.MasterSecret);
                SendChangeCipherSpec();
                SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: false));
                ArmRetransmission();
                _state = State.WaitFinished;
                Debug.WriteLine($"{LogPrefix} Resuming session: {DtlsVersion.Name(NegotiatedVersion)}, {CipherSuite}");
                return;
            }

            bool certificateBased = CipherSuite.ServerCertificateType != CertificateKeyType.None;
            if (certificateBased)
            {
                var certificate = new CertificateMessage();
                certificate.Chain.Add(_settings.Certificate.GetEncoded());
                SendHandshake(HandshakeType.Certificate, certificate.Encode());
            }

            byte[] serverParams = _keyExchange.CreateServerParams();
            if (serverParams != null)
            {
                var ske = new TlsWriter().WriteBytes(serverParams);
                if (_keyExchange.SignsParams)
                {
                    byte[] signed = Concat(Concat(ClientRandom, ServerRandom), serverParams);
                    byte[] signature = Sign(_settings.KeyPair.Private, signed, ch.Extension<SignatureAlgorithmsExtension>()?.Algorithms, out ushort? scheme);
                    if (scheme.HasValue)
                        ske.WriteUInt16(scheme.Value);
                    ske.WriteOpaque16(signature);
                }
                SendHandshake(HandshakeType.ServerKeyExchange, ske.ToArray());
            }

            if (_settings.RequireClientCertificate && certificateBased)
            {
                _certificateRequest = new CertificateRequestMessage();
                if (CipherSuite.IsStaticKeyAgreement)
                    _certificateRequest.CertificateTypes = new byte[] { 1, 2, 64, 3, 4, 65, 66 }; // also the fixed (EC)DH types
                SendHandshake(HandshakeType.CertificateRequest, _certificateRequest.Encode(NegotiatedVersion));
            }

            SendHandshake(HandshakeType.ServerHelloDone, Array.Empty<byte>());
            ArmRetransmission();
            _state = _certificateRequest != null ? State.WaitClientCertificate : State.WaitClientKeyExchange;
            Debug.WriteLine($"{LogPrefix} Sent server flight: {DtlsVersion.Name(NegotiatedVersion)}, {CipherSuite}");
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
                    _state = _clientCertificate != null && !fixedKeyAgreement ? State.WaitCertificateVerify : State.WaitFinished;
                    break;

                case State.WaitCertificateVerify when type == HandshakeType.CertificateVerify:
                    var cv = CertificateVerifyMessage.Decode(body, NegotiatedVersion);
                    if (!Verify(_clientCertificate.GetPublicKey(), TranscriptBytes(), cv.SignatureScheme, cv.Signature, _certificateRequest.SignatureAlgorithms))
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
            var certificate = CertificateMessage.Decode(body);
            if (certificate.Chain.Count == 0)
            {
                if (_settings.RequireClientCertificate)
                    throw new DtlsException(AlertDescription.HandshakeFailure, "Client did not send a certificate.");
            }
            else
            {
                _clientCertificate = Dtls12ClientConnection.ParseCertificate(certificate.Chain[0]);
                if (!Dtls12ClientConnection.CertificateTypeAccepted(_certificateRequest, _clientCertificate.GetPublicKey())
                    && !(CipherSuite.IsStaticKeyAgreement && Dtls12ClientConnection.FixedTypeAccepted(_certificateRequest, _clientCertificate)))
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "Client certificate type was not requested.");
                if (_settings.ClientCertificateValidator != null && !_settings.ClientCertificateValidator(_clientCertificate, certificate.Chain))
                    throw new DtlsException(AlertDescription.BadCertificate, "Client certificate was rejected.");
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
                SendChangeCipherSpec();
                SendHandshake(HandshakeType.Finished, ComputeVerifyData(fromClient: false));

                if (_sessionId.Length != 0)
                    _settings.SessionCache.Store(new Dtls12SessionState(_sessionId, NegotiatedVersion, CipherSuite.Id, MasterSecret,
                        UseEncryptThenMac, _clientCertificate?.GetEncoded()));
            }

            _state = State.Connected;
            IsHandshakeComplete = true;
            Debug.WriteLine($"{LogPrefix} Handshake complete with {RemoteEndPoint}");
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        /// <summary>
        /// Sends a NewSessionTicket after the handshake. Note: RFC 5077 tickets belong inside the
        /// handshake; session resumption is not implemented yet.
        /// </summary>
        public void SendNewSessionTicket(byte[] ticket, uint lifetimeHint) => Locked(() =>
        {
            if (!IsHandshakeComplete)
                throw new InvalidOperationException("The handshake has not completed.");
            SendHandshakeNoFlight(HandshakeType.NewSessionTicket, new NewSessionTicketMessage { LifetimeHint = lifetimeHint, Ticket = ticket }.Encode());
        });
    }
}
