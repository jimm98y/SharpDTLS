using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// Client side of a DTLS 1.0/1.2 association (RFC 6347 §4.2, RFC 5246 §7.3).
    /// </summary>
    public class Dtls12ClientConnection : Dtls12Connection
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

        public Dtls12ClientConnection(Action<byte[]> send) : base(isClient: true, send)
        {
        }

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        /// <summary>Cipher suites to offer in preference order; null for the defaults of the version range.</summary>
        public IList<ushort> CipherSuites { get; set; }

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80, DtlsSrtp.SRTP_AEAD_AES_128_GCM };

        /// <summary>
        /// Optional server certificate validation. Return false to abort with bad_certificate.
        /// When null, any certificate is accepted (only proof of key possession is checked).
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator { get; set; }

        /// <summary>The server's end-entity certificate once received.</summary>
        public X509Certificate ServerCertificate => _serverCertificate;

        /// <summary>The negotiated (EC)DHE group, or 0 (RSA key exchange, or custom DH parameters).</summary>
        public ushort NamedGroup => _keyExchange?.Group ?? 0;

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
        public bool IsResumed { get; private set; }

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
            bool presentTicket = resumable?.Ticket != null && UseSessionTickets;
            _offeredSession = resumable != null && (presentTicket || resumable.SessionId.Length != 0) && offered.Contains(resumable.CipherSuite)
                              && DtlsVersion.IsAtLeast(resumable.Version, MinimumVersion) && DtlsVersion.IsAtLeast(MaximumVersion, resumable.Version)
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
            if (MaximumVersion == DtlsVersion.Dtls12)
                ch.Extensions.Add(new SignatureAlgorithmsExtension(Dtls12Signatures.Supported));
            if (offeredSuites.Any(s => s.IsCbc))
                ch.Extensions.Add(new EncryptThenMacExtension());
            ch.Extensions.Add(new ExtendedMasterSecretExtension());
            ch.Extensions.Add(new RenegotiationInfoExtension());
            if (SrtpProtectionProfiles != null && SrtpProtectionProfiles.Length > 0)
                ch.Extensions.Add(new UseSrtpExtension(SrtpProtectionProfiles));
            if (UseSessionTickets)
                ch.Extensions.Add(new SessionTicketExtension(presentTicket && _offeredSession != null ? _offeredSession.Ticket : null));
            if (offeredSuites.Any(s => s.RequiresSrp))
                ch.Extensions.Add(new SrpExtension(SrpIdentity));
            if (offeredSuites.Any(s => s.RequiresPwd))
                ch.Extensions.Add(PwdProtectionKey != null
                    ? new PwdProtectExtension(EccPwd.ProtectUsername(PwdUsername, PwdProtectionKey, new Org.BouncyCastle.Security.SecureRandom()))
                    : new PwdClearExtension(EccPwd.PrepareOpaqueString(PwdUsername)));

            _clientHello = ch;

            // The initial ClientHello and HelloVerifyRequest are not part of the transcript (RFC 6347 §4.2.6).
            ResetTranscript();
            BeginFlight();
            SendHandshake(HandshakeType.ClientHello, ch.Encode());
            ArmRetransmission();
            _state = State.WaitServerHello;
            Debug.WriteLine($"{LogPrefix} Sent ClientHello (cookie {cookie.Length} bytes)");
        }

        protected override void OnHandshakeMessage(byte type, byte[] body, byte[] message, ushort epoch)
        {
            if (IsHandshakeComplete)
            {
                OnPostHandshakeMessage(type, body);
                return;
            }

            switch (_state)
            {
                case State.WaitServerHello when type == HandshakeType.HelloVerifyRequest:
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
            if ((sh.ServerVersion != DtlsVersion.Dtls10 && sh.ServerVersion != DtlsVersion.Dtls12)
                || !DtlsVersion.IsAtLeast(sh.ServerVersion, MinimumVersion)
                || !DtlsVersion.IsAtLeast(MaximumVersion, sh.ServerVersion))
                throw new DtlsException(AlertDescription.ProtocolVersion, $"Server selected unsupported version {DtlsVersion.Name(sh.ServerVersion)}.");

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

            // An empty SessionTicket extension announces a NewSessionTicket before the server's ChangeCipherSpec.
            _ticketExpected = sh.Extension<SessionTicketExtension>() != null;
            if (_ticketExpected && _clientHello.Extension<SessionTicketExtension>() == null)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited SessionTicket extension.");

            var srtp = sh.Extension<ServerUseSrtpExtension>();
            if (srtp != null)
            {
                if (SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SelectedProfile))
                    throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected SRTP profile 0x{srtp.SelectedProfile:X4}, which was not offered.");
                SelectedSrtpProtectionProfile = srtp.SelectedProfile;
            }

            NegotiatedVersion = sh.ServerVersion;
            CipherSuite = suite;
            ServerRandom = sh.Random;
            AddToTranscript(message);
            Debug.WriteLine($"{LogPrefix} ServerHello: {DtlsVersion.Name(NegotiatedVersion)}, {suite}");

            if (_offeredSession != null && sh.SessionId.AsSpan().SequenceEqual(_offeredSessionId))
            {
                // Abbreviated handshake: the server's ChangeCipherSpec and Finished follow (RFC 5246 §7.3).
                var session = _offeredSession;
                if (sh.ServerVersion != session.Version || sh.CipherSuite != session.CipherSuite || UseEncryptThenMac != session.EncryptThenMac)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Server resumed the session with different parameters.");
                // RFC 7627 §5.3: resumable sessions use the extended master secret, so the ServerHello must too.
                if (!UseExtendedMasterSecret)
                    throw new DtlsException(AlertDescription.HandshakeFailure, "Server resumed without the extended master secret.");

                IsResumed = true;
                SessionState = session;
                if (session.PeerCertificate != null)
                    _serverCertificate = ParseCertificate(session.PeerCertificate);
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
            var certificate = CertificateMessage.Decode(body);
            if (certificate.Chain.Count == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Server sent an empty Certificate.");

            _serverCertificate = ParseCertificate(certificate.Chain[0]);
            if (!KeyMatches(CipherSuite.ServerCertificateType, _serverCertificate.GetPublicKey()))
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "Server certificate key does not match the cipher suite.");
            if (ServerCertificateValidator != null && !ServerCertificateValidator(_serverCertificate, certificate.Chain))
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate was rejected.");

            AddToTranscript(message);
            CreateKeyExchange();
        }

        private void CreateKeyExchange()
        {
            _keyExchange = KeyExchanges.CreateClient(CipherSuite, new ClientKeyExchangeContext
            {
                ClientHelloVersion = _clientHello.ClientVersion,
                ServerPublicKey = _serverCertificate?.GetPublicKey(),
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
                if (!Verify(_serverCertificate.GetPublicKey(), signed, scheme, signature, Dtls12Signatures.Supported))
                    throw new DtlsException(AlertDescription.DecryptError, "ServerKeyExchange signature is invalid.");
            }
            r.EnsureEnd();

            AddToTranscript(message);
            _state = State.WaitCertificateRequestOrDone;
        }

        private void SendFinalFlight()
        {
            BeginFlight();

            // Certificate (only when requested). Send ours only if its type and a signature scheme are accepted,
            // or, with static (EC)DH, if it holds a key agreement key on the server's parameters (fixed (EC)DH).
            bool authenticate = false;
            bool fixedKeyAgreement = false;
            if (_certificateRequest != null && ClientCertificate != null && ClientCertificateKeyPair != null)
            {
                var key = ClientCertificateKeyPair.Private;
                fixedKeyAgreement = CipherSuite.IsStaticKeyAgreement && _keyExchange.SupportsFixedClientKey(key)
                    && FixedTypeAccepted(_certificateRequest, ClientCertificate);
                authenticate = !fixedKeyAgreement && CertificateTypeAccepted(_certificateRequest, key)
                    && (!IsDtls12 || Dtls12Signatures.SelectScheme(key, _certificateRequest.SignatureAlgorithms) != null);
            }

            if (_certificateRequest != null)
            {
                var certificate = new CertificateMessage();
                if (authenticate || fixedKeyAgreement)
                    certificate.Chain.Add(ClientCertificate.GetEncoded());
                SendHandshake(HandshakeType.Certificate, certificate.Encode());
            }

            byte[] preMasterSecret;
            byte[] clientKeyExchange = fixedKeyAgreement
                ? _keyExchange.CreateFixedClientKeyExchange(ClientCertificateKeyPair.Private, out preMasterSecret)
                : _keyExchange.CreateClientKeyExchange(out preMasterSecret);
            SendHandshake(HandshakeType.ClientKeyExchange, clientKeyExchange);
            DeriveKeys(preMasterSecret);

            if (authenticate)
            {
                byte[] signature = Sign(ClientCertificateKeyPair.Private, TranscriptBytes(), _certificateRequest.SignatureAlgorithms, out ushort? scheme);
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
                    UseEncryptThenMac, _serverCertificate?.GetEncoded());
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
