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

        public event EventHandler<EventArgs> HandshakeFinished;
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

        /// <summary>Smallest finite-field Diffie-Hellman prime accepted from a server.</summary>
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
            var offered = (CipherSuites ?? SharpDTLS.CipherSuites.DefaultFor(MinimumVersion, MaximumVersion, includePsk: havePsk))
                .Where(id => SharpDTLS.CipherSuites.TryGet(id, out var s) && (s.IsUsableWith(MaximumVersion) || s.IsUsableWith(MinimumVersion))
                             && (havePsk || !s.RequiresPsk))
                .ToList();
            var offeredSuites = offered.Select(id => SharpDTLS.CipherSuites.Get(id)).ToList();
            if (offered.Count == 0)
                throw new InvalidOperationException("No configured cipher suite is usable with the configured versions.");

            var ch = new ClientHelloMessage
            {
                ClientVersion = MaximumVersion,
                Random = ClientRandom,
                Cookie = cookie,
                CipherSuites = offered,
            };

            // Supported groups: elliptic curves, plus the RFC 7919 FFDHE groups when DHE suites are offered.
            var groups = EcdheGroups.Supported.ToList();
            if (offeredSuites.Any(s => s.KeyExchange is KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_DSS
                                      or KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE))
                groups.AddRange(FfdheGroups.Supported);
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

            // Certificate (only when requested). Send ours only if its type and a signature scheme are accepted.
            bool authenticate = false;
            if (_certificateRequest != null)
            {
                authenticate = ClientCertificate != null && ClientCertificateKeyPair != null
                    && CertificateTypeAccepted(_certificateRequest, ClientCertificateKeyPair.Private)
                    && (!IsDtls12 || Dtls12Signatures.SelectScheme(ClientCertificateKeyPair.Private, _certificateRequest.SignatureAlgorithms) != null);

                var certificate = new CertificateMessage();
                if (authenticate)
                    certificate.Chain.Add(ClientCertificate.GetEncoded());
                SendHandshake(HandshakeType.Certificate, certificate.Encode());
            }

            SendHandshake(HandshakeType.ClientKeyExchange, _keyExchange.CreateClientKeyExchange(out byte[] preMasterSecret));
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
            _state = State.Connected;
            IsHandshakeComplete = true;
            Debug.WriteLine($"{LogPrefix} Handshake complete");
            RaiseEvent(() => HandshakeFinished?.Invoke(this, EventArgs.Empty));
        }

        private void OnPostHandshakeMessage(byte type, byte[] body)
        {
            switch (type)
            {
                case HandshakeType.NewSessionTicket:
                    var ticket = NewSessionTicketMessage.Decode(body);
                    RaiseEvent(() => NewSessionTicketMessageReceived?.Invoke(this, ticket));
                    break;

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
            _ => true,
        };

        // RFC 5246 §7.4.4 ClientCertificateType: rsa_sign(1), dss_sign(2), ecdsa_sign(64)
        internal static bool CertificateTypeAccepted(CertificateRequestMessage request, AsymmetricKeyParameter key)
            => key is RsaKeyParameters ? request.CertificateTypes.Contains((byte)1)
             : key is DsaKeyParameters ? request.CertificateTypes.Contains((byte)2)
             : key is ECKeyParameters ? request.CertificateTypes.Contains((byte)64)
             : false;
    }
}
