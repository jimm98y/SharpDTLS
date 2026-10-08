using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS13
{
    public class Dtls13Client : Dtls13Connection
    {
        private const ushort GroupX25519 = 0x001d;

        private enum State
        {
            Start,
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
        private readonly List<OfferedPsk> _offeredPsks = new();
        private OfferedPsk _selectedPsk;
        private bool _earlyDataOffered;

        /// <summary>A PSK offered in pre_shared_key: a resumption ticket or the external PSK.</summary>
        private sealed record OfferedPsk(byte[] Identity, uint ObfuscatedAge, byte[] Key, Dtls13CipherSuite HashSuite,
            Dtls13SessionTicket Ticket);

        public event EventHandler<EventArgs> HandshakeFinished;

        /// <summary>A ticket from an earlier connection to resume with (PSK resumption, RFC 8446 §2.2).</summary>
        public Dtls13SessionTicket ResumptionTicket { get; set; }

        /// <summary>Advertise psk_dhe_ke so the server issues tickets, and offer <see cref="ResumptionTicket"/>.</summary>
        public bool UseSessionTickets { get; set; } = true;

        /// <summary>The most recent ticket the server issued on this connection, or null.</summary>
        public Dtls13SessionTicket SessionTicket { get; private set; }

        /// <summary>Whether the server accepted <see cref="ResumptionTicket"/>.</summary>
        public bool IsResumed { get; private set; }

        /// <summary>
        /// An externally provisioned PSK to authenticate with (RFC 8446 §4.2.11), offered after any resumption ticket.
        /// The server is then not authenticated by a certificate.
        /// </summary>
        public Dtls13ExternalPsk ExternalPsk { get; set; }

        /// <summary>Whether the handshake was authenticated with <see cref="ExternalPsk"/>.</summary>
        public bool IsExternalPsk { get; private set; }

        /// <summary>
        /// PSK key exchange modes to offer (RFC 8446 §4.2.9). The default psk_dhe_ke keeps forward secrecy; offering
        /// only psk_ke drops the key share entirely, for peers that cannot afford (EC)DHE.
        /// </summary>
        public byte[] PskKeyExchangeModes { get; set; } = { PskKeyExchangeModesExtension.PskDheKe };

        private bool OffersPskDhe => PskKeyExchangeModes.Contains(PskKeyExchangeModesExtension.PskDheKe);

        /// <summary>
        /// 0-RTT data to send right after the ClientHello when resuming with a ticket that allows it (RFC 8446 §2.3).
        /// It is sent at most once, may be replayed by an attacker, and is lost when the server declines it
        /// (<see cref="EarlyDataAccepted"/> false): send it again after the handshake in that case.
        /// </summary>
        public byte[] EarlyData { get; set; }

        /// <summary>Whether the server accepted <see cref="EarlyData"/>.</summary>
        public bool EarlyDataAccepted { get; private set; }

        public IClientTransport ClientTransport { get; }

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        /// <summary>Cipher suites to offer, in preference order: the defaults in <see cref="Dtls13CipherSuite.Supported"/>, or any of <see cref="Dtls13CipherSuite.All"/>.</summary>
        public IList<ushort> CipherSuites { get; set; } = new List<ushort>(Dtls13CipherSuite.Supported);

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0001, 0x0007 };

        /// <summary>The server's end-entity certificate once the handshake has progressed past Certificate.</summary>
        public X509Certificate ServerCertificate => _serverCertificate;

        /// <summary>
        /// Optional server certificate validation. Return false to abort with bad_certificate.
        /// When null, any certificate is accepted (only proof of key possession is checked).
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator { get; set; }

        public Dtls13Client(IClientTransport clientTransport)
            : base(isClient: true, send: data => clientTransport.Send(data))
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += (_, data) => ProcessDatagram(data);
        }

        public void BeginHandshake()
        {
            Run(() =>
            {
                if (_state != State.Start)
                    throw new InvalidOperationException("The handshake has already started.");

                foreach (var suite in CipherSuites)
                    if (!Dtls13CipherSuite.IsSupported(suite))
                        throw new InvalidOperationException($"Cipher suite 0x{suite:X4} is not supported.");

                var (privateKey, publicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
                Session.PrivateKey = privateKey.GetEncoded();
                Session.PublicKey = publicKey.GetEncoded();

                _clientHello = BuildClientHello(Dtls13CryptoUtils.GenerateRandom(32), cookie: null);

                BeginFlight();
                byte[] record = SendPlaintextHandshake(_clientHello);
                Session.Transcript.AddPlaintextRecord(record);
                if (_earlyDataOffered)
                    SendEarlyData();
                _state = State.WaitServerHello;
                ArmRetransmission();
            });
        }

        private ClientHelloDatagram BuildClientHello(byte[] random, byte[] cookie)
        {
            var clientHello = new ClientHelloDatagram(Session.PublicKey) { ClientRandom = random };
            clientHello.CipherSuites = new List<ushort>(CipherSuites);

            // Advertise only what is implemented.
            clientHello.Extensions.RemoveAll(e => e is ClientSignatureAlgorithms || e is EncryptThenMac);
            clientHello.Extensions.Add(new ClientSignatureAlgorithms(Dtls13Signatures.Supported));

            if (SrtpProtectionProfiles != null && SrtpProtectionProfiles.Length > 0)
                clientHello.Extensions.Add(new UseSrtpExtension(SrtpProtectionProfiles));
            if (cookie != null)
                clientHello.Extensions.Add(new CookieExtension(cookie));

            if (UseSessionTickets || ExternalPsk != null)
            {
                // psk_ke only: no (EC)DHE at all, so no key share (the handshake then needs the PSK to be accepted).
                if (!OffersPskDhe && (ExternalPsk != null || (UseSessionTickets && ResumptionTicket is { IsExpired: false })))
                {
                    clientHello.Extensions.RemoveAll(e => e is ClientKeyShareExtension || e is SupportedGroups);
                    Session.PrivateKey = null;
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
                ? Dtls13CipherSuite.Get(_hrrCipherSuite).HashAlgorithm == hashSuite.HashAlgorithm
                : CipherSuites.Any(id => Dtls13CipherSuite.Get(id).HashAlgorithm == hashSuite.HashAlgorithm);

            var ticket = ResumptionTicket;
            if (UseSessionTickets && ticket != null && !ticket.IsExpired && Dtls13CipherSuite.IsSupported(ticket.CipherSuite)
                && Compatible(Dtls13CipherSuite.Get(ticket.CipherSuite)))
                _offeredPsks.Add(new OfferedPsk(ticket.Ticket, ticket.ObfuscatedAge, ticket.Psk, Dtls13CipherSuite.Get(ticket.CipherSuite), ticket));

            // External PSKs have no age: obfuscated_ticket_age is 0 (RFC 8446 §4.2.11).
            if (ExternalPsk != null && Compatible(Dtls13CipherSuite.Get(ExternalPsk.CipherSuite)))
                _offeredPsks.Add(new OfferedPsk(ExternalPsk.Identity, 0, ExternalPsk.Key, Dtls13CipherSuite.Get(ExternalPsk.CipherSuite), null));

            if (_offeredPsks.Count == 0)
                return;

            // 0-RTT only with the ticket as the first identity, within its limit and with its suite offered
            // (the server must select it), and never after a HelloRetryRequest (RFC 8446 §4.2.10).
            var first = _offeredPsks[0];
            _earlyDataOffered = EarlyData != null && first.Ticket != null && !_receivedHelloRetryRequest
                                && first.Ticket.MaxEarlyDataSize >= EarlyData.Length && CipherSuites.Contains(first.Ticket.CipherSuite);
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

        // Epoch 1, under client_early_traffic_secret of the ticket's suite; not part of any flight.
        private void SendEarlyData()
        {
            var ticketSuite = Dtls13CipherSuite.Get(_offeredPsks[0].Ticket.CipherSuite);
            var earlyKeys = Dtls13CryptoUtils.CalculateEarlyKeys(_clientHello.ClientRandom, Session.Transcript.Hash(ticketSuite), _offeredPsks[0].Key, ticketSuite);
            SendProtected(earlyKeys, new ApplicationDataDatagram(EarlyData).ToBytes());
        }

        // ── ServerHello / HelloRetryRequest ──────────────────────────────────────────────────

        protected override void OnPlaintextHandshake(byte[] record)
        {
            if (record[13] != 0x02)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[13]:X2}");

            // Retransmitted ServerHello/HelloRetryRequest (e.g. answering a retransmitted ClientHello): ignore.
            int messageSeq = (record[17] << 8) | record[18];
            if (_state != State.WaitServerHello || messageSeq < NextReceiveMessageSeq)
                return;

            var serverHello = new ServerHelloDatagram();
            serverHello.FromBytes(record);
            ValidateServerHello(serverHello);

            if (HelloRetryRequest.IsHelloRetryRequest(serverHello))
                OnHelloRetryRequest(record, serverHello);
            else
                OnServerHello(record, serverHello);
        }

        private void ValidateServerHello(ServerHelloDatagram serverHello)
        {
            if (serverHello.Bytes[25] != 0xFE || serverHello.Bytes[26] != 0xFD)
                throw new DtlsException(AlertDescription.ProtocolVersion, "ServerHello legacy_version must be DTLS 1.2.");

            var versions = serverHello.Extensions.OfType<ServerSupportedVersions>().FirstOrDefault();
            if (versions == null)
                throw new DtlsException(AlertDescription.ProtocolVersion, "Server did not negotiate DTLS 1.3.");

            if (!CipherSuites.Contains(serverHello.SelectedCipherSuite))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected a cipher suite that was not offered (0x{serverHello.SelectedCipherSuite:X4}).");

            // RFC 9147 §5: DTLS 1.3 servers must not echo legacy_session_id.
            if (serverHello.LegacySessionIdEcho.Length != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "DTLS 1.3 ServerHello echoes a legacy_session_id.");
        }

        private void OnHelloRetryRequest(byte[] record, ServerHelloDatagram hrr)
        {
            if (_receivedHelloRetryRequest)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Received a second HelloRetryRequest.");

            _receivedHelloRetryRequest = true;
            _hrrCipherSuite = hrr.SelectedCipherSuite;
            var suite = Dtls13CipherSuite.Get(hrr.SelectedCipherSuite);

            var keyShare = hrr.Extensions.OfType<ServerKeyShareExtension>().FirstOrDefault();
            var cookie = hrr.Extensions.OfType<CookieExtension>().FirstOrDefault();

            // RFC 8446 §4.1.4: the HRR must change something, and may only ask for a group we offered
            // but have not sent a share for. x25519 is the only group offered (and its share is sent).
            if (keyShare != null)
                throw new DtlsException(AlertDescription.IllegalParameter, $"HelloRetryRequest selected group 0x{keyShare.KeyType:X4}, which already had a key share.");
            if (cookie == null)
                throw new DtlsException(AlertDescription.IllegalParameter, "HelloRetryRequest would not change the ClientHello.");

            // RFC 8446 §4.4.1: Transcript = message_hash(Hash(ClientHello1)) || HelloRetryRequest || ...
            Session.Transcript.ReplaceWithMessageHash(suite);
            Session.Transcript.AddPlaintextRecord(record);
            NextReceiveMessageSeq = hrr.SequenceNumber + 1;

            _clientHello = BuildClientHello(_clientHello.ClientRandom, cookie.Cookie);

            BeginFlight();
            byte[] clientHello2 = SendPlaintextHandshake(_clientHello);
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
            if (keyShare != null && (keyShare.KeyType != GroupX25519 || Session.PrivateKey == null))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected group 0x{keyShare.KeyType:X4}, which was not offered.");

            StopRetransmission();

            var suite = Dtls13CipherSuite.Get(serverHello.SelectedCipherSuite);
            Session.CipherSuite = suite;

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
                IsResumed = _selectedPsk.Ticket != null;
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

            Session.Transcript.AddPlaintextRecord(record);
            NextReceiveMessageSeq = serverHello.SequenceNumber + 1;

            byte[] sharedSecret = keyShare == null ? null : Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, keyShare.PublicKey);
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

                    var srtp = encryptedExtensions.Extensions.OfType<UseSrtpExtension>().FirstOrDefault();
                    if (srtp != null)
                    {
                        // RFC 5764 §4.1.1: exactly one profile, and one we offered
                        if (srtp.SrtpProtectionProfiles.Length != 1 || SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SrtpProtectionProfiles[0]))
                            throw new DtlsException(AlertDescription.IllegalParameter, "Server selected an SRTP profile that was not offered.");
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
                    if (!Dtls13Signatures.Verify(scheme, _serverCertificate.GetPublicKey(), content, certificateVerify.Signature))
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

            Session.PeerCertificate = certificate.Certificate;
            if (ServerCertificateValidator != null && !ServerCertificateValidator(_serverCertificate, certificate.CertificateChain))
                throw new DtlsException(AlertDescription.BadCertificate, "Server certificate was rejected.");
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
                Session.PeerCertificate, nst.MaxEarlyDataSize);
        }

        private void SendClientCertificate()
        {
            var suite = Session.CipherSuite;
            var keys = Session.ServerHandshakeKeys;

            // Send our certificate only if we can sign with a scheme the server accepts.
            ushort? scheme = null;
            if (ClientCertificate != null && ClientCertificateKeyPair != null)
                scheme = Dtls13Signatures.SelectScheme(ClientCertificateKeyPair.Private, _certificateRequest.SignatureAlgorithms);

            var chain = scheme.HasValue ? new[] { ClientCertificate.GetEncoded() } : Array.Empty<byte[]>();
            SendHandshake(new CertificateDatagram(chain, _certificateRequest.RequestContext), keys);

            if (scheme.HasValue)
            {
                byte[] content = Dtls13Signatures.BuildSignedContent(server: false, Session.Transcript.Hash(suite));
                byte[] signature = Dtls13Signatures.Sign(scheme.Value, ClientCertificateKeyPair.Private, content);
                SendHandshake(new CertificateVerifyDatagram(signature, scheme.Value), keys);
            }

            Debug.WriteLine($"[DTLS13 Client] Sent Certificate ({chain.Length} entries)");
        }
    }
}
