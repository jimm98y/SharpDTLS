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

        public event EventHandler<EventArgs> HandshakeFinished;

        public IClientTransport ClientTransport { get; }

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        /// <summary>Cipher suites to offer, in preference order. Must be a subset of <see cref="Dtls13CipherSuite.Supported"/>.</summary>
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

            return clientHello;
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

            if (!serverHello.LegacySessionIdEcho.AsSpan().SequenceEqual(_clientHello.LegacySessionId))
                throw new DtlsException(AlertDescription.IllegalParameter, "legacy_session_id_echo does not match.");
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

            var keyShare = serverHello.Extensions.OfType<ServerKeyShareExtension>().FirstOrDefault();
            if (keyShare == null || keyShare.PublicKey == null)
                throw new DtlsException(AlertDescription.MissingExtension, "ServerHello has no key_share.");
            if (keyShare.KeyType != GroupX25519)
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected group 0x{keyShare.KeyType:X4}, which was not offered.");

            StopRetransmission();

            var suite = Dtls13CipherSuite.Get(serverHello.SelectedCipherSuite);
            Session.CipherSuite = suite;
            Session.Transcript.AddPlaintextRecord(record);
            NextReceiveMessageSeq = serverHello.SequenceNumber + 1;

            byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, keyShare.PublicKey);
            var handshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), sharedSecret, suite);

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
                    var srtp = encryptedExtensions.Extensions.OfType<UseSrtpExtension>().FirstOrDefault();
                    if (srtp != null)
                    {
                        // RFC 5764 §4.1.1: exactly one profile, and one we offered
                        if (srtp.SrtpProtectionProfiles.Length != 1 || SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SrtpProtectionProfiles[0]))
                            throw new DtlsException(AlertDescription.IllegalParameter, "Server selected an SRTP profile that was not offered.");
                        SelectedSrtpProtectionProfile = srtp.SrtpProtectionProfiles[0];
                    }
                    Session.Transcript.AddHandshake(message);
                    _state = State.WaitCertificateOrCertificateRequest;
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
