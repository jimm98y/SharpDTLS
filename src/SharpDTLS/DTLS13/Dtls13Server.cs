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
    public class Dtls13Server
    {
        private const ushort GroupX25519 = 0x001d;

        private readonly ConcurrentDictionary<string, Dtls13ServerConnection> _connections = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        internal AsymmetricCipherKeyPair ServerKeyPair { get; }
        internal X509Certificate ServerCertificate { get; }

        public IServerTransport ServerTransport { get; }

        /// <summary>Send a HelloRetryRequest with a cookie before allocating state (address validation, RFC 9147 §5.1).</summary>
        public bool ShouldSendHelloRetry { get; set; } = true;

        /// <summary>Request a client certificate and abort with certificate_required if none is sent.</summary>
        public bool RequireClientCertificate { get; set; } = false;

        /// <summary>Cipher suites in server preference order: the defaults in <see cref="Dtls13CipherSuite.Supported"/>, or any of <see cref="Dtls13CipherSuite.All"/>.</summary>
        public IList<ushort> CipherSuites { get; set; } = new List<ushort>(Dtls13CipherSuite.Supported);

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { 0x0007, 0x0001 };

        /// <summary>Optional client certificate validation. Return false to abort with bad_certificate.</summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator { get; set; }

        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format).</summary>
        public Action<string> KeyLogWriter { get; set; }

        public event EventHandler<EventArgs> HandshakeFinished;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;
        public event EventHandler<Dtls13DataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<Dtls13ConnectionEventArgs> ConnectionClosed;

        public Dtls13Server(IServerTransport serverTransport)
            : this(serverTransport, Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public Dtls13Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            ServerKeyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
            ServerCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

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

            if (_connections.TryGetValue(endpoint.ToString(), out var connection))
            {
                connection.ProcessDatagram(data);
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

            var versions = clientHello.Extensions.OfType<ClientSupportedVersions>().FirstOrDefault();
            if (versions == null || !versions.Versions.Contains(ClientSupportedVersions.Dtls13))
                throw new DtlsException(AlertDescription.ProtocolVersion, "Client does not support DTLS 1.3.");
            if (clientHello.LegacyCookie.Length != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "DTLS 1.3 ClientHello has a legacy_cookie.");

            var groups = clientHello.Extensions.OfType<SupportedGroups>().FirstOrDefault();
            if (groups == null || !groups.Groups.Contains(GroupX25519))
                throw new DtlsException(AlertDescription.HandshakeFailure, "No supported key exchange group in common.");

            ushort suiteId = CipherSuites.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (suiteId == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common.");

            bool hasKeyShare = clientHello.PublicKey != null;
            var ipEndpoint = (IPEndPoint)endpoint;
            string ip = ipEndpoint.Address.ToString();

            HelloRetryState retry = null;
            var cookie = clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault();
            if (cookie != null && Dtls13CryptoUtils.ValidateCookie(DateTime.UtcNow, ip, ipEndpoint.Port, cookie.Cookie,
                    out ushort cookieSuite, out byte[] clientHello1Hash, out bool keyShareRequested))
            {
                if (!clientHello.CipherSuites.Contains(cookieSuite) || !CipherSuites.Contains(cookieSuite))
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 does not offer the cipher suite selected in HelloRetryRequest.");
                if (!hasKeyShare)
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 has no x25519 key share.");

                suiteId = cookieSuite;
                retry = new HelloRetryState(clientHello1Hash, cookie.Cookie, keyShareRequested);
            }
            else if (ShouldSendHelloRetry || !hasKeyShare)
            {
                SendHelloRetryRequest(endpoint, record, clientHello, suiteId, requestKeyShare: !hasKeyShare);
                return;
            }

            var connection = new Dtls13ServerConnection(this, endpoint);
            if (!_connections.TryAdd(endpoint.ToString(), connection))
            {
                _connections[endpoint.ToString()].ProcessDatagram(datagram);
                return;
            }

            connection.Start(record, clientHello, Dtls13CipherSuite.Get(suiteId), retry);
        }

        private void SendHelloRetryRequest(EndPoint endpoint, byte[] record, ClientHelloDatagram clientHello, ushort suiteId, bool requestKeyShare)
        {
            var suite = Dtls13CipherSuite.Get(suiteId);
            var transcript = new Dtls13Transcript();
            transcript.AddPlaintextRecord(record);

            var ipEndpoint = (IPEndPoint)endpoint;
            byte[] cookie = Dtls13CryptoUtils.CreateCookie(DateTime.UtcNow, ipEndpoint.Address.ToString(), ipEndpoint.Port,
                suiteId, transcript.Hash(suite), requestKeyShare);

            var hrr = new HelloRetryRequest(suiteId, cookie, requestKeyShare ? GroupX25519 : null, clientHello.LegacySessionId)
            {
                SequenceNumber = clientHello.SequenceNumber,
                // RFC 9147 §5.1: reuse the ClientHello's record sequence number so a stateless server never repeats one.
                RecordSequenceNumber = clientHello.RecordSequenceNumber,
            };

            Debug.WriteLine($"[DTLS13 Server] Sending HelloRetryRequest to {endpoint}");
            ServerTransport.Send(endpoint, hrr.ToBytes());
        }

        private void SendPlaintextAlert(EndPoint endpoint, AlertDescription alert)
        {
            byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, (byte)alert };
            try { ServerTransport.Send(endpoint, record); }
            catch (Exception ex) { Debug.WriteLine($"[DTLS13 Server] Failed to send alert: {ex.Message}"); }
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal void OnConnectionEstablished(Dtls13ServerConnection connection)
            => HandshakeFinished?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));

        internal void OnApplicationData(Dtls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls13DataReceivedEventArgs(connection.RemoteEndPoint, connection, data));

        internal void OnKeyUpdate(KeyUpdateDatagram keyUpdate)
            => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal void OnConnectionClosed(Dtls13ServerConnection connection)
        {
            _connections.TryRemove(new KeyValuePair<string, Dtls13ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
            ConnectionClosed?.Invoke(this, new Dtls13ConnectionEventArgs(connection.RemoteEndPoint, connection));
        }

        internal sealed class HelloRetryState
        {
            public HelloRetryState(byte[] clientHello1Hash, byte[] cookie, bool keyShareRequested)
            {
                ClientHello1Hash = clientHello1Hash;
                Cookie = cookie;
                KeyShareRequested = keyShareRequested;
            }

            public byte[] ClientHello1Hash { get; }
            public byte[] Cookie { get; }
            public bool KeyShareRequested { get; }
        }
    }

    /// <summary>
    /// Server side of one DTLS 1.3 association.
    /// </summary>
    public class Dtls13ServerConnection : Dtls13Connection
    {
        private const ushort GroupX25519 = 0x001d;

        private enum State
        {
            Start,
            WaitClientCertificate,
            WaitClientCertificateVerify,
            WaitClientFinished,
            Connected,
        }

        private readonly Dtls13Server _server;
        private State _state = State.Start;
        private ClientHelloDatagram _clientHello;
        private CertificateRequestDatagram _certificateRequest;
        private X509Certificate _clientCertificate;

        public EndPoint RemoteEndPoint { get; }

        /// <summary>The client's certificate, when one was sent.</summary>
        public X509Certificate ClientCertificate => _clientCertificate;

        internal Dtls13ServerConnection(Dtls13Server server, EndPoint remoteEndPoint)
            : base(isClient: false, send: data => server.ServerTransport.Send(remoteEndPoint, data))
        {
            _server = server;
            RemoteEndPoint = remoteEndPoint;
            InitialRetransmitTimeout = server.InitialRetransmitTimeout;
            KeyLogWriter = server.KeyLogWriter;

            ApplicationDataReceived += (_, data) => _server.OnApplicationData(this, data);
            KeyUpdateReceived += (_, keyUpdate) => _server.OnKeyUpdate(keyUpdate);
            Closed += (_, _) => _server.OnConnectionClosed(this);
        }

        internal void Start(byte[] record, ClientHelloDatagram clientHello, Dtls13CipherSuite suite, Dtls13Server.HelloRetryState retry)
        {
            Run(() =>
            {
                _clientHello = clientHello;
                Session.CipherSuite = suite;

                if (retry != null)
                {
                    // Rebuild the transcript the client has: message_hash(ClientHello1) || HelloRetryRequest || ClientHello2.
                    // The HelloRetryRequest is deterministic given the cookie, so it can be recreated byte for byte.
                    var hrr = new HelloRetryRequest(suite.Id, retry.Cookie, retry.KeyShareRequested ? GroupX25519 : null, clientHello.LegacySessionId);
                    Session.Transcript.AddMessageHash(retry.ClientHello1Hash);
                    Session.Transcript.AddPlaintextRecord(hrr.ToBytes());
                }
                Session.Transcript.AddPlaintextRecord(record);

                // Message sequence numbers continue after the stateless HelloRetryRequest (RFC 9147 §5.2).
                NextReceiveMessageSeq = clientHello.SequenceNumber + 1;
                NextSendMessageSeq = clientHello.SequenceNumber;
                SetPlaintextRecordSequence(clientHello.RecordSequenceNumber);

                SendServerFlight();
            });
        }

        private void SendServerFlight()
        {
            var suite = Session.CipherSuite;

            var (privateKey, publicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey = privateKey.GetEncoded();
            Session.PublicKey = publicKey.GetEncoded();

            BeginFlight();

            var serverHello = new ServerHelloDatagram(Session.PublicKey, suite.Id, Dtls13CryptoUtils.GenerateRandom(32))
            {
                LegacySessionIdEcho = _clientHello.LegacySessionId,
            };
            Session.Transcript.AddPlaintextRecord(SendPlaintextHandshake(serverHello));

            byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, _clientHello.PublicKey);
            var handshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(_clientHello.ClientRandom, Session.Transcript.Hash(suite), sharedSecret, suite);
            Session.ServerHandshakeKeys = handshakeKeys;
            Session.WriteKeys = handshakeKeys;
            AddReadKeys(handshakeKeys);

            SendHandshake(BuildEncryptedExtensions(), handshakeKeys);

            if (_server.RequireClientCertificate)
            {
                _certificateRequest = new CertificateRequestDatagram();
                SendHandshake(_certificateRequest, handshakeKeys);
                Session.RequiresClientAuth = true;
            }

            SendHandshake(new CertificateDatagram(_server.ServerCertificate.GetEncoded()), handshakeKeys);

            var clientSchemes = _clientHello.Extensions.OfType<ClientSignatureAlgorithms>().FirstOrDefault()?.SignatureAlgorithms;
            ushort scheme = Dtls13Signatures.SelectScheme(_server.ServerKeyPair.Private, clientSchemes)
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "No signature scheme in common with the client.");
            byte[] content = Dtls13Signatures.BuildSignedContent(server: true, Session.Transcript.Hash(suite));
            SendHandshake(new CertificateVerifyDatagram(Dtls13Signatures.Sign(scheme, _server.ServerKeyPair.Private, content), scheme), handshakeKeys);

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
            ushort? profile = DtlsSrtp.Select(_server.SrtpProtectionProfiles, offered?.SrtpProtectionProfiles);
            if (profile.HasValue)
            {
                SelectedSrtpProtectionProfile = profile;
                extensions.Extensions.Add(new UseSrtpExtension(new[] { profile.Value }, offered.MasterKeyIdentifier));
            }

            return extensions;
        }

        protected override void OnPlaintextHandshake(byte[] record)
        {
            if (record[13] != 0x01)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected plaintext handshake message 0x{record[13]:X2}");

            int messageSeq = (record[17] << 8) | record[18];
            if (messageSeq < NextReceiveMessageSeq && !IsHandshakeComplete)
                OnDuplicatePlaintextHandshake(record); // our flight was lost: retransmit it
        }

        protected override void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            var suite = Session.CipherSuite;

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
                    if (!Dtls13Signatures.Verify(scheme, _clientCertificate.GetPublicKey(), content, certificateVerify.Signature))
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

            var applicationKeys = Session.ServerApplicationKeys;
            Session.WriteKeys = applicationKeys;
            AddReadKeys(applicationKeys);

            _state = State.Connected;
            IsHandshakeComplete = true;

            // ACK the client's final flight (RFC 9147 §7.1) in the application epoch.
            SendAck();

            WriteKeyLog(Convert.ToHexString(_clientHello.ClientRandom), handshakeKeys, applicationKeys);
            Debug.WriteLine($"[DTLS13 Server] Handshake complete with {RemoteEndPoint}");
            RaiseEvent(() => _server.OnConnectionEstablished(this));
        }

        /// <summary>Sends a NewSessionTicket. Note: resumption with these tickets is not implemented yet.</summary>
        public void SendNewSessionTicket(byte[] ticket, byte[] nonce = null, uint lifetime = 7200, uint ageAdd = 0)
        {
            Run(() =>
            {
                if (!IsHandshakeComplete)
                    throw new InvalidOperationException("The handshake has not completed.");

                nonce ??= Dtls13CryptoUtils.GenerateRandom(8);
                if (ageAdd == 0)
                    ageAdd = BitConverter.ToUInt32(Dtls13CryptoUtils.GenerateRandom(4), 0);

                BeginFlight();
                SendHandshake(new NewSessionTicketDatagram(ticket, nonce, lifetime, ageAdd), Session.WriteKeys, addToTranscript: false);
                ArmRetransmission();
            });
        }
    }
}
