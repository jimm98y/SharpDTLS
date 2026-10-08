using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;

namespace SharpDTLS.DTLS12
{
    public class Dtls12DataReceivedEventArgs : EventArgs
    {
        public Dtls12DataReceivedEventArgs(EndPoint remoteEndPoint, byte[] data)
        {
            RemoteEndPoint = remoteEndPoint;
            Data = data;
        }

        public EndPoint RemoteEndPoint { get; }
        public byte[] Data { get; }
    }

    // DTLS 1.2 server handshake flow:
    //   1. Receive ClientHello (no cookie) → send HelloVerifyRequest
    //   2. Receive ClientHello (with cookie) → validate, send ServerHello + Certificate + ServerKeyExchange
    //      + [CertificateRequest] + ServerHelloDone
    //   3. Receive [Certificate] + ClientKeyExchange + [CertificateVerify] → derive keys, verify
    //   4. Receive ChangeCipherSpec → note epoch change
    //   5. Receive Finished (encrypted) → verify, send ChangeCipherSpec + Finished (encrypted)
    //   6. Application data exchange
    public class Dtls12Server
    {
        private const int MaxHandshakeBodyPerRecord = 1167;

        // ECDHE suites by certificate key type, in server preference order.
        public static readonly ushort[] EcdsaCipherSuites = { 0xC02B, 0xC02C, 0xCCA9 };
        public static readonly ushort[] RsaCipherSuites   = { 0xC02F, 0xC030, 0xCCA8 };

        private readonly AsymmetricCipherKeyPair _serverCertificateKeyPair;
        private readonly X509Certificate _serverX509Certificate;
        public bool ShouldSendHelloVerify { get; set; } = true;
        public bool RequireClientCertificate { get; set; } = false;

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } =
            { DtlsSrtp.SRTP_AEAD_AES_128_GCM, DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80, DtlsSrtp.SRTP_AEAD_AES_256_GCM, DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_32 };
        public event EventHandler<EventArgs>                   HandshakeFinished;
        public event EventHandler<AlertDatagram>               AlertReceived;
        public event EventHandler<NewSessionTicketDatagram>    NewSessionTicketSent;
        public event EventHandler<Dtls12DataReceivedEventArgs> ApplicationDataReceived;

        public IServerTransport ServerTransport { get; }

        private readonly ConcurrentDictionary<string, Dtls12Session>  _sessions             = new();
        private readonly ConcurrentDictionary<string, HandshakeState> _states               = new();
        private readonly ConcurrentDictionary<string, List<byte[]>>   _pendingEpoch1Records = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        // Every send goes through the outbox, which is flushed outside the lock so that timer threads
        // and synchronous transports cannot deadlock.
        private readonly object _sync = new object();
        private readonly Queue<(EndPoint Endpoint, byte[] Datagram)> _outbox = new();

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1).</summary>
        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        private enum HandshakeState
        {
            WaitingForClientCertificate,
            WaitingForClientKeyExchange,
            WaitingForCertificateVerify,
            WaitingForChangeCipherSpec,
            WaitingForFinished,
            Complete
        }

        public Dtls12Server(IServerTransport serverTransport)
        {
            (_serverCertificateKeyPair, _serverX509Certificate) = Dtls12CryptoUtils.GenerateSelfSignedCertificate();

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        public Dtls12Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            _serverCertificateKeyPair = keyPair;
            _serverX509Certificate = certificate;

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        private void OnDataReceived(object sender, byte[] data) => Locked(() => OnDataReceivedLocked(sender, data));

        private void OnDataReceivedLocked(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            var key = endpoint.ToString();

            // A datagram may carry several records (RFC 6347 §4.1.1).
            foreach (var record in DtlsRecordSplitter.Split(data))
            {
                _sessions.TryGetValue(key, out var session);
                try
                {
                    ProcessRecord(endpoint, key, record);
                }
                catch (DtlsRecordDiscardedException ex)
                {
                    Debug.WriteLine($"[DTLS12 Server] Discarded record from {endpoint}: {ex.Message}");
                }
                catch (DtlsException ex)
                {
                    Debug.WriteLine($"[DTLS12 Server] Handshake with {endpoint} failed: {ex.Message}");
                    SendFatalAlert(endpoint, key, session, ex.Alert);
                    return;
                }
                catch (Exception ex)
                {
                    // Malformed or unauthenticated records are dropped silently (RFC 6347 §4.1.2.7).
                    Debug.WriteLine($"[DTLS12 Server] Dropped record from {endpoint}: {ex.Message}");
                }
            }
        }

        private void ProcessRecord(EndPoint endpoint, string key, byte[] data)
        {
            byte recordType = data[0];

            if (!_sessions.TryGetValue(key, out var session))
            {
                if (recordType == 0x16)
                    HandleInitialClientHello(endpoint, key, data);
                return;
            }

            var state = _states[key];

            if (recordType == 0x15 && state != HandshakeState.Complete && session.CryptoContext == null)
            {
                var alert = new AlertDatagram();
                alert.FromBytes(data);
                HandlePeerAlert(endpoint, key, alert);
                return;
            }

            if (recordType == 0x16 && data.Length > 13 && data[3] == 0 && data[4] == 0 && data[13] == 0x01)
            {
                // Retransmitted ClientHello: our flight was lost, resend it (RFC 6347 §4.2.4).
                if (state != HandshakeState.Complete)
                    RetransmitFlight(endpoint, session);
                return;
            }

            if (state == HandshakeState.Complete && (recordType == 0x14 || recordType == 0x16))
            {
                // The client retransmitted its final flight, so our CCS + Finished were lost.
                RetransmitFlight(endpoint, session);
                return;
            }

            if (state == HandshakeState.WaitingForClientCertificate && recordType == 0x16)
            {
                HandleClientCertificate(endpoint, key, session, data);
            }
            else if (state == HandshakeState.WaitingForClientKeyExchange && recordType == 0x16)
            {
                HandleClientKeyExchange(endpoint, key, session, data);
            }
            else if (state == HandshakeState.WaitingForCertificateVerify && recordType == 0x16)
            {
                HandleCertificateVerify(endpoint, key, session, data);
            }
            else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x14)
            {
                var ccs = new ChangeCipherSpecDatagram();
                ccs.FromBytes(data);
                Debug.WriteLine($"[DTLS12 Server] Received ChangeCipherSpec from {endpoint}");
                _states[key] = HandshakeState.WaitingForFinished;

                if (_pendingEpoch1Records.TryRemove(key, out var pending))
                {
                    foreach (var pendingData in pending)
                        HandleClientFinished(endpoint, key, session, pendingData);
                }
            }
            else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x16)
            {
                // Encrypted Finished arrived before CCS — buffer it.
                var pending = _pendingEpoch1Records.GetOrAdd(key, _ => new List<byte[]>());
                if (pending.Count < 4)
                    pending.Add(data);
                Debug.WriteLine($"[DTLS12 Server] Buffered encrypted Finished pending CCS from {endpoint}");
            }
            else if (state == HandshakeState.WaitingForFinished && recordType == 0x16)
            {
                HandleClientFinished(endpoint, key, session, data);
            }
            else if (state == HandshakeState.Complete && recordType == 0x17)
            {
                HandleApplicationData(endpoint, session, data);
            }
            else if (recordType == 0x15 && session.CryptoContext != null)
            {
                HandleClientAlert(endpoint, key, session, data);
            }
        }

        private void HandleInitialClientHello(EndPoint endpoint, string key, byte[] data)
        {
            if (data.Length < 25 || data[13] != 0x01)
                return; // only a ClientHello can start an association

            // A ClientHello larger than the path MTU arrives fragmented.
            if (!_clientHelloReassembler.TryAdd(key, data, out data))
                return;

            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(data);

            var ipEndpoint = (IPEndPoint)endpoint;
            if (ShouldSendHelloVerify &&
                (clientHello.Cookie.Length == 0 ||
                 !Dtls12CryptoUtils.ValidateCookie(DateTime.UtcNow, ipEndpoint.Address.ToString(), ipEndpoint.Port, clientHello.Cookie)))
            {
                var cookie = Dtls12CryptoUtils.CreateCookie(DateTime.UtcNow, ipEndpoint.Address.ToString(), ipEndpoint.Port);

                // RFC 6347 §4.2.1: reuse the ClientHello's record sequence number; a stateless server
                // answers with the same message_seq as the ClientHello.
                var hvr = new HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = clientHello.RecordSequenceNumber };
                byte[] hvrBytes = hvr.ToBytes();
                hvrBytes[17] = (byte)(clientHello.MessageSequenceNumber >> 8);
                hvrBytes[18] = (byte)clientHello.MessageSequenceNumber;
                Send(endpoint, hvrBytes);
                Debug.WriteLine($"[DTLS12 Server] Sent HelloVerifyRequest to {endpoint}");
                return;
            }

            if (data[25] != 0xFE || data[26] > 0xFD)
                throw new DtlsException(AlertDescription.ProtocolVersion, "Client does not support DTLS 1.2.");

            // RFC 8422 §5.1.1: without supported_groups the client is assumed to support any curve.
            var groups = clientHello.Extensions.OfType<SupportedGroupsExtension>().FirstOrDefault();
            ushort group = groups == null
                ? EcdheGroups.X25519
                : EcdheGroups.Supported.FirstOrDefault(g => groups.Groups.Contains(g));
            if (group == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No supported key exchange group in common.");

            bool isEcKey = _serverCertificateKeyPair.Private is ECPrivateKeyParameters;
            ushort[] usable = isEcKey ? EcdsaCipherSuites : RsaCipherSuites;
            ushort cipherSuite = usable.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (cipherSuite == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common.");

            // RFC 5746: the client signals secure renegotiation support with the extension or the SCSV.
            var renegotiationInfo = clientHello.Extensions.OfType<RenegotiationInfoExtension>().FirstOrDefault();
            if (renegotiationInfo != null && renegotiationInfo.RenegotiatedConnection.Length != 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Non-empty renegotiation_info in initial handshake.");
            bool secureRenegotiation = renegotiationInfo != null || clientHello.CipherSuites.Contains(0x00FF);
            bool extendedMasterSecret = clientHello.Extensions.OfType<ExtendedMasterSecretExtension>().Any();

            var clientSchemes = clientHello.Extensions.OfType<SignatureAlgorithmsExtension>().FirstOrDefault()?.Algorithms;
            ushort scheme = Dtls12Signatures.SelectScheme(_serverCertificateKeyPair.Private, clientSchemes)
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "No signature algorithm in common.");

            var (serverPrivKey, serverPubKey) = EcdheGroups.GenerateKeyPair(group);

            var session = new Dtls12Session
            {
                PrivateKey   = serverPrivKey,
                PublicKey    = serverPubKey,
                ClientRandom = clientHello.ClientRandom,
                ServerRandom = Dtls12CryptoUtils.GenerateRandom(32),
                CipherSuite  = cipherSuite,
                NamedGroup   = group,
                // Message and record sequence numbers continue after a stateless HelloVerifyRequest.
                MessageSequenceNumber = clientHello.MessageSequenceNumber,
                RecordSequenceNumber  = (ushort)clientHello.RecordSequenceNumber,
                UseExtendedMasterSecret = extendedMasterSecret,
            };

            // Register session BEFORE sending so synchronous mock transport chains route correctly.
            _sessions[key] = session;
            _states[key]   = RequireClientCertificate
                ? HandshakeState.WaitingForClientCertificate
                : HandshakeState.WaitingForClientKeyExchange;

            ushort? srtpProfile = DtlsSrtp.Select(SrtpProtectionProfiles, clientHello.Extensions.OfType<UseSrtpExtension>().FirstOrDefault()?.ProtectionProfiles);
            session.SrtpProtectionProfile = srtpProfile;

            var serverHello = new ServerHelloDatagram(cipherSuite, session.ServerRandom,
                srtpProfile.HasValue, srtpProfile ?? 0)
            {
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            if (secureRenegotiation)
                serverHello.Extensions.Add(new RenegotiationInfoExtension());
            if (extendedMasterSecret)
                serverHello.Extensions.Add(new ExtendedMasterSecretExtension());
            session.RetransmitTimer = new RetransmitTimer(
                () => Locked(() => RetransmitFlight(endpoint, session)),
                () => Locked(() => { Debug.WriteLine($"[DTLS12 Server] Handshake with {endpoint} timed out"); RemoveSession(key); }));
            session.Flight.Clear();
            session.HandshakeMessages.Add(clientHello);
            session.HandshakeMessages.Add(serverHello);
            SendInFlight(endpoint, session, () => { serverHello.RecordSequenceNumber = session.RecordSequenceNumber; return FragmentRecord(session, serverHello.ToBytes()); });

            byte[] derCert = _serverX509Certificate.GetEncoded();

            var certificate = new ServerCertificateDatagram(derCert)
            {
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(certificate);
            SendInFlight(endpoint, session, () => { certificate.RecordSequenceNumber = session.RecordSequenceNumber; return FragmentRecord(session, certificate.ToBytes()); });

            byte[] ecParams = BuildEcParams(group, serverPubKey);
            byte[] toSign   = session.ClientRandom.Concat(session.ServerRandom).Concat(ecParams).ToArray();
            byte[] signature = Dtls12Signatures.Sign(scheme, _serverCertificateKeyPair.Private, toSign);

            var serverKeyExchange = new ServerKeyExchangeDatagram(serverPubKey, signature, (byte)(scheme >> 8), (byte)scheme, group)
            {
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverKeyExchange);
            SendInFlight(endpoint, session, () => { serverKeyExchange.RecordSequenceNumber = session.RecordSequenceNumber; return FragmentRecord(session, serverKeyExchange.ToBytes()); });

            if (RequireClientCertificate)
            {
                var certRequest = new CertificateRequestDatagram
                {
                    MessageSequenceNumber = session.MessageSequenceNumber++,
                };
                session.HandshakeMessages.Add(certRequest);
                SendInFlight(endpoint, session, () => { certRequest.RecordSequenceNumber = session.RecordSequenceNumber; return FragmentRecord(session, certRequest.ToBytes()); });
                Debug.WriteLine($"[DTLS12 Server] Sent CertificateRequest to {endpoint}");
            }

            var serverHelloDone = new ServerHelloDoneDatagram
            {
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverHelloDone);
            SendInFlight(endpoint, session, () => { serverHelloDone.RecordSequenceNumber = session.RecordSequenceNumber; return FragmentRecord(session, serverHelloDone.ToBytes()); });

            session.RetransmitTimer.Start(InitialRetransmitTimeout);
            Debug.WriteLine($"[DTLS12 Server] ServerHello flight sent to {endpoint}");
        }

        private void HandleClientCertificate(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            session.RetransmitTimer?.Stop();
            var cert = new ServerCertificateDatagram();
            cert.FromBytes(data);
            session.HandshakeMessages.Add(cert);

            if (cert.Certificate == null || cert.Certificate.Length == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Client sent an empty Certificate but one is required.");

            session.ClientCertificateBytes = cert.Certificate;
            _states[key] = HandshakeState.WaitingForClientKeyExchange;
            Debug.WriteLine($"[DTLS12 Server] Received client Certificate ({cert.Certificate.Length} bytes) from {endpoint}");
        }

        private void HandleClientKeyExchange(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            session.RetransmitTimer?.Stop();
            var cke = new ClientKeyExchangeDatagram();
            cke.FromBytes(data);
            session.HandshakeMessages.Add(cke);

            byte[] preMaster = EcdheGroups.Agree(session.NamedGroup, session.PrivateKey, cke.PublicKey);
            bool   sha384    = session.CipherSuite == 0xC030 || session.CipherSuite == 0xC02C;
            byte[] master    = session.UseExtendedMasterSecret
                ? Dtls12CryptoUtils.CalculateExtendedMasterSecret(preMaster, Dtls12CryptoUtils.HashTranscript(session.HandshakeMessages, sha384), sha384)
                : Dtls12CryptoUtils.CalculateMasterSecret(preMaster, session.ClientRandom, session.ServerRandom, sha384);

            session.CryptoContext = Dtls12CryptoUtils.DeriveKeys(master, session.ClientRandom, session.ServerRandom, session.CipherSuite);

            _states[key] = session.ClientCertificateBytes != null
                ? HandshakeState.WaitingForCertificateVerify
                : HandshakeState.WaitingForChangeCipherSpec;
        }

        private void HandleCertificateVerify(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var certVerify = new CertificateVerifyDatagram();
            certVerify.FromBytes(data);

            byte[] transcriptBytes = Dtls12CryptoUtils.GetTranscriptBytes(session.HandshakeMessages);

            X509Certificate clientCert = new X509CertificateParser().ReadCertificate(session.ClientCertificateBytes)
                ?? throw new DtlsException(AlertDescription.BadCertificate, "Client certificate could not be parsed.");

            ushort scheme = Dtls12Signatures.Scheme(certVerify.HashAlgorithm, certVerify.SigAlgorithm);
            if (!Dtls12Signatures.Verify(scheme, clientCert.GetPublicKey(), transcriptBytes, certVerify.Signature))
                throw new DtlsException(AlertDescription.DecryptError, "Client CertificateVerify signature is invalid.");

            session.HandshakeMessages.Add(certVerify);
            _states[key] = HandshakeState.WaitingForChangeCipherSpec;
            Debug.WriteLine($"[DTLS12 Server] Client CertificateVerify verified from {endpoint}");
        }

        private void HandleClientFinished(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var encFinished = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            encFinished.FromBytes(data);
            var clientFinished = encFinished.Datagram as FinishedDatagram
                ?? throw new DtlsException(AlertDescription.UnexpectedMessage, "Expected Finished.");

            bool   sha384         = session.CryptoContext.UseSha384;
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(session.HandshakeMessages, sha384);
            byte[] expectedVerify = Dtls12CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "client finished", transcriptHash, sha384);

            if (!CryptographicOperations.FixedTimeEquals(expectedVerify, clientFinished.VerifyData))
                throw new DtlsException(AlertDescription.DecryptError, "Client Finished verification failed.");

            Debug.WriteLine($"[DTLS12 Server] Client Finished verified");

            session.HandshakeMessages.Add(encFinished);

            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch = 0,
            };
            session.Flight.Clear();
            SendInFlight(endpoint, session, () => { ccs.RecordSequenceNumber = session.RecordSequenceNumber++; return new[] { ccs.ToBytes() }; });

            byte[] serverTranscriptHash = Dtls12CryptoUtils.HashTranscript(session.HandshakeMessages, sha384);
            byte[] serverVerify = Dtls12CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "server finished", serverTranscriptHash, sha384);

            var finished = new FinishedDatagram(serverVerify, session.MessageSequenceNumber++);
            var encServerFinished = new ServerEncryptedDatagram(session.CryptoContext, finished)
            {
                Epoch = 1,
            };

            _states[key] = HandshakeState.Complete;
            session.Epoch = 1;

            // The final flight is only retransmitted when the client retransmits its own (RFC 6347 §4.2.4).
            SendInFlight(endpoint, session, () => { encServerFinished.SequenceNumber = session.CryptoContext.ServerSequenceNumber++; return new[] { encServerFinished.ToBytes() }; });

            Debug.WriteLine($"[DTLS12 Server] Handshake complete with {endpoint}");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(EndPoint endpoint, Dtls12Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext);
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;
            ApplicationDataReceived?.Invoke(this, new Dtls12DataReceivedEventArgs(endpoint, appData.Data));
        }

        /// <summary>Sends application data to a peer whose handshake has completed.</summary>
        public void SendApplicationData(EndPoint endpoint, byte[] data) => Locked(() => SendApplicationDataLocked(endpoint, data));

        private void SendApplicationDataLocked(EndPoint endpoint, byte[] data)
        {
            var key = endpoint.ToString();
            if (!_sessions.TryGetValue(key, out var session) || !_states.TryGetValue(key, out var state) || state != HandshakeState.Complete)
                throw new InvalidOperationException($"No established DTLS 1.2 session for {endpoint}.");

            var enc = new ServerEncryptedDatagram(session.CryptoContext, new ApplicationDataDatagram(data), 0x17)
            {
                Epoch = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            Send(endpoint, enc.ToBytes());
        }

        private void HandleClientAlert(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext);
            enc.FromBytes(data);
            HandlePeerAlert(endpoint, key, enc.Datagram as AlertDatagram);
        }

        private void HandlePeerAlert(EndPoint endpoint, string key, AlertDatagram alert)
        {
            Debug.WriteLine($"[DTLS12 Server] Received Alert from {endpoint}: level={alert.Level} desc={alert.Description}");
            AlertReceived?.Invoke(this, alert);

            // close_notify and fatal alerts end the session.
            if (alert.Level == 2 || alert.Description == 0)
                RemoveSession(key);
        }

        private void SendFatalAlert(EndPoint endpoint, string key, Dtls12Session session, AlertDescription description)
        {
            try
            {
                var alert = new AlertDatagram(2, (byte)description);
                if (session?.CryptoContext != null && _states.TryGetValue(key, out var state) && state == HandshakeState.Complete)
                {
                    var enc = new ServerEncryptedDatagram(session.CryptoContext, new RawPlaintextDatagram(new[] { alert.Level, alert.Description }), 0x15)
                    {
                        Epoch = 1,
                        SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
                    };
                    Send(endpoint, enc.ToBytes());
                }
                else
                {
                    alert.RecordSequenceNumber = session != null ? session.RecordSequenceNumber++ : 0;
                    Send(endpoint, alert.ToBytes());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DTLS12 Server] Failed to send alert to {endpoint}: {ex.Message}");
            }
            finally
            {
                RemoveSession(key);
            }
        }

        private void RemoveSession(string key)
        {
            if (_sessions.TryGetValue(key, out var removed))
                removed.RetransmitTimer?.Stop();
            _sessions.TryRemove(key, out _);
            _states.TryRemove(key, out _);
            _pendingEpoch1Records.TryRemove(key, out _);
        }

        /// <summary>RFC 5705 keying material exporter for an established session.</summary>
        public byte[] ExportKeyingMaterial(EndPoint endpoint, string label, byte[] context, int length)
        {
            var key = endpoint.ToString();
            if (!_sessions.TryGetValue(key, out var session) || !_states.TryGetValue(key, out var state) || state != HandshakeState.Complete)
                throw new InvalidOperationException($"No established DTLS session for {endpoint}.");
            return Dtls12CryptoUtils.ExportKeyingMaterial(session.CryptoContext.MasterSecret, session.ClientRandom, session.ServerRandom, label, context, length, session.CryptoContext.UseSha384);
        }

        /// <summary>SRTP master keys and salts (RFC 5764 §4.2), or null when use_srtp was not negotiated.</summary>
        public DtlsSrtpKeys GetSrtpKeys(EndPoint endpoint)
        {
            if (!_sessions.TryGetValue(endpoint.ToString(), out var session) || session.SrtpProtectionProfile == null)
                return null;
            ushort profile = session.SrtpProtectionProfile.Value;
            return DtlsSrtp.Split(profile, ExportKeyingMaterial(endpoint, DtlsSrtp.ExporterLabel, null, DtlsSrtp.KeyingMaterialLength(profile)));
        }

        // Sends a NewSessionTicket post-handshake message to the peer (RFC 5077).
        public void SendNewSessionTicket(EndPoint endpoint, string sessionKey, byte[] ticket, uint lifetimeHint = 7200)
            => Locked(() => SendNewSessionTicketLocked(endpoint, sessionKey, ticket, lifetimeHint));

        private void SendNewSessionTicketLocked(EndPoint endpoint, string sessionKey, byte[] ticket, uint lifetimeHint)
        {
            if (!_sessions.TryGetValue(sessionKey, out var session))
                throw new InvalidOperationException($"No session for {sessionKey}");

            var nst = new NewSessionTicketDatagram(ticket, lifetimeHint)
            {
                MessageSequenceNumber = session.MessageSequenceNumber++,
                RecordSequenceNumber  = session.RecordSequenceNumber,
            };

            var enc = new ServerEncryptedDatagram(session.CryptoContext, nst)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            Send(endpoint, enc.ToBytes());
            session.RecordSequenceNumber++;

            Debug.WriteLine($"[DTLS12 Server] Sent NewSessionTicket to {endpoint} (lifetime={lifetimeHint}s)");
            NewSessionTicketSent?.Invoke(this, nst);
        }

        private static IEnumerable<byte[]> FragmentRecord(Dtls12Session session, byte[] record)
        {
            long startSeq = 0;
            for (int i = 5; i <= 10; i++) startSeq = (startSeq << 8) | record[i];

            int seq = (int)startSeq;
            var fragments = HandshakeFragmenter.FragmentUnencryptedRecord(record, MaxHandshakeBodyPerRecord, ref seq);
            if (seq > session.RecordSequenceNumber)
                session.RecordSequenceNumber = (ushort)seq;
            return fragments;
        }

        // ── Sending and retransmission ──────────────────────────────────────

        private void Send(EndPoint endpoint, byte[] datagram) => _outbox.Enqueue((endpoint, datagram));

        private void SendInFlight(EndPoint endpoint, Dtls12Session session, Func<IEnumerable<byte[]>> build)
        {
            session.Flight.Add(build);
            foreach (var datagram in build())
                Send(endpoint, datagram);
        }

        private void RetransmitFlight(EndPoint endpoint, Dtls12Session session)
        {
            Debug.WriteLine($"[DTLS12 Server] Retransmitting flight to {endpoint} ({session.Flight.Count} messages)");
            foreach (var build in session.Flight)
                foreach (var datagram in build())
                    Send(endpoint, datagram);
        }

        private void Locked(Action action)
        {
            lock (_sync)
                action();

            if (Monitor.IsEntered(_sync))
                return; // the outermost caller flushes once the lock is released

            while (true)
            {
                (EndPoint Endpoint, byte[] Datagram) next;
                lock (_sync)
                {
                    if (_outbox.Count == 0)
                        return;
                    next = _outbox.Dequeue();
                }
                try { ServerTransport.Send(next.Endpoint, next.Datagram); }
                catch (Exception ex) { Debug.WriteLine($"[DTLS12 Server] Send to {next.Endpoint} failed: {ex.Message}"); }
            }
        }

        private static byte[] BuildEcParams(ushort group, byte[] publicKey)
        {
            var result = new byte[1 + 2 + 1 + publicKey.Length];
            result[0] = 0x03; // named_curve
            result[1] = (byte)(group >> 8);
            result[2] = (byte)group;
            result[3] = (byte)publicKey.Length;
            Buffer.BlockCopy(publicKey, 0, result, 4, publicKey.Length);
            return result;
        }
    }
}
