using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace SharpDTLS.DTLS12
{
    // DTLS 1.2 client handshake flow:
    //   1. Send ClientHello (no cookie)
    //   2. Receive HelloVerifyRequest → re-send ClientHello with cookie
    //   3. Receive ServerHello, Certificate, ServerKeyExchange, [CertificateRequest,] ServerHelloDone
    //   4. Send [Certificate,] ClientKeyExchange, [CertificateVerify,] ChangeCipherSpec + Finished (encrypted)
    //   5. Receive ChangeCipherSpec → switch to epoch 1
    //   6. Receive Finished (encrypted) → verify → handshake complete
    //   7. Application data exchange
    public class Dtls12Client
    {
        public event EventHandler<EventArgs>                    HandshakeFinished;
        public event EventHandler<AlertDatagram>                AlertReceived;
        public event EventHandler<NewSessionTicketDatagram>     NewSessionTicketReceived;
        public event EventHandler<byte[]>                       ApplicationDataReceived;
        public event EventHandler<Exception>                    Failed;

        public Dtls12Session Session { get; } = new Dtls12Session();
        public IClientTransport ClientTransport { get; }

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles { get; set; } = { DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80, DtlsSrtp.SRTP_AEAD_AES_128_GCM };

        /// <summary>The SRTP protection profile selected by the server, or null.</summary>
        public ushort? SelectedSrtpProtectionProfile => Session.SrtpProtectionProfile;

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        private ServerHelloDatagram       _serverHello;
        private ServerCertificateDatagram _serverCert;
        private ServerKeyExchangeDatagram _serverKex;
        private CertificateRequestDatagram _certRequest;
        private ClientHelloDatagram       _clientHello;
        private bool                      _certRequested;
        private bool                      _changeCipherSpecReceived;
        private bool                      _handshakeComplete;

        private int _expectedServerMsgSeq = 0;

        // Every send goes through the outbox, which is flushed outside the lock so that timer threads
        // and synchronous transports cannot deadlock.
        private readonly object _sync = new object();
        private readonly Queue<byte[]> _outbox = new Queue<byte[]>();

        // Current flight; each entry re-serializes its message with a fresh record sequence number,
        // as a retransmission must not reuse one (the peer's replay window would drop it).
        private readonly List<Func<byte[]>> _flight = new List<Func<byte[]>>();
        private readonly RetransmitTimer _retransmitTimer;
        private bool _failed;

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1).</summary>
        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);
        private readonly SortedDictionary<int, List<byte[]>> _handshakeReorderBuffer = new();
        private readonly HandshakeReassembler _reassembler = new();

        public Dtls12Client(IClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            _retransmitTimer = new RetransmitTimer(
                () => Locked(RetransmitFlight),
                () => Locked(() => Fail(new DtlsException(AlertDescription.HandshakeFailure, "DTLS handshake timed out."))));
            ClientTransport.OnDataReceived += OnDataReceived;
        }

        public void BeginHandshake() => Locked(() =>
        {
            Session.ClientRandom = Dtls12CryptoUtils.GenerateRandom(32);

            SendClientHello(cookie: null);
        });

        private void SendClientHello(byte[] cookie)
        {
            _handshakeReorderBuffer.Clear();

            // RFC 6347 §4.2.2: the ClientHello answering a HelloVerifyRequest continues the message and
            // record sequence numbers (message_seq 1), and the server's ServerHello follows with message_seq 1.
            var ch = new ClientHelloDatagram(includeSrtp: false)
            {
                ClientRandom         = Session.ClientRandom,
                Cookie               = cookie ?? Array.Empty<byte>(),
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };

            // Offer only the key exchange group that is implemented.
            ch.Extensions.RemoveAll(e => e is SupportedGroupsExtension || e is SignatureAlgorithmsExtension);
            ch.Extensions.Insert(0, new SupportedGroupsExtension(EcdheGroups.Supported));
            ch.Extensions.Insert(1, new SignatureAlgorithmsExtension(Dtls12Signatures.Supported));
            ch.Extensions.Add(new RenegotiationInfoExtension());
            ch.Extensions.Add(new ExtendedMasterSecretExtension());
            if (SrtpProtectionProfiles != null && SrtpProtectionProfiles.Length > 0)
                ch.Extensions.Add(new UseSrtpExtension(SrtpProtectionProfiles));
            _clientHello = ch;

            // The initial ClientHello and HelloVerifyRequest are not part of the transcript.
            Session.HandshakeMessages.Clear();
            Session.HandshakeMessages.Add(ch);
            BeginFlight();
            SendInFlight(() => { ch.RecordSequenceNumber = Session.RecordSequenceNumber++; return ch.ToBytes(); });
            _retransmitTimer.Start(InitialRetransmitTimeout);
            Debug.WriteLine($"[DTLS12 Client] Sent ClientHello (cookie len={ch.Cookie.Length})");
        }

        private void OnDataReceived(object sender, byte[] datagram) => Locked(() =>
        {
            if (_failed)
                return;

            // A datagram may carry several records (RFC 6347 §4.1.1).
            foreach (var data in DtlsRecordSplitter.Split(datagram))
            {
                try
                {
                    byte recordType = data[0];

                    if (recordType == 0x16) // Handshake
                        HandleHandshakeRecord(data);
                    else if (recordType == 0x14) // ChangeCipherSpec
                        HandleChangeCipherSpec(data);
                    else if (recordType == 0x17) // ApplicationData (encrypted)
                        HandleApplicationData(data);
                    else if (recordType == 0x15) // Alert
                        HandleAlert(data);
                }
                catch (DtlsException ex)
                {
                    Fail(ex);
                    return;
                }
                catch (Exception ex)
                {
                    // Malformed or unauthenticated records are dropped silently (RFC 6347 §4.1.2.7).
                    Debug.WriteLine($"[DTLS12 Client] Dropped record: {ex.Message}");
                }
            }
        });

        private void Fail(DtlsException ex)
        {
            if (_failed)
                return;
            _failed = true;
            _retransmitTimer.Stop();
            Debug.WriteLine($"[DTLS12 Client] Handshake failed: {ex.Message}");
            if (ex.Message != "DTLS handshake timed out.")
                SendAlert(ex.Alert);
            Failed?.Invoke(this, ex);
        }

        // ── Sending and retransmission ──────────────────────────────────────

        private void Send(byte[] datagram) => _outbox.Enqueue(datagram);

        private void BeginFlight()
        {
            _retransmitTimer.Stop();
            _flight.Clear();
        }

        private void SendInFlight(Func<byte[]> build)
        {
            _flight.Add(build);
            Send(build());
        }

        private void RetransmitFlight()
        {
            if (_failed || _flight.Count == 0)
                return;
            Debug.WriteLine($"[DTLS12 Client] Retransmitting flight ({_flight.Count} records)");
            foreach (var build in _flight)
                Send(build());
        }

        private void Locked(Action action)
        {
            lock (_sync)
                action();

            if (Monitor.IsEntered(_sync))
                return; // the outermost caller flushes once the lock is released

            while (true)
            {
                byte[] next;
                lock (_sync)
                {
                    if (_outbox.Count == 0)
                        return;
                    next = _outbox.Dequeue();
                }
                try { ClientTransport.Send(next); }
                catch (Exception ex) { Debug.WriteLine($"[DTLS12 Client] Send failed: {ex.Message}"); }
            }
        }

        private void SendAlert(AlertDescription description)
        {
            try
            {
                var alert = new AlertDatagram(2, (byte)description);
                if (_handshakeComplete)
                {
                    var enc = new ClientEncryptedDatagram(Session.CryptoContext, new RawPlaintextDatagram(new[] { alert.Level, alert.Description }), 0x15)
                    {
                        Epoch = 1,
                        SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
                    };
                    Send(enc.ToBytes());
                }
                else
                {
                    alert.RecordSequenceNumber = Session.RecordSequenceNumber++;
                    Send(alert.ToBytes());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DTLS12 Client] Failed to send alert: {ex.Message}");
            }
        }

        private void HandleHandshakeRecord(byte[] data)
        {
            if (_handshakeComplete)
            {
                HandlePostHandshakeRecord(data);
                return;
            }

            bool epochZero = data[3] == 0 && data[4] == 0;
            if (epochZero && (_changeCipherSpecReceived || (data.Length > 18 && ((data[17] << 8) | data[18]) < _expectedServerMsgSeq)))
            {
                // The server retransmitted an earlier flight, so it has not seen ours: resend it.
                if (_retransmitTimer.IsRunning)
                    RetransmitFlight();
                return;
            }

            // After server CCS the next 0x16 is the encrypted Finished — data[13] is the nonce, not a type byte.
            if (_changeCipherSpecReceived)
            {
                HandleServerFinished(data);
                return;
            }

            int msgSeq = (data[17] << 8) | data[18];

            if (msgSeq < _expectedServerMsgSeq)
                return; // duplicate

            if (msgSeq > _expectedServerMsgSeq)
            {
                if (!_handshakeReorderBuffer.TryGetValue(msgSeq, out var list))
                    _handshakeReorderBuffer[msgSeq] = list = new List<byte[]>();
                list.Add(data);
                Debug.WriteLine($"[DTLS12 Client] Buffered out-of-order msg_seq={msgSeq}, expected={_expectedServerMsgSeq}");
                return;
            }

            if (!_reassembler.TryAddUnencryptedFragment(data, out byte[] complete))
                return;

            _expectedServerMsgSeq++;
            DispatchHandshakeMessage(complete);

            while (_handshakeReorderBuffer.TryGetValue(_expectedServerMsgSeq, out var bufferedList))
            {
                byte[] completeMsg = null;
                foreach (var fragment in bufferedList)
                {
                    if (_reassembler.TryAddUnencryptedFragment(fragment, out completeMsg))
                        break;
                }
                if (completeMsg == null) break;

                _handshakeReorderBuffer.Remove(_expectedServerMsgSeq);
                _expectedServerMsgSeq++;
                DispatchHandshakeMessage(completeMsg);
            }
        }

        private void DispatchHandshakeMessage(byte[] data)
        {
            byte hsType = data[13];
            switch (hsType)
            {
                case 0x03: _retransmitTimer.Stop(); HandleHelloVerifyRequest(data);  break;
                case 0x02: _retransmitTimer.Stop(); HandleServerHello(data);         break;
                case 0x0B: HandleServerCertificate(data);   break;
                case 0x0C: HandleServerKeyExchange(data);   break;
                case 0x0D: HandleCertificateRequest(data);  break;
                case 0x0E: HandleServerHelloDone(data);     break;
                default:
                    Debug.WriteLine($"[DTLS12 Client] Unknown handshake type 0x{hsType:X2}");
                    break;
            }
        }

        private void HandleHelloVerifyRequest(byte[] data)
        {
            var hvr = new HelloVerifyRequestDatagram();
            hvr.FromBytes(data);
            Debug.WriteLine($"[DTLS12 Client] Received HelloVerifyRequest, cookie len={hvr.Cookie.Length}");

            // RFC 6347: initial ClientHello and HelloVerifyRequest must NOT be in the MAC
            SendClientHello(hvr.Cookie);
        }

        private void HandleServerHello(byte[] data)
        {
            _serverHello = new ServerHelloDatagram();
            _serverHello.FromBytes(data);

            if (data[25] != 0xFE || data[26] != 0xFD)
                throw new DtlsException(AlertDescription.ProtocolVersion, "Server did not negotiate DTLS 1.2.");
            if (!_clientHello.CipherSuites.Contains(_serverHello.SelectedCipherSuite))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected a cipher suite that was not offered (0x{_serverHello.SelectedCipherSuite:X4}).");

            var renegotiationInfo = _serverHello.Extensions.OfType<RenegotiationInfoExtension>().FirstOrDefault();
            if (renegotiationInfo != null && renegotiationInfo.RenegotiatedConnection.Length != 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "Non-empty renegotiation_info in initial handshake.");
            Session.UseExtendedMasterSecret = _serverHello.Extensions.OfType<ExtendedMasterSecretExtension>().Any();

            var srtp = _serverHello.Extensions.OfType<ServerUseSrtpExtension>().FirstOrDefault();
            if (srtp != null)
            {
                if (SrtpProtectionProfiles == null || !SrtpProtectionProfiles.Contains(srtp.SelectedProfile))
                    throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected SRTP profile 0x{srtp.SelectedProfile:X4}, which was not offered.");
                Session.SrtpProtectionProfile = srtp.SelectedProfile;
            }
            Session.ServerRandom = _serverHello.ServerRandom;
            Session.CipherSuite  = _serverHello.SelectedCipherSuite;
            Session.HandshakeMessages.Add(_serverHello);
            Debug.WriteLine($"[DTLS12 Client] Received ServerHello, cipher=0x{_serverHello.SelectedCipherSuite:X4}");
        }

        private void HandleServerCertificate(byte[] data)
        {
            _serverCert = new ServerCertificateDatagram();
            _serverCert.FromBytes(data);
            Session.HandshakeMessages.Add(_serverCert);
            Debug.WriteLine($"[DTLS12 Client] Received Certificate, len={_serverCert.Certificate.Length}");
        }

        private void HandleServerKeyExchange(byte[] data)
        {
            _serverKex = new ServerKeyExchangeDatagram();
            _serverKex.FromBytes(data);

            if (_serverKex.CurveType != 0x03 || !EcdheGroups.IsSupported(_serverKex.NamedCurve))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected curve 0x{_serverKex.NamedCurve:X4}, which was not offered.");

            // Verify signature over ClientRandom + ServerRandom + ECParams with the scheme the server chose.
            byte[] ecParams = BuildEcParams(_serverKex);
            byte[] toVerify = Session.ClientRandom.Concat(Session.ServerRandom).Concat(ecParams).ToArray();

            X509Certificate cert = new X509CertificateParser().ReadCertificate(_serverCert.Certificate)
                ?? throw new DtlsException(AlertDescription.BadCertificate, "Server certificate could not be parsed.");

            ushort scheme = Dtls12Signatures.Scheme(_serverKex.HashAlgorithm, _serverKex.SigAlgorithm);
            if (!Dtls12Signatures.Verify(scheme, cert.GetPublicKey(), toVerify, _serverKex.Signature))
                throw new DtlsException(AlertDescription.DecryptError, "ServerKeyExchange signature is invalid.");

            Session.NamedGroup = _serverKex.NamedCurve;
            (Session.PrivateKey, Session.PublicKey) = EcdheGroups.GenerateKeyPair(Session.NamedGroup);

            Session.HandshakeMessages.Add(_serverKex);
            Debug.WriteLine($"[DTLS12 Client] Received ServerKeyExchange, signature verified");
        }

        private void HandleCertificateRequest(byte[] data)
        {
            var certReq = new CertificateRequestDatagram();
            certReq.FromBytes(data);
            Session.HandshakeMessages.Add(certReq);
            _certRequest = certReq;
            _certRequested = true;
            Debug.WriteLine($"[DTLS12 Client] Received CertificateRequest");
        }

        private void HandleServerHelloDone(byte[] data)
        {
            var done = new ServerHelloDoneDatagram();
            done.FromBytes(data);
            Session.HandshakeMessages.Add(done);
            Debug.WriteLine($"[DTLS12 Client] Received ServerHelloDone");

            SendClientFlightAndFinished();
        }

        private void SendClientFlightAndFinished()
        {
            BeginFlight();

            // ── Client Certificate (if requested and we can sign with an accepted scheme) ──
            ushort? certVerifyScheme = _certRequested && ClientCertificate != null && ClientCertificateKeyPair != null
                ? Dtls12Signatures.SelectScheme(ClientCertificateKeyPair.Private, _certRequest.SupportedSignatureAlgorithms)
                : null;
            bool sendingCert = certVerifyScheme.HasValue;

            if (_certRequested)
            {
                byte[] certDer = sendingCert ? ClientCertificate.GetEncoded() : Array.Empty<byte>();
                var clientCert = new ServerCertificateDatagram(certDer)
                {
                    RecordSequenceNumber  = Session.RecordSequenceNumber++,
                    MessageSequenceNumber = Session.MessageSequenceNumber++,
                };
                Session.HandshakeMessages.Add(clientCert);
                SendInFlight(() => { clientCert.RecordSequenceNumber = Session.RecordSequenceNumber++; return clientCert.ToBytes(); });
                Debug.WriteLine($"[DTLS12 Client] Sent Certificate (len={certDer.Length})");
            }

            // ── ClientKeyExchange ───────────────────────────────────────────────
            var cke = new ClientKeyExchangeDatagram(Session.PublicKey)
            {
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };
            Session.HandshakeMessages.Add(cke);
            SendInFlight(() => { cke.RecordSequenceNumber = Session.RecordSequenceNumber++; return cke.ToBytes(); });

            // Derive keys
            byte[] preMaster = EcdheGroups.Agree(Session.NamedGroup, Session.PrivateKey, _serverKex.PublicKey);
            bool   sha384    = Session.CipherSuite == 0xC030 || Session.CipherSuite == 0xC02C;
            byte[] master    = Session.UseExtendedMasterSecret
                ? Dtls12CryptoUtils.CalculateExtendedMasterSecret(preMaster, Dtls12CryptoUtils.HashTranscript(Session.HandshakeMessages, sha384), sha384)
                : Dtls12CryptoUtils.CalculateMasterSecret(preMaster, Session.ClientRandom, Session.ServerRandom, sha384);
            Session.CryptoContext = Dtls12CryptoUtils.DeriveKeys(master, Session.ClientRandom, Session.ServerRandom, Session.CipherSuite);


            // ── CertificateVerify (only if we sent a non-empty cert) ────────────
            if (sendingCert)
            {
                byte[] transcriptBytes = Dtls12CryptoUtils.GetTranscriptBytes(Session.HandshakeMessages);

                ushort scheme = certVerifyScheme.Value;
                byte[] signature = Dtls12Signatures.Sign(scheme, ClientCertificateKeyPair.Private, transcriptBytes);

                var certVerify = new CertificateVerifyDatagram(signature, (byte)(scheme >> 8), (byte)scheme)
                {
                    RecordSequenceNumber  = Session.RecordSequenceNumber++,
                    MessageSequenceNumber = Session.MessageSequenceNumber++,
                };
                Session.HandshakeMessages.Add(certVerify);
                SendInFlight(() => { certVerify.RecordSequenceNumber = Session.RecordSequenceNumber++; return certVerify.ToBytes(); });
                Debug.WriteLine($"[DTLS12 Client] Sent CertificateVerify");
            }

            // ── ChangeCipherSpec ────────────────────────────────────────────────
            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch = 0,
            };
            SendInFlight(() => { ccs.RecordSequenceNumber = Session.RecordSequenceNumber++; return ccs.ToBytes(); });

            // ── Finished (encrypted, epoch 1) ───────────────────────────────────
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(Session.HandshakeMessages, sha384);
            byte[] verifyData = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash, sha384);

            var finished = new FinishedDatagram(verifyData, Session.MessageSequenceNumber++);
            var encFinished = new ClientEncryptedDatagram(Session.CryptoContext, finished)
            {
                Epoch          = 1,
            };
            SendInFlight(() => { encFinished.SequenceNumber = Session.CryptoContext.ClientSequenceNumber++; return encFinished.ToBytes(); });
            _retransmitTimer.Start(InitialRetransmitTimeout);

            Debug.WriteLine($"[DTLS12 Client] Sent [Certificate +] ClientKeyExchange + [CertVerify +] CCS + Finished");
        }

        private void HandleChangeCipherSpec(byte[] data)
        {
            var ccs = new ChangeCipherSpecDatagram();
            ccs.FromBytes(data);
            _changeCipherSpecReceived = true;
            Debug.WriteLine($"[DTLS12 Client] Received ChangeCipherSpec from server");
        }

        private void HandleServerFinished(byte[] data)
        {
            var enc = new ServerEncryptedDatagram(Session.CryptoContext);
            enc.FromBytes(data);
            var serverFinished = enc.Datagram as FinishedDatagram
                ?? throw new DtlsException(AlertDescription.UnexpectedMessage, "Expected Finished.");

            bool sha384 = Session.CryptoContext.UseSha384;

            // Reconstruct the transcript hash the server used, which includes the client Finished.
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(Session.HandshakeMessages, sha384);
            byte[] clientVerify   = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash, sha384);

            var allMessages  = new List<IDatagram>(Session.HandshakeMessages);
            var tempFinished = new FinishedDatagram(clientVerify, (ushort)(Session.MessageSequenceNumber - 1));
            tempFinished.ToBytes();
            var tempEnc = new ClientEncryptedDatagram(Session.CryptoContext, tempFinished);
            tempEnc.Datagram = tempFinished;
            allMessages.Add(tempEnc);

            byte[] fullTranscriptHash = Dtls12CryptoUtils.HashTranscript(allMessages, sha384);
            byte[] expectedVerify = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "server finished", fullTranscriptHash, sha384);

            if (!CryptographicOperations.FixedTimeEquals(expectedVerify, serverFinished.VerifyData))
                throw new DtlsException(AlertDescription.DecryptError, "Server Finished verification failed.");

            // Only the verified server Finished ends our final flight (the CCS before it may arrive alone).
            _retransmitTimer.Stop();
            _handshakeComplete = true;
            Debug.WriteLine($"[DTLS12 Client] Server Finished verified — handshake complete!");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(byte[] data)
        {
            if (!_handshakeComplete)
                throw new DtlsRecordDiscardedException("Application data before handshake completion");

            var enc = new ServerEncryptedDatagram(Session.CryptoContext);
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;
            ApplicationDataReceived?.Invoke(this, appData.Data);
        }

        private void HandlePostHandshakeRecord(byte[] data)
        {
            // Post-handshake 0x16 records are encrypted with epoch 1 keys.
            var enc = new ServerEncryptedDatagram(Session.CryptoContext);
            enc.FromBytes(data);

            switch (enc.Datagram)
            {
                case NewSessionTicketDatagram nst:
                    Debug.WriteLine($"[DTLS12 Client] Received NewSessionTicket (lifetime={nst.TicketLifetimeHint}s)");
                    NewSessionTicketReceived?.Invoke(this, nst);
                    break;

                default:
                    Debug.WriteLine($"[DTLS12 Client] Received unknown post-handshake handshake record, ignoring");
                    break;
            }
        }

        private void HandleAlert(byte[] data)
        {
            AlertDatagram alert;

            if (data[3] != 0 || data[4] != 0)
            {
                if (Session.CryptoContext == null)
                    throw new DtlsRecordDiscardedException("Encrypted alert before keys are established");
                var enc = new ServerEncryptedDatagram(Session.CryptoContext);
                enc.FromBytes(data);
                alert = enc.Datagram as AlertDatagram;
            }
            else
            {
                alert = new AlertDatagram();
                alert.FromBytes(data);
            }

            Debug.WriteLine($"[DTLS12 Client] Received Alert level={alert.Level} desc={alert.Description}");
            AlertReceived?.Invoke(this, alert);
        }

        /// <summary>RFC 5705 keying material exporter.</summary>
        public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
        {
            if (!_handshakeComplete)
                throw new InvalidOperationException("The handshake has not completed.");
            return Dtls12CryptoUtils.ExportKeyingMaterial(Session.CryptoContext.MasterSecret, Session.ClientRandom, Session.ServerRandom, label, context, length, Session.CryptoContext.UseSha384);
        }

        /// <summary>SRTP master keys and salts (RFC 5764 §4.2), or null when use_srtp was not negotiated.</summary>
        public DtlsSrtpKeys GetSrtpKeys()
        {
            if (Session.SrtpProtectionProfile == null)
                return null;
            ushort profile = Session.SrtpProtectionProfile.Value;
            return DtlsSrtp.Split(profile, ExportKeyingMaterial(DtlsSrtp.ExporterLabel, null, DtlsSrtp.KeyingMaterialLength(profile)));
        }

        public void SendApplicationData(byte[] data) => Locked(() =>
        {
            if (!_handshakeComplete)
                throw new InvalidOperationException("The handshake has not completed.");

            var appData = new ApplicationDataDatagram(data);
            var enc = new ClientEncryptedDatagram(Session.CryptoContext, appData, 0x17)
            {
                Epoch = 1,
                SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
            };
            Send(enc.ToBytes());
        });

        // ECParams = curve_type(1) + named_curve(2) + point_length(1) + point_data
        private static byte[] BuildEcParams(ServerKeyExchangeDatagram kex)
        {
            var buf = new byte[1 + 2 + 1 + kex.PublicKey.Length];
            buf[0] = kex.CurveType;
            buf[1] = (byte)((kex.NamedCurve >> 8) & 0xFF);
            buf[2] = (byte)(kex.NamedCurve & 0xFF);
            buf[3] = (byte)kex.PublicKey.Length;
            Buffer.BlockCopy(kex.PublicKey, 0, buf, 4, kex.PublicKey.Length);
            return buf;
        }
    }
}
