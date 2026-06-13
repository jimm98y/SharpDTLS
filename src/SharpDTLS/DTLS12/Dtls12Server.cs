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
using System.Net;
using System.Text;

namespace SharpDTLS.DTLS12
{
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
        private readonly AsymmetricCipherKeyPair _serverCertificateKeyPair;
        private readonly X509Certificate _serverX509Certificate;
        public bool ShouldSendHelloVerify { get; set; } = true;
        public bool RequireClientCertificate { get; set; } = false;
        public event EventHandler<EventArgs>                 HandshakeFinished;
        public event EventHandler<AlertDatagram>             AlertReceived;
        public event EventHandler<NewSessionTicketDatagram>  NewSessionTicketSent;

        public IServerTransport ServerTransport { get; }

        private readonly Dictionary<string, Dtls12Session>  _sessions             = new();
        private readonly Dictionary<string, HandshakeState> _states               = new();
        private readonly Dictionary<string, List<byte[]>>   _pendingEpoch1Records = new();

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

        private void OnDataReceived(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            var key = endpoint.ToString();

            Console.WriteLine($"[DTLS12 Server] received {data.Length} bytes from {endpoint}");

            try
            {
                byte recordType = data[0];

                if (!_sessions.TryGetValue(key, out var session))
                {
                    HandleInitialClientHello(endpoint, key, data);
                    return;
                }

                var state = _states[key];

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

                    if (_pendingEpoch1Records.TryGetValue(key, out var pending))
                    {
                        _pendingEpoch1Records.Remove(key);
                        foreach (var pendingData in pending)
                            HandleClientFinished(endpoint, key, session, pendingData);
                    }
                }
                else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x16)
                {
                    // Encrypted Finished arrived before CCS — buffer it.
                    if (!_pendingEpoch1Records.TryGetValue(key, out var pending))
                        _pendingEpoch1Records[key] = pending = new List<byte[]>();
                    pending.Add(data);
                    Debug.WriteLine($"[DTLS12 Server] Buffered encrypted Finished pending CCS from {endpoint}");
                }
                else if (state == HandshakeState.WaitingForFinished && recordType == 0x16)
                {
                    HandleClientFinished(endpoint, key, session, data);
                }
                else if (state == HandshakeState.Complete && recordType == 0x17)
                {
                    HandleApplicationData(endpoint, key, session, data);
                }
                else if (state == HandshakeState.Complete && recordType == 0x15)
                {
                    HandleClientAlert(endpoint, session, data);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DTLS12 Server] Error from {endpoint}: {ex.Message}");
            }
        }

        private void HandleInitialClientHello(EndPoint endpoint, string key, byte[] data)
        {
            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(data);

            if (ShouldSendHelloVerify && clientHello.Cookie.Length == 0)
            {
                var cookie = Dtls12CryptoUtils.CreateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);

                var hvr = new HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = 0 };
                ServerTransport.Send(endpoint, hvr.ToBytes());
                Debug.WriteLine($"[DTLS12 Server] Sent HelloVerifyRequest to {endpoint}");
                return;
            }

            if (ShouldSendHelloVerify && clientHello.Cookie.Length > 0)
            {
                if (!Dtls12CryptoUtils.ValidateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port,
                    clientHello.Cookie))
                {
                    throw new Exception("Invalid cookie");
                }
            }

            var (privateX25519, publicX25519) = Dtls12CryptoUtils.CreateX25519KeyPair();
            byte[] serverPrivKey = privateX25519.GetEncoded();
            byte[] serverPubKey  = publicX25519.GetEncoded();

            var session = new Dtls12Session
            {
                PrivateKey   = serverPrivKey,
                PublicKey    = serverPubKey,
                ClientRandom = clientHello.ClientRandom,
                ServerRandom = Dtls12CryptoUtils.GenerateRandom(32),
            };

            // Register session BEFORE sending so synchronous mock transport chains route correctly.
            _sessions[key] = session;
            _states[key]   = RequireClientCertificate
                ? HandshakeState.WaitingForClientCertificate
                : HandshakeState.WaitingForClientKeyExchange;

            bool clientWantsSrtp = clientHello.Extensions.OfType<UseSrtpExtension>().Any();
            ushort srtpProfile = clientWantsSrtp
                ? clientHello.Extensions.OfType<UseSrtpExtension>().First().ProtectionProfiles[0]
                : (ushort)0;

            bool isEcKey = _serverCertificateKeyPair.Private is ECPrivateKeyParameters;
            ushort[] preferred = isEcKey
                ? new ushort[] { 0xC02B, 0xC02C, 0xCCA9, 0xC02F, 0xC030, 0xCCA8 }
                : new ushort[] { 0xC02F, 0xC030, 0xCCA8, 0xC02B, 0xC02C, 0xCCA9 };
            ushort cipherSuite = preferred.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (cipherSuite == 0) cipherSuite = clientHello.CipherSuites.First();
            session.CipherSuite = cipherSuite;

            var serverHello = new ServerHelloDatagram(cipherSuite, session.ServerRandom,
                clientWantsSrtp, srtpProfile)
            {
                RecordSequenceNumber = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(clientHello);
            session.HandshakeMessages.Add(serverHello);
            SendUnencryptedHandshake(endpoint, session, serverHello.ToBytes());

            byte[] derCert = _serverX509Certificate.GetEncoded();

            var certificate = new ServerCertificateDatagram(derCert)
            {
                RecordSequenceNumber = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(certificate);
            SendUnencryptedHandshake(endpoint, session, certificate.ToBytes());

            byte[] ecParams = BuildEcParams(serverPubKey);
            byte[] toSign   = session.ClientRandom.Concat(session.ServerRandom).Concat(ecParams).ToArray();

            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA");
            signer.Init(true, _serverCertificateKeyPair.Private);
            signer.BlockUpdate(toSign, 0, toSign.Length);
            byte[] signature = signer.GenerateSignature();
            byte sigAlg = isEcKey ? (byte)0x03 : (byte)0x01;

            var serverKeyExchange = new ServerKeyExchangeDatagram(serverPubKey, signature, 0x04, sigAlg)
            {
                RecordSequenceNumber = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverKeyExchange);
            SendUnencryptedHandshake(endpoint, session, serverKeyExchange.ToBytes());

            if (RequireClientCertificate)
            {
                var certRequest = new CertificateRequestDatagram
                {
                    RecordSequenceNumber  = session.RecordSequenceNumber++,
                    MessageSequenceNumber = session.MessageSequenceNumber++,
                };
                session.HandshakeMessages.Add(certRequest);
                SendUnencryptedHandshake(endpoint, session, certRequest.ToBytes());
                Debug.WriteLine($"[DTLS12 Server] Sent CertificateRequest to {endpoint}");
            }

            var serverHelloDone = new ServerHelloDoneDatagram
            {
                RecordSequenceNumber = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverHelloDone);
            SendUnencryptedHandshake(endpoint, session, serverHelloDone.ToBytes());

            Debug.WriteLine($"[DTLS12 Server] ServerHello flight sent to {endpoint}");
        }

        private void HandleClientCertificate(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var cert = new ServerCertificateDatagram();
            cert.FromBytes(data);
            session.HandshakeMessages.Add(cert);

            if (cert.Certificate == null || cert.Certificate.Length == 0)
                throw new Exception("Client sent empty Certificate; RequireClientCertificate is set.");

            session.ClientCertificateBytes = cert.Certificate;
            _states[key] = HandshakeState.WaitingForClientKeyExchange;
            Debug.WriteLine($"[DTLS12 Server] Received client Certificate ({cert.Certificate.Length} bytes) from {endpoint}");
        }

        private void HandleClientKeyExchange(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var cke = new ClientKeyExchangeDatagram();
            cke.FromBytes(data);
            session.HandshakeMessages.Add(cke);

            byte[] preMaster = Dtls12CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, cke.PublicKey);
            bool   sha384    = session.CipherSuite == 0xC030 || session.CipherSuite == 0xC02C;
            byte[] master    = Dtls12CryptoUtils.CalculateMasterSecret(preMaster, session.ClientRandom, session.ServerRandom, sha384);

            session.CryptoContext = Dtls12CryptoUtils.DeriveKeys(master, session.ClientRandom, session.ServerRandom, session.CipherSuite);

            Debug.WriteLine($"[DTLS12 Server] master_secret: {Convert.ToHexString(master).ToLower()}");
            Debug.WriteLine($"[DTLS12 Server] client_key: {Convert.ToHexString(session.CryptoContext.ClientKey).ToLower()}");
            Debug.WriteLine($"[DTLS12 Server] server_key: {Convert.ToHexString(session.CryptoContext.ServerKey).ToLower()}");

            _states[key] = session.ClientCertificateBytes != null
                ? HandshakeState.WaitingForCertificateVerify
                : HandshakeState.WaitingForChangeCipherSpec;
        }

        private void HandleCertificateVerify(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var certVerify = new CertificateVerifyDatagram();
            certVerify.FromBytes(data);

            byte[] transcriptBytes = Dtls12CryptoUtils.GetTranscriptBytes(session.HandshakeMessages);

            X509Certificate clientCert = new X509CertificateParser().ReadCertificate(session.ClientCertificateBytes);
            AsymmetricKeyParameter pubKey = clientCert.GetPublicKey();
            bool isEcKey = pubKey is ECPublicKeyParameters;

            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA");
            signer.Init(false, pubKey);
            signer.BlockUpdate(transcriptBytes, 0, transcriptBytes.Length);

            if (!signer.VerifySignature(certVerify.Signature))
                throw new Exception("Client CertificateVerify signature invalid!");

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
            var clientFinished = encFinished.Datagram as FinishedDatagram;

            bool   sha384         = session.CryptoContext.UseSha384;
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(session.HandshakeMessages, sha384);
            byte[] expectedVerify = Dtls12CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "client finished", transcriptHash, sha384);

            if (!expectedVerify.SequenceEqual(clientFinished.VerifyData))
                throw new Exception("Client Finished verify_data mismatch!");

            Debug.WriteLine($"[DTLS12 Server] Client Finished verified");

            session.HandshakeMessages.Add(encFinished);

            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch = 0,
                RecordSequenceNumber = session.RecordSequenceNumber++,
            };
            ServerTransport.Send(endpoint, ccs.ToBytes());

            byte[] serverTranscriptHash = Dtls12CryptoUtils.HashTranscript(session.HandshakeMessages, sha384);
            byte[] serverVerify = Dtls12CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "server finished", serverTranscriptHash, sha384);

            var finished = new FinishedDatagram(serverVerify, session.MessageSequenceNumber++);
            var encServerFinished = new ServerEncryptedDatagram(session.CryptoContext, finished)
            {
                Epoch = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, encServerFinished.ToBytes());

            _states[key] = HandshakeState.Complete;
            session.Epoch = 1;
            session.RecordSequenceNumber = (ushort)(session.CryptoContext.ServerSequenceNumber);

            Debug.WriteLine($"[DTLS12 Server] Handshake complete with {endpoint}");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(EndPoint endpoint, string key, Dtls12Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;

            Console.WriteLine($"[DTLS12 Server] AppData from {endpoint}: {Encoding.UTF8.GetString(appData.Data)}");

            var reply = new ServerEncryptedDatagram(session.CryptoContext, new ApplicationDataDatagram(
                Encoding.UTF8.GetBytes("Hello from DTLS 1.2 server!")), 0x17)
            {
                Epoch = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, reply.ToBytes());
        }

        private void HandleClientAlert(EndPoint endpoint, Dtls12Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            enc.FromBytes(data);
            var alert = enc.Datagram as AlertDatagram;
            Debug.WriteLine($"[DTLS12 Server] Received Alert from {endpoint}: level={alert.Level} desc={alert.Description}");
            AlertReceived?.Invoke(this, alert);
        }

        // Sends a NewSessionTicket post-handshake message to the peer (RFC 5077).
        public void SendNewSessionTicket(EndPoint endpoint, string sessionKey, byte[] ticket, uint lifetimeHint = 7200)
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
            ServerTransport.Send(endpoint, enc.ToBytes());
            session.RecordSequenceNumber++;

            Debug.WriteLine($"[DTLS12 Server] Sent NewSessionTicket to {endpoint} (lifetime={lifetimeHint}s)");
            NewSessionTicketSent?.Invoke(this, nst);
        }

        private void SendUnencryptedHandshake(EndPoint endpoint, Dtls12Session session, byte[] record)
        {
            long startSeq = 0;
            for (int i = 5; i <= 10; i++) startSeq = (startSeq << 8) | record[i];

            int seq = (int)startSeq;
            var fragments = HandshakeFragmenter.FragmentUnencryptedRecord(record, MaxHandshakeBodyPerRecord, ref seq);
            if (seq > session.RecordSequenceNumber)
                session.RecordSequenceNumber = (ushort)seq;

            foreach (var fragment in fragments)
                ServerTransport.Send(endpoint, fragment);
        }

        private static byte[] BuildEcParams(byte[] publicKey)
        {
            var result = new byte[1 + 2 + 1 + publicKey.Length];
            result[0] = 0x03;
            result[1] = 0x00; result[2] = 0x1D; // x25519
            result[3] = (byte)publicKey.Length;
            Buffer.BlockCopy(publicKey, 0, result, 4, publicKey.Length);
            return result;
        }

    }
}
