using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;

namespace SharpDTLS.DTLS10
{
    // DTLS 1.0 server handshake flow — identical to DTLS 1.2 except:
    //   - Version 0xFE 0xFF
    //   - TLS 1.0 PRF (P_MD5 XOR P_SHA1)
    //   - AES-128-CBC + HMAC-SHA1 instead of AES-128-GCM
    //   - SHA1WITHRSA signature on ServerKeyExchange
    public class Dtls10Server
    {
        private const int MaxHandshakeBodyPerRecord = 1167;
        private readonly AsymmetricCipherKeyPair _serverCertificateKeyPair;
        private readonly X509Certificate _serverX509Certificate;

        public bool ShouldSendHelloVerify { get; set; } = true;
        public event EventHandler<EventArgs> HandshakeFinished;
        public ServerTransport ServerTransport { get; }

        private readonly Dictionary<string, Dtls10Session>  _sessions             = new();
        private readonly Dictionary<string, HandshakeState> _states               = new();
        private readonly Dictionary<string, List<byte[]>>   _pendingEpoch1Records = new();

        private enum HandshakeState
        {
            WaitingForClientKeyExchange,
            WaitingForChangeCipherSpec,
            WaitingForFinished,
            Complete
        }

        public Dtls10Server(ServerTransport serverTransport)
        {
            (_serverCertificateKeyPair, _serverX509Certificate) = Dtls10CryptoUtils.GenerateSelfSignedCertificate();

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        public Dtls10Server(ServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            _serverCertificateKeyPair = keyPair;
            _serverX509Certificate = certificate;

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        private void OnDataReceived(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            var key      = endpoint.ToString();

            Console.WriteLine($"[DTLS10 Server] received {data.Length} bytes from {endpoint}");

            try
            {
                byte recordType = data[0];

                if (!_sessions.TryGetValue(key, out var session))
                {
                    HandleInitialClientHello(endpoint, key, data);
                    return;
                }

                var state = _states[key];

                if (state == HandshakeState.WaitingForClientKeyExchange && recordType == 0x16)
                    HandleClientKeyExchange(endpoint, key, session, data);
                else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x14)
                {
                    var ccs = new ChangeCipherSpecDatagram();
                    ccs.FromBytes(data);
                    Debug.WriteLine($"[DTLS10 Server] Received ChangeCipherSpec from {endpoint}");
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
                    Debug.WriteLine($"[DTLS10 Server] Buffered encrypted Finished pending CCS from {endpoint}");
                }
                else if (state == HandshakeState.WaitingForFinished && recordType == 0x16)
                    HandleClientFinished(endpoint, key, session, data);
                else if (state == HandshakeState.Complete && recordType == 0x17)
                    HandleApplicationData(endpoint, key, session, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DTLS10 Server] Error from {endpoint}: {ex.Message}");
            }
        }

        private void HandleInitialClientHello(EndPoint endpoint, string key, byte[] data)
        {
            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(data);

            if (ShouldSendHelloVerify && clientHello.Cookie.Length == 0)
            {
                var cookie = Dtls10CryptoUtils.CreateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
                var hvr = new HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = 0 };
                ServerTransport.Send(endpoint, hvr.ToBytes());
                Debug.WriteLine($"[DTLS10 Server] Sent HelloVerifyRequest to {endpoint}");
                return;
            }

            if (ShouldSendHelloVerify && clientHello.Cookie.Length > 0)
            {
                if (!Dtls10CryptoUtils.ValidateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port,
                    clientHello.Cookie))
                    throw new Exception("Invalid cookie");
            }

            var (privateX25519, publicX25519) = Dtls10CryptoUtils.CreateX25519KeyPair();
            byte[] serverPrivKey = privateX25519.GetEncoded();
            byte[] serverPubKey  = publicX25519.GetEncoded();

            var session = new Dtls10Session
            {
                PrivateKey   = serverPrivKey,
                PublicKey    = serverPubKey,
                ClientRandom = clientHello.ClientRandom,
                ServerRandom = Dtls10CryptoUtils.GenerateRandom(32),
            };

            bool clientWantsSrtp = clientHello.Extensions
                .OfType<DTLS12.Messages.UseSrtpExtension>().Any();
            ushort srtpProfile = clientWantsSrtp
                ? clientHello.Extensions.OfType<DTLS12.Messages.UseSrtpExtension>().First().ProtectionProfiles[0]
                : (ushort)0;

            // Prefer ECDSA suites when using an EC certificate; prefer 128-bit over 256-bit.
            bool isEcKey = _serverCertificateKeyPair.Private is ECPrivateKeyParameters;
            ushort[] preferred = isEcKey
                ? new ushort[] { 0xC009, 0xC00A, 0xC013, 0xC014 }
                : new ushort[] { 0xC013, 0xC014, 0xC009, 0xC00A };
            ushort cipherSuite = preferred.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (cipherSuite == 0) cipherSuite = clientHello.CipherSuites.First();
            session.CipherSuite = cipherSuite;

            var serverHello = new ServerHelloDatagram(cipherSuite, session.ServerRandom,
                clientWantsSrtp, srtpProfile)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(clientHello);
            session.HandshakeMessages.Add(serverHello);
            SendUnencryptedHandshake(endpoint, session, serverHello.ToBytes());

            byte[] derCert = _serverX509Certificate.GetEncoded();

            var certificate = new ServerCertificateDatagram(derCert)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(certificate);
            SendUnencryptedHandshake(endpoint, session, certificate.ToBytes());

            byte[] ecParams = BuildEcParams(serverPubKey);
            byte[] toSign   = session.ClientRandom.Concat(session.ServerRandom).Concat(ecParams).ToArray();

            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA1WITHRSA");
            signer.Init(true, _serverCertificateKeyPair.Private);
            signer.BlockUpdate(toSign, 0, toSign.Length);
            byte[] signature = signer.GenerateSignature();
            byte hashAlg = isEcKey ? (byte)0x04 : (byte)0x02; // 0x04 = SHA256, 0x02 = SHA1
            byte sigAlg  = isEcKey ? (byte)0x03 : (byte)0x01; // 0x03 = ECDSA,  0x01 = RSA

            var serverKeyExchange = new ServerKeyExchangeDatagram(serverPubKey, signature, hashAlg, sigAlg)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverKeyExchange);
            SendUnencryptedHandshake(endpoint, session, serverKeyExchange.ToBytes());

            var serverHelloDone = new ServerHelloDoneDatagram
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverHelloDone);
            SendUnencryptedHandshake(endpoint, session, serverHelloDone.ToBytes());

            _sessions[key] = session;
            _states[key]   = HandshakeState.WaitingForClientKeyExchange;
            Debug.WriteLine($"[DTLS10 Server] ServerHello flight sent to {endpoint}");
        }

        private void HandleClientKeyExchange(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var cke = new ClientKeyExchangeDatagram();
            cke.FromBytes(data);
            session.HandshakeMessages.Add(cke);

            byte[] preMaster = Dtls10CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, cke.PublicKey);
            byte[] master    = Dtls10CryptoUtils.CalculateMasterSecret(preMaster, session.ClientRandom, session.ServerRandom);
            session.CryptoContext = Dtls10CryptoUtils.DeriveKeys(master, session.ClientRandom, session.ServerRandom, session.CipherSuite);

            Debug.WriteLine($"[DTLS10 Server] master_secret: {Convert.ToHexString(master).ToLower()}");
            Debug.WriteLine($"[DTLS10 Server] client_key: {Convert.ToHexString(session.CryptoContext.ClientKey).ToLower()}");
            Debug.WriteLine($"[DTLS10 Server] server_key: {Convert.ToHexString(session.CryptoContext.ServerKey).ToLower()}");

            _states[key] = HandshakeState.WaitingForChangeCipherSpec;
        }

        private void HandleClientFinished(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var encFinished = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            encFinished.FromBytes(data);
            var clientFinished = encFinished.Datagram as FinishedDatagram;

            byte[] transcriptHash = Dtls10CryptoUtils.HashTranscript(session.HandshakeMessages);
            byte[] expectedVerify = Dtls10CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            if (!expectedVerify.SequenceEqual(clientFinished.VerifyData))
                throw new Exception("Client Finished verify_data mismatch!");

            Debug.WriteLine($"[DTLS10 Server] Client Finished verified");
            session.HandshakeMessages.Add(encFinished);

            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch                = 0,
                RecordSequenceNumber = session.RecordSequenceNumber++,
            };
            ServerTransport.Send(endpoint, ccs.ToBytes());

            byte[] serverTranscriptHash = Dtls10CryptoUtils.HashTranscript(session.HandshakeMessages);
            byte[] serverVerify = Dtls10CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "server finished", serverTranscriptHash);

            var finished = new FinishedDatagram(serverVerify, session.MessageSequenceNumber++);
            var encServerFinished = new ServerEncryptedDatagram(session.CryptoContext, finished)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, encServerFinished.ToBytes());

            _states[key] = HandshakeState.Complete;
            session.Epoch = 1;
            session.RecordSequenceNumber = (ushort)session.CryptoContext.ServerSequenceNumber;

            Debug.WriteLine($"[DTLS10 Server] Handshake complete with {endpoint}");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;

            Console.WriteLine($"[DTLS10 Server] AppData from {endpoint}: {Encoding.UTF8.GetString(appData.Data)}");

            var reply = new ServerEncryptedDatagram(session.CryptoContext,
                new ApplicationDataDatagram(Encoding.UTF8.GetBytes("Hello from DTLS 1.0 server!")), 0x17)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, reply.ToBytes());
        }

        private void SendUnencryptedHandshake(EndPoint endpoint, Dtls10Session session, byte[] record)
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
