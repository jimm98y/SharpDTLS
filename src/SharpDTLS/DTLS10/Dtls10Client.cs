using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10
{
    // DTLS 1.0 client handshake flow:
    //   1. Send ClientHello (no cookie)
    //   2. Receive HelloVerifyRequest → re-send ClientHello with cookie
    //   3. Receive ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
    //   4. Send ClientKeyExchange + ChangeCipherSpec + Finished (encrypted)
    //   5. Receive ChangeCipherSpec → switch to epoch 1
    //   6. Receive Finished (encrypted) → verify → handshake complete
    //   7. Application data exchange
    public class Dtls10Client
    {
        public event EventHandler<EventArgs> HandshakeFinished;

        public Dtls10Session Session { get; } = new Dtls10Session();
        public ClientTransport ClientTransport { get; }

        private ServerHelloDatagram       _serverHello;
        private ServerCertificateDatagram _serverCert;
        private ServerKeyExchangeDatagram _serverKex;
        private bool                      _changeCipherSpecReceived;
        private bool                      _handshakeComplete;

        public Dtls10Client(ClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += OnDataReceived;
        }

        public void BeginHandshake()
        {
            var (priv, pub) = CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey   = priv.GetEncoded();
            Session.PublicKey    = pub.GetEncoded();
            Session.ClientRandom = CryptoUtils.GenerateRandom(32);

            SendClientHello(cookie: null);
        }

        private void SendClientHello(byte[] cookie)
        {
            var ch = new ClientHelloDatagram(includeSrtp: true)
            {
                ClientRandom          = Session.ClientRandom,
                Cookie                = cookie ?? Array.Empty<byte>(),
                RecordSequenceNumber  = Session.RecordSequenceNumber++,
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };

            if (cookie != null && cookie.Length > 0)
            {
                Session.HandshakeMessages.Clear();
                Session.MessageSequenceNumber = 1;
                ch.MessageSequenceNumber = 0;
                Session.RecordSequenceNumber = 1;
                ch.RecordSequenceNumber = 1;
            }

            Session.HandshakeMessages.Add(ch);
            ClientTransport.Send(ch.ToBytes());
            Debug.WriteLine($"[DTLS10 Client] Sent ClientHello (cookie len={ch.Cookie.Length})");
        }

        private void OnDataReceived(object sender, byte[] data)
        {
            Console.WriteLine($"[DTLS10 Client] received {data.Length} bytes");

            try
            {
                byte recordType = data[0];

                if (recordType == 0x16)
                    HandleHandshakeRecord(data);
                else if (recordType == 0x14)
                    HandleChangeCipherSpec(data);
                else if (recordType == 0x17)
                    HandleApplicationData(data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DTLS10 Client] Error: {ex.Message}");
            }
        }

        private void HandleHandshakeRecord(byte[] data)
        {
            if (_handshakeComplete) return;

            // After CCS, the next 0x16 record is the encrypted Finished — IV is at data[13], not a handshake type byte.
            if (_changeCipherSpecReceived)
            {
                HandleServerFinished(data);
                return;
            }

            byte hsType = data[13];

            switch (hsType)
            {
                case 0x03: HandleHelloVerifyRequest(data); break;
                case 0x02: HandleServerHello(data);        break;
                case 0x0B: HandleServerCertificate(data);  break;
                case 0x0C: HandleServerKeyExchange(data);  break;
                case 0x0E: HandleServerHelloDone(data);    break;
                default:
                    Debug.WriteLine($"[DTLS10 Client] Unknown handshake type 0x{hsType:X2}");
                    break;
            }
        }

        private void HandleHelloVerifyRequest(byte[] data)
        {
            var hvr = new HelloVerifyRequestDatagram();
            hvr.FromBytes(data);
            Debug.WriteLine($"[DTLS10 Client] Received HelloVerifyRequest, cookie len={hvr.Cookie.Length}");
            SendClientHello(hvr.Cookie);
        }

        private void HandleServerHello(byte[] data)
        {
            _serverHello = new ServerHelloDatagram();
            _serverHello.FromBytes(data);
            Session.ServerRandom = _serverHello.ServerRandom;
            Session.HandshakeMessages.Add(_serverHello);
            Debug.WriteLine($"[DTLS10 Client] Received ServerHello, cipher=0x{_serverHello.SelectedCipherSuite:X4}");
        }

        private void HandleServerCertificate(byte[] data)
        {
            _serverCert = new ServerCertificateDatagram();
            _serverCert.FromBytes(data);
            Session.HandshakeMessages.Add(_serverCert);
            Debug.WriteLine($"[DTLS10 Client] Received Certificate, len={_serverCert.Certificate.Length}");
        }

        private void HandleServerKeyExchange(byte[] data)
        {
            _serverKex = new ServerKeyExchangeDatagram();
            _serverKex.FromBytes(data);

            byte[] ecParams = BuildEcParams(_serverKex);
            byte[] toVerify = Session.ClientRandom.Concat(Session.ServerRandom).Concat(ecParams).ToArray();

            X509Certificate cert   = new X509CertificateParser().ReadCertificate(_serverCert.Certificate);
            AsymmetricKeyParameter pubKey = cert.GetPublicKey();

            ISigner signer = SignerUtilities.GetSigner("SHA1WITHRSA");
            signer.Init(false, pubKey);
            signer.BlockUpdate(toVerify, 0, toVerify.Length);

            if (!signer.VerifySignature(_serverKex.Signature))
                throw new Exception("ServerKeyExchange signature invalid!");

            Session.HandshakeMessages.Add(_serverKex);
            Debug.WriteLine($"[DTLS10 Client] Received ServerKeyExchange, signature verified");
        }

        private void HandleServerHelloDone(byte[] data)
        {
            var done = new ServerHelloDoneDatagram();
            done.FromBytes(data);
            Session.HandshakeMessages.Add(done);
            Debug.WriteLine($"[DTLS10 Client] Received ServerHelloDone");

            SendClientKeyExchangeAndFinished();
        }

        private void SendClientKeyExchangeAndFinished()
        {
            var cke = new ClientKeyExchangeDatagram(Session.PublicKey)
            {
                RecordSequenceNumber  = Session.RecordSequenceNumber++,
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };
            Session.HandshakeMessages.Add(cke);
            ClientTransport.Send(cke.ToBytes());

            byte[] preMaster = CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, _serverKex.PublicKey);
            byte[] master    = Dtls10CryptoUtils.CalculateMasterSecret(preMaster, Session.ClientRandom, Session.ServerRandom);
            Session.CryptoContext = Dtls10CryptoUtils.DeriveKeys(master, Session.ClientRandom, Session.ServerRandom);

            Debug.WriteLine($"[DTLS10 Client] master_secret: {Convert.ToHexString(master).ToLower()}");
            Debug.WriteLine($"[DTLS10 Client] client_key: {Convert.ToHexString(Session.CryptoContext.ClientKey).ToLower()}");
            Debug.WriteLine($"[DTLS10 Client] server_key: {Convert.ToHexString(Session.CryptoContext.ServerKey).ToLower()}");

            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch                = 0,
                RecordSequenceNumber = Session.RecordSequenceNumber++,
            };
            ClientTransport.Send(ccs.ToBytes());

            byte[] transcriptHash = Dtls10CryptoUtils.HashTranscript(Session.HandshakeMessages);
            byte[] verifyData = Dtls10CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            var finished = new FinishedDatagram(verifyData, Session.MessageSequenceNumber++);
            var encFinished = new ClientEncryptedDatagram(Session.CryptoContext, finished)
            {
                Epoch          = 1,
                SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
            };
            ClientTransport.Send(encFinished.ToBytes());

            Debug.WriteLine($"[DTLS10 Client] Sent ClientKeyExchange + CCS + Finished");
        }

        private void HandleChangeCipherSpec(byte[] data)
        {
            var ccs = new ChangeCipherSpecDatagram();
            ccs.FromBytes(data);
            _changeCipherSpecReceived = true;
            Debug.WriteLine($"[DTLS10 Client] Received ChangeCipherSpec from server");
        }

        private void HandleServerFinished(byte[] data)
        {
            var enc = new ServerEncryptedDatagram(Session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = Session.CryptoContext.ServerSequenceNumber++,
            };
            enc.FromBytes(data);
            var serverFinished = enc.Datagram as FinishedDatagram;

            // Reconstruct transcript hash as the server computed it (includes client Finished).
            byte[] transcriptHash = Dtls10CryptoUtils.HashTranscript(Session.HandshakeMessages);
            byte[] clientVerify   = Dtls10CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            var allMessages   = new List<IDatagram>(Session.HandshakeMessages);
            var tempFinished  = new FinishedDatagram(clientVerify, (ushort)(Session.MessageSequenceNumber - 1));
            tempFinished.ToBytes();
            var tempEnc = new ClientEncryptedDatagram(Session.CryptoContext, tempFinished);
            tempEnc.Datagram = tempFinished;
            allMessages.Add(tempEnc);

            byte[] fullTranscriptHash = Dtls10CryptoUtils.HashTranscript(allMessages);
            byte[] expectedVerify = Dtls10CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "server finished", fullTranscriptHash);

            if (!expectedVerify.SequenceEqual(serverFinished.VerifyData))
                throw new Exception("Server Finished verify_data mismatch!");

            _handshakeComplete = true;
            Debug.WriteLine($"[DTLS10 Client] Server Finished verified — handshake complete!");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(byte[] data)
        {
            var enc = new ServerEncryptedDatagram(Session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = Session.CryptoContext.ServerSequenceNumber++,
            };
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;
            Console.WriteLine($"[DTLS10 Client] AppData from server: {Encoding.UTF8.GetString(appData.Data)}");
        }

        public void SendApplicationData(byte[] data)
        {
            var appData = new ApplicationDataDatagram(data);
            var enc = new ClientEncryptedDatagram(Session.CryptoContext, appData, 0x17)
            {
                Epoch          = 1,
                SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
            };
            ClientTransport.Send(enc.ToBytes());
        }

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
