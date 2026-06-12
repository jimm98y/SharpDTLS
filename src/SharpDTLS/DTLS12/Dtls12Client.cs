using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS12
{
    // DTLS 1.2 client handshake flow:
    //   1. Send ClientHello (no cookie)
    //   2. Receive HelloVerifyRequest → re-send ClientHello with cookie
    //   3. Receive ServerHello, Certificate, ServerKeyExchange, ServerHelloDone (one or more packets)
    //   4. Send ClientKeyExchange + ChangeCipherSpec + Finished (encrypted)
    //   5. Receive ChangeCipherSpec → switch to epoch 1
    //   6. Receive Finished (encrypted) → verify → handshake complete
    //   7. Application data exchange
    public class Dtls12Client
    {
        public event EventHandler<EventArgs> HandshakeFinished;

        public Dtls12Session Session { get; } = new Dtls12Session();
        public ClientTransport ClientTransport { get; }

        private ServerHelloDatagram       _serverHello;
        private ServerCertificateDatagram _serverCert;
        private ServerKeyExchangeDatagram _serverKex;
        private bool                      _changeCipherSpecReceived;
        private bool                      _handshakeComplete;

        private int _expectedServerMsgSeq = 0;
        private readonly SortedDictionary<int, byte[]> _handshakeReorderBuffer = new();

        public Dtls12Client(ClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += OnDataReceived;
        }

        public void BeginHandshake()
        {
            var (priv, pub) = Dtls13CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey   = priv.GetEncoded();
            Session.PublicKey    = pub.GetEncoded();
            Session.ClientRandom = Dtls13CryptoUtils.GenerateRandom(32);

            SendClientHello(cookie: null);
        }

        private void SendClientHello(byte[] cookie)
        {
            _expectedServerMsgSeq = 0;
            _handshakeReorderBuffer.Clear();

            var ch = new ClientHelloDatagram(includeSrtp: true)
            {
                ClientRandom         = Session.ClientRandom,
                Cookie               = cookie ?? Array.Empty<byte>(),
                RecordSequenceNumber = Session.RecordSequenceNumber++,
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };

            // On retry with cookie, clear existing transcript and start fresh
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
            Debug.WriteLine($"[DTLS12 Client] Sent ClientHello (cookie len={ch.Cookie.Length})");
        }

        private void OnDataReceived(object sender, byte[] data)
        {
            Console.WriteLine($"[DTLS12 Client] received {data.Length} bytes");

            try
            {
                byte recordType = data[0];

                if (recordType == 0x16) // Handshake
                    HandleHandshakeRecord(data);
                else if (recordType == 0x14) // ChangeCipherSpec
                    HandleChangeCipherSpec(data);
                else if (recordType == 0x17) // ApplicationData (encrypted)
                    HandleApplicationData(data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DTLS12 Client] Error: {ex.Message}");
            }
        }

        private void HandleHandshakeRecord(byte[] data)
        {
            if (_handshakeComplete) return;

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
                _handshakeReorderBuffer[msgSeq] = data;
                Debug.WriteLine($"[DTLS12 Client] Buffered out-of-order msg_seq={msgSeq}, expected={_expectedServerMsgSeq}");
                return;
            }

            DispatchHandshakeMessage(data);
            _expectedServerMsgSeq++;

            while (_handshakeReorderBuffer.TryGetValue(_expectedServerMsgSeq, out var buffered))
            {
                _handshakeReorderBuffer.Remove(_expectedServerMsgSeq);
                DispatchHandshakeMessage(buffered);
                _expectedServerMsgSeq++;
            }
        }

        private void DispatchHandshakeMessage(byte[] data)
        {
            byte hsType = data[13];
            switch (hsType)
            {
                case 0x03: HandleHelloVerifyRequest(data); break;
                case 0x02: HandleServerHello(data);        break;
                case 0x0B: HandleServerCertificate(data);  break;
                case 0x0C: HandleServerKeyExchange(data);  break;
                case 0x0E: HandleServerHelloDone(data);    break;
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
            Session.ServerRandom = _serverHello.ServerRandom;
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

            // Verify signature over ClientRandom + ServerRandom + ECParams
            byte[] ecParams = BuildEcParams(_serverKex);
            byte[] toVerify = Session.ClientRandom.Concat(Session.ServerRandom).Concat(ecParams).ToArray();

            X509Certificate cert = new X509CertificateParser().ReadCertificate(_serverCert.Certificate);
            AsymmetricKeyParameter pubKey = cert.GetPublicKey();

            ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA");
            signer.Init(false, pubKey);
            signer.BlockUpdate(toVerify, 0, toVerify.Length);

            if (!signer.VerifySignature(_serverKex.Signature))
                throw new Exception("ServerKeyExchange signature invalid!");

            Session.HandshakeMessages.Add(_serverKex);
            Debug.WriteLine($"[DTLS12 Client] Received ServerKeyExchange, signature verified");
        }

        private void HandleServerHelloDone(byte[] data)
        {
            var done = new ServerHelloDoneDatagram();
            done.FromBytes(data);
            Session.HandshakeMessages.Add(done);
            Debug.WriteLine($"[DTLS12 Client] Received ServerHelloDone");

            SendClientKeyExchangeAndFinished();
        }

        private void SendClientKeyExchangeAndFinished()
        {
            // ClientKeyExchange — send our ECDHE public key
            var cke = new ClientKeyExchangeDatagram(Session.PublicKey)
            {
                RecordSequenceNumber = Session.RecordSequenceNumber++,
                MessageSequenceNumber = Session.MessageSequenceNumber++,
            };
            Session.HandshakeMessages.Add(cke);
            ClientTransport.Send(cke.ToBytes());

            // Derive keys
            byte[] preMaster = Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, _serverKex.PublicKey);
            byte[] master    = Dtls12CryptoUtils.CalculateMasterSecret(preMaster, Session.ClientRandom, Session.ServerRandom);
            Session.CryptoContext = Dtls12CryptoUtils.DeriveKeys(master, Session.ClientRandom, Session.ServerRandom);

            Debug.WriteLine($"[DTLS12 Client] master_secret: {Convert.ToHexString(master).ToLower()}");
            Debug.WriteLine($"[DTLS12 Client] client_key: {Convert.ToHexString(Session.CryptoContext.ClientKey).ToLower()}");
            Debug.WriteLine($"[DTLS12 Client] server_key: {Convert.ToHexString(Session.CryptoContext.ServerKey).ToLower()}");

            // ChangeCipherSpec (epoch 0, increments receiver's epoch)
            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch = 0,
                RecordSequenceNumber = Session.RecordSequenceNumber++,
            };
            ClientTransport.Send(ccs.ToBytes());

            // Finished (encrypted, epoch 1)
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(Session.HandshakeMessages);
            byte[] verifyData = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            var finished = new FinishedDatagram(verifyData, Session.MessageSequenceNumber++);
            var encFinished = new ClientEncryptedDatagram(Session.CryptoContext, finished)
            {
                Epoch = 1,
                SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
            };
            ClientTransport.Send(encFinished.ToBytes());

            Debug.WriteLine($"[DTLS12 Client] Sent ClientKeyExchange + CCS + Finished");
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
            var enc = new ServerEncryptedDatagram(Session.CryptoContext)
            {
                Epoch = 1,
                SequenceNumber = Session.CryptoContext.ServerSequenceNumber++,
            };
            enc.FromBytes(data);
            var serverFinished = enc.Datagram as FinishedDatagram;

            // At this point session.HandshakeMessages doesn't include client Finished yet
            // — server Finished is computed over transcript up to and including client Finished
            // We need to reconstruct that transcript.
            // The server computed: Hash(ClientHello ... ClientFinished)
            // We already added client messages; we need to add client Finished too.
            // For simplicity: rebuild transcript hash as the server would have seen it.
            // (We track the encrypted Finished we sent as part of the transcript.)
            // Actually we stored HandshakeMessages without the client Finished above.
            // Let's compute the hash the same way the server did.

            // Build the transcript hash the server used (includes client Finished)
            // We need to add a synthetic finished to the list temporarily.
            byte[] transcriptHash = Dtls12CryptoUtils.HashTranscript(Session.HandshakeMessages);
            // The hash above is without client Finished; we need to add it.
            // The server re-computed after adding client Finished, so we need the same.
            // Recompute by adding client Finished contribution manually.
            byte[] serverExpectedVerify = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "server finished", transcriptHash);

            // Hmm — the above is the hash WITHOUT client Finished. Let me correct this.
            // The server's transcript hash INCLUDES client Finished.
            // We sent clientFinished but didn't store it in HandshakeMessages.
            // Rebuild what the server sees: current session messages + client Finished bytes.

            // Since we don't have client Finished stored, compute the client finished data again:
            byte[] clientVerify = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            // Now build the full transcript hash including the clientFinished contribution:
            var allMessages = new List<IDatagram>(Session.HandshakeMessages);
            var tempFinished = new FinishedDatagram(clientVerify,
                (ushort)(Session.MessageSequenceNumber - 1));
            tempFinished.ToBytes(); // populate Bytes
            // wrap in ClientEncryptedDatagram so HashTranscript knows to skip to inner datagram
            var tempEnc = new ClientEncryptedDatagram(Session.CryptoContext, tempFinished);
            tempEnc.Datagram = tempFinished;
            // We need Bytes set on the outer; simulate by using inner directly:
            allMessages.Add(tempEnc);

            byte[] fullTranscriptHash = Dtls12CryptoUtils.HashTranscript(allMessages);
            byte[] expectedVerify = Dtls12CryptoUtils.CalculateVerifyData(
                Session.CryptoContext.MasterSecret, "server finished", fullTranscriptHash);

            if (!expectedVerify.SequenceEqual(serverFinished.VerifyData))
                throw new Exception("Server Finished verify_data mismatch!");

            _handshakeComplete = true;
            Debug.WriteLine($"[DTLS12 Client] Server Finished verified — handshake complete!");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(byte[] data)
        {
            var enc = new ServerEncryptedDatagram(Session.CryptoContext)
            {
                Epoch = 1,
                SequenceNumber = Session.CryptoContext.ServerSequenceNumber++,
            };
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;
            Console.WriteLine($"[DTLS12 Client] AppData from server: {Encoding.UTF8.GetString(appData.Data)}");
        }

        public void SendApplicationData(byte[] data)
        {
            var appData = new ApplicationDataDatagram(data);
            var enc = new ClientEncryptedDatagram(Session.CryptoContext, appData, 0x17)
            {
                Epoch = 1,
                SequenceNumber = Session.CryptoContext.ClientSequenceNumber++,
            };
            ClientTransport.Send(enc.ToBytes());
        }

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
