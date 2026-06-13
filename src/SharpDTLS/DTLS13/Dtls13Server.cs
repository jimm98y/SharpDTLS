using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS.DTLS13
{
    public class Dtls13Server
    {
        // Maximum HS body bytes per encrypted fragment. Keeps each datagram under ~1200 bytes
        // (5 B record header + 16 B AEAD tag + 12 B HS header + 1167 B body ≈ 1200 B).
        private const int MaxHandshakeBodyPerRecord = 1167;

        private readonly AsymmetricCipherKeyPair _serverCertificateKeyPair;
        private readonly X509Certificate _serverX509Certificate;
        Dictionary<string, Dtls13Session> _sessions = new Dictionary<string, Dtls13Session>();
        public event EventHandler<EventArgs> HandshakeFinished;

        public IServerTransport ServerTransport { get; }
        public bool ShouldSendHelloRetry { get; set; } = true;
        public bool RequireClientCertificate { get; set; } = false;

        public Dtls13Server(IServerTransport serverTransport)
        {
            (_serverCertificateKeyPair, _serverX509Certificate) = Dtls13CryptoUtils.GenerateSelfSignedCertificate();

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        public Dtls13Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            _serverCertificateKeyPair = keyPair;
            _serverX509Certificate = certificate;

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        private async void ServerTransport_OnDataReceived(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            Console.WriteLine($"The server received: {Convert.ToHexString(data)}");

            if (!_sessions.TryGetValue(endpoint.ToString(), out var session))
            {
                await HandleInitialClientHello(endpoint, data);
            }
            else if (session.RequiresClientAuth && !session.ReceivedClientCertificate)
            {
                HandleClientCertificate(endpoint, session, data);
            }
            else if (session.RequiresClientAuth && !session.ReceivedClientCertificateVerify)
            {
                HandleClientCertificateVerify(endpoint, session, data);
            }
            else if (session.ServerApplicationKeys == null)
            {
                await HandleClientFinished(endpoint, session, data);
            }
            else
            {
                await HandleApplicationData(endpoint, session, data);
            }
        }

        private async Task HandleInitialClientHello(EndPoint endpoint, byte[] data)
        {
            var clientHello = new ClientHelloDatagram();

            try
            {
                clientHello.FromBytes(data);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to parse ClientHello from {endpoint}: {ex.Message}");
                return;
            }

            if (ShouldSendHelloRetry)
            {
                if (clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault() == null)
                {
                    var serverHelloRetry = new HelloRetryRequest(DateTime.UtcNow, ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
                    ServerTransport.Send(endpoint, serverHelloRetry.ToBytes());
                    return;
                }
                else
                {
                    if (!Dtls13CryptoUtils.ValidateCookie(DateTime.UtcNow, ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port, clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault().Cookie))
                        throw new Exception("Invalid cookie!");
                }
            }

            var session = new Dtls13Session();
            session.HandshakeMessages.Add(clientHello);

            var (ecdhPrivateKey, ecdhPublicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
            session.PrivateKey = ecdhPrivateKey.GetEncoded();
            session.PublicKey  = ecdhPublicKey.GetEncoded();

            if (!_sessions.TryAdd(endpoint.ToString(), session))
                throw new Exception("Failed to add new session");

            var serverHello = new ServerHelloDatagram(session.PublicKey, clientHello.CipherSuites.First(), Dtls13CryptoUtils.GenerateRandom(32));
            var serverHelloBytes = serverHello.ToBytes();
            session.HandshakeMessages.Add(serverHello);
            ServerTransport.Send(endpoint, serverHelloBytes);

            byte[] helloHash    = Dtls13CryptoUtils.CalculateHelloHash(clientHello.Bytes, serverHelloBytes);
            byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, clientHello.PublicKey);

            session.ServerHandshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);

            session.Epoch = 2;

            SendEncryptedHandshake(endpoint, session, new EncryptedExtensionsDatagram());

            if (RequireClientCertificate)
            {
                SendEncryptedHandshake(endpoint, session, new CertificateRequestDatagram());
                session.RequiresClientAuth = true;
                Debug.WriteLine($"[DTLS13 Server] Sent CertificateRequest to {endpoint}");
            }

            var derCertificate = _serverX509Certificate.GetEncoded();
            SendEncryptedHandshake(endpoint, session, new CertificateDatagram(derCertificate));

            byte[] h = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
            byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

            bool isEcKey = _serverCertificateKeyPair.Private is ECPrivateKeyParameters;
            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA/PSS");
            signer.Init(true, _serverCertificateKeyPair.Private);
            signer.BlockUpdate(toSign);
            byte[] signature = signer.GenerateSignature();

            uint sigType = isEcKey ? 0x0403u : 0x0804u;
            SendEncryptedHandshake(endpoint, session, new CertificateVerifyDatagram(signature, sigType));

            var crypto          = new BcTlsCrypto();
            var hashAlg         = CryptoHashAlgorithm.sha256;
            var finishedServerKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
            byte[] finishedHash = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
            byte[] verifyServerData = Dtls13CryptoUtils.CalculateHmac(finishedServerKey, finishedHash);

            SendEncryptedHandshake(endpoint, session, new FinishedDatagram() { VerifyData = verifyServerData });

            await Task.CompletedTask;
        }

        private void HandleClientCertificate(EndPoint endpoint, Dtls13Session session, byte[] data)
        {
            var encClientCert = new ClientEncryptedDatagram(session.ServerHandshakeKeys);
            encClientCert.FromBytes(data);
            session.ServerHandshakeKeys.ClientKeyUseCounter++;

            var clientCertDatagram = encClientCert.Datagram as CertificateDatagram;
            if (clientCertDatagram?.Certificate == null || clientCertDatagram.Certificate.Length == 0)
                throw new Exception("Client sent empty Certificate; RequireClientCertificate is set.");

            session.ClientCertificateBytes = clientCertDatagram.Certificate;
            session.HandshakeMessages.Add(encClientCert);
            session.ReceivedClientCertificate = true;
            Debug.WriteLine($"[DTLS13 Server] Received client Certificate ({clientCertDatagram.Certificate.Length} bytes) from {endpoint}");
        }

        private void HandleClientCertificateVerify(EndPoint endpoint, Dtls13Session session, byte[] data)
        {
            var encCertVerify = new ClientEncryptedDatagram(session.ServerHandshakeKeys);
            encCertVerify.FromBytes(data);
            session.ServerHandshakeKeys.ClientKeyUseCounter++;

            var clientCertVerify = encCertVerify.Datagram as CertificateVerifyDatagram;

            byte[] h = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
            byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, client CertificateVerify\0").Concat(h).ToArray();

            X509Certificate clientX509 = new X509CertificateParser().ReadCertificate(session.ClientCertificateBytes);
            AsymmetricKeyParameter pubKey = clientX509.GetPublicKey();
            bool isEcKey = pubKey is ECPublicKeyParameters;

            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA/PSS");
            signer.Init(false, pubKey);
            signer.BlockUpdate(toSign);

            if (!signer.VerifySignature(clientCertVerify.Signature))
                throw new Exception("Client CertificateVerify signature invalid!");

            session.HandshakeMessages.Add(encCertVerify);
            session.ReceivedClientCertificateVerify = true;
            Debug.WriteLine($"[DTLS13 Server] Client CertificateVerify verified from {endpoint}");
        }

        private async Task HandleClientFinished(EndPoint endpoint, Dtls13Session session, byte[] data)
        {
            var encryptedFinishedDatagram = new ClientEncryptedDatagram(session.ServerHandshakeKeys);
            encryptedFinishedDatagram.FromBytes(data);
            var clientFinishedDatagram = encryptedFinishedDatagram.Datagram as FinishedDatagram;

            var crypto          = new BcTlsCrypto();
            var hashAlg         = CryptoHashAlgorithm.sha256;
            var finishedClientKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
            byte[] finishedHash = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
            byte[] verifyClientData = Dtls13CryptoUtils.CalculateHmac(finishedClientKey, finishedHash);

            if (!verifyClientData.SequenceEqual(clientFinishedDatagram.VerifyData))
                throw new Exception("Client verify failed!");

            Debug.WriteLine($"Client verify successful!");

            session.ServerHandshakeKeys.ClientKeyUseCounter++;

            var clientHello = session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
            session.ServerApplicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, finishedHash, session.ServerHandshakeKeys.Secret);

            // reset
            session.RecordNumber = 0;
            session.Epoch = 3;

            var ack = new AcknowledgementDatagram();
            var serverAckDatagram = new ServerEncryptedDatagram(session.ServerApplicationKeys, ack)
            {
                Epoch = session.Epoch,
                RecordNumber = session.RecordNumber++,
            };
            var encryptedAckDatagramBytes = serverAckDatagram.ToBytes();
            session.ServerApplicationKeys.ServerKeyUseCounter++;
            ServerTransport.Send(endpoint, encryptedAckDatagramBytes);

            HandshakeFinished?.Invoke(this, EventArgs.Empty);
            KeylogUtils.WriteKeys(
                Convert.ToHexString(session.ServerHandshakeKeys.ClientRandom),
                Convert.ToHexString(session.ServerHandshakeKeys.ClientSecret),
                Convert.ToHexString(session.ServerApplicationKeys.ClientSecret),
                Convert.ToHexString(session.ServerHandshakeKeys.ServerSecret),
                Convert.ToHexString(session.ServerApplicationKeys.ServerSecret));

            await Task.CompletedTask;
        }

        private async Task HandleApplicationData(EndPoint endpoint, Dtls13Session session, byte[] data)
        {
            var encryptedApplicationDatagram = new ClientEncryptedDatagram(session.ServerApplicationKeys);
            encryptedApplicationDatagram.FromBytes(data);
            var clientApplicationDatagram = encryptedApplicationDatagram.Datagram as ApplicationDataDatagram;
            session.ServerApplicationKeys.ClientKeyUseCounter++;

            Debug.WriteLine($"Received server application data: {Encoding.UTF8.GetString(clientApplicationDatagram.Data)}");

            await Task.Delay(1000);

            var encryptedDatagram = new ServerEncryptedDatagram(session.ServerApplicationKeys, new ApplicationDataDatagram(Encoding.UTF8.GetBytes("Hello from server!")))
            {
                Epoch = session.Epoch,
                RecordNumber = session.RecordNumber++,
            };
            var bytes = encryptedDatagram.ToBytes();
            session.ServerApplicationKeys.ServerKeyUseCounter++;
            ServerTransport.Send(endpoint, bytes);
        }

        private void SendEncryptedHandshake(EndPoint endpoint, Dtls13Session session, IDatagram datagram)
        {
            byte[] fullPlaintext = datagram.ToBytes();

            var sessionEntry = new ServerEncryptedDatagram(session.ServerHandshakeKeys, datagram);
            session.HandshakeMessages.Add(sessionEntry);

            foreach (var fragment in HandshakeFragmenter.FragmentHandshakePlaintext(fullPlaintext, MaxHandshakeBodyPerRecord))
            {
                var fragEnc = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new RawPlaintextDatagram(fragment))
                {
                    Epoch = session.Epoch,
                    RecordNumber = session.RecordNumber++,
                };
                ServerTransport.Send(endpoint, fragEnc.ToBytes());
                session.ServerHandshakeKeys.ServerKeyUseCounter++;
            }
        }
    }
}
