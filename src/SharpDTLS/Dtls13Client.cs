using SharpDTLS.DTLS13;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS
{
    public class Dtls13Client
    {
        private string _privateKey = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        private string _publicKey = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        private string _clientRandom = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

        private EncryptedExtensionsDatagram _serverExtensionsDatagram = null;
        private CertificateDatagram _serverCertificateDatagram = null;
        private CertificateVerifyDatagram _serverCertVerifyDatagram = null;
        private FinishedDatagram _serverFinishedDatagram = null;
        private AcknowledgementDatagram _serverAckDatagram = null;

        public event EventHandler<EventArgs> HandshakeFinished;

        public Dtls13Session Session { get; } = new Dtls13Session();
        public ClientTransport ClientTransport { get; }

        public Dtls13Client(ClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += ClientTransport_OnDataReceived;
        }

        private async void ClientTransport_OnDataReceived(object? sender, byte[] data)
        {
            Console.WriteLine($"The client received: {Convert.ToHexString(data)}");

            if (Session.ServerHandshakeKeys == null)
            {
                var serverHello = new ServerHelloDatagram();
                try
                {
                    serverHello.FromBytes(data);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to parse ServerHello: {ex.Message}");
                    return;
                }

                Session.HandshakeMessages.Add(serverHello);

                if (serverHello.Extensions.OfType<CookieExtension>().FirstOrDefault() != null)
                {
                    var clientHelloWithCookie = new ClientHelloDatagram(Session.PublicKey)
                    {
                        ClientRandom = Convert.FromHexString(_clientRandom),
                    };
                    clientHelloWithCookie.Extensions.Add(new CookieExtension() { Cookie = serverHello.Extensions.OfType<CookieExtension>().First().Cookie });

                    // in cases where the cookie exchange is used, the initial ClientHello and HelloVerifyRequest MUST NOT be included in the CertificateVerify or Finished MAC computations
                    Session.HandshakeMessages.Clear();

                    Session.HandshakeMessages.Add(clientHelloWithCookie);
                    ClientTransport.Send(clientHelloWithCookie.ToBytes());
                    return;
                }

                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();

                byte[] helloHash = CryptoUtils.CalculateHelloHash(clientHello.ToBytes(), serverHello.Bytes);
                Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, serverHello.PublicKey);
                Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                Session.ServerHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);
                Debug.WriteLine($"handshake_secret: {Convert.ToHexString(Session.ServerHandshakeKeys.Secret).ToLowerInvariant()}");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                // from now on the conneciton is encrypted
                Session.Epoch = 2;
                Session.RecordNumber = 0;
            }
            else if (_serverExtensionsDatagram == null)
            {
                ServerEncryptedDatagram encryptedExtensionsDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedExtensionsDatagram.FromBytes(data);
                var serverExtensionsDatagram = encryptedExtensionsDatagram.Datagram as EncryptedExtensionsDatagram;
                Session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server extensions: {serverExtensionsDatagram.Extensions.Count}");
                _serverExtensionsDatagram = serverExtensionsDatagram;
            }
            else if (_serverCertificateDatagram == null)
            {
                ServerEncryptedDatagram encryptedCertificateDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedCertificateDatagram.FromBytes(data);
                var serverCertificateDatagram = encryptedCertificateDatagram.Datagram as CertificateDatagram;
                Session.HandshakeMessages.Add(encryptedCertificateDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server certificate: {Convert.ToHexString(serverCertificateDatagram.Certificate).ToLowerInvariant()}");
                _serverCertificateDatagram = serverCertificateDatagram;
            }
            else if(_serverCertVerifyDatagram == null)
            {
                ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedCertVerifyDatagram.FromBytes(data);
                var serverCertVerifyDatagram = encryptedCertVerifyDatagram.Datagram as CertificateVerifyDatagram;

                Debug.WriteLine($"Received server cert verify: {Convert.ToHexString(serverCertVerifyDatagram.Signature).ToLowerInvariant()}");

                byte[] h = CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

                X509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(_serverCertificateDatagram.Certificate);
                AsymmetricKeyParameter publicKey = serverCertificate.GetPublicKey();

                ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA/PSS");
                signer.Init(false, publicKey);
                signer.BlockUpdate(toSign);

                if(!signer.VerifySignature(serverCertVerifyDatagram.Signature))
                {
                    throw new Exception("Signature invalid!");
                }

                Session.HandshakeMessages.Add(encryptedCertVerifyDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;
                _serverCertVerifyDatagram = serverCertVerifyDatagram;

                Debug.WriteLine($"Signature verified");
            }
            else if(_serverFinishedDatagram == null)
            {
                ServerEncryptedDatagram encryptedFinishedDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedFinishedDatagram.FromBytes(data);
                var serverFinishedDatagram = encryptedFinishedDatagram.Datagram as FinishedDatagram;

                Debug.WriteLine($"Received server finished: {Convert.ToHexString(serverFinishedDatagram.VerifyData).ToLowerInvariant()}");

                var crypto = new BcTlsCrypto();
                var hashAlg = CryptoHashAlgorithm.sha256;
                var finishedServerKey = CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] finishedServerHash = CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                byte[] verifyServerData = CryptoUtils.CalculateHmac(finishedServerKey, finishedServerHash);

                if (!verifyServerData.SequenceEqual(serverFinishedDatagram.VerifyData))
                {
                    throw new Exception("Server verify failed!");
                }

                Debug.WriteLine($"Server verify successful!");

                Session.HandshakeMessages.Add(encryptedFinishedDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;
                byte[] finishedClientHash = CryptoUtils.HashAllMessages(Session.HandshakeMessages);

                var finishedClientKey = CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] verifyClientData = CryptoUtils.CalculateHmac(finishedClientKey, finishedClientHash);

                ClientEncryptedDatagram encryptedClientFinishedDatagram = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, new FinishedDatagram() { VerifyData = verifyClientData })
                {
                    Epoch = Session.Epoch,
                    RecordNumber = Session.RecordNumber++,
                };
                var encryptedClientFinishedDatagramBytes = encryptedClientFinishedDatagram.ToBytes();
                ClientTransport.Send(encryptedClientFinishedDatagramBytes);
                Session.ServerHandshakeKeys.ClientKeyUseCounter++;

                // calculate application keys
                byte[] allMessagesHash = CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
                Session.ServerApplicationKeys = CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, allMessagesHash, Session.ServerHandshakeKeys.Secret);

                Debug.WriteLine("Client Application Keys:");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerSnKey).ToLowerInvariant()}");
                Debug.WriteLine("------------------------");

                _serverFinishedDatagram = serverFinishedDatagram;
            }
            else if(_serverAckDatagram == null)
            {
                Debug.WriteLine($"Client received ACK: {Convert.ToHexString(data).ToLowerInvariant()}");

                ServerEncryptedDatagram encryptedServerAckDatagram = new ServerEncryptedDatagram(Session.ServerApplicationKeys);
                encryptedServerAckDatagram.FromBytes(data);
                var serverAckDatagram = encryptedServerAckDatagram.Datagram as AcknowledgementDatagram;
                Session.ServerApplicationKeys.ServerKeyUseCounter++;

                _serverAckDatagram = serverAckDatagram;

                Session.Epoch = 3;
                Session.RecordNumber = 0;

                HandshakeFinished?.Invoke(this, EventArgs.Empty);
            }
            else
            {
                ServerEncryptedDatagram encryptedServerApplicationDatagram = new ServerEncryptedDatagram(Session.ServerApplicationKeys);
                encryptedServerApplicationDatagram.FromBytes(data);
                var serverApplicationDatagram = encryptedServerApplicationDatagram.Datagram as ApplicationDataDatagram;
                Session.ServerApplicationKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server application data: {Encoding.UTF8.GetString(serverApplicationDatagram.Data)}");

                await Task.Delay(1000);

                SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
            }
        }

        // DTLS 1.3 impl
        public void BeginHandshake()
        {
            // generate X25519 key pair
            //var (privateX25519, publicX25519) = CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey = Convert.FromHexString(_privateKey);
            Session.PublicKey = Convert.FromHexString(_publicKey);

            var clientHello = new ClientHelloDatagram(Session.PublicKey) 
            { 
                ClientRandom = Convert.FromHexString(_clientRandom) 
            };
            clientHello.Extensions.Add(new UseSrtpExtension());

            Session.HandshakeMessages.Add(clientHello);
            ClientTransport.Send(clientHello.ToBytes());
        }

        public void SendApplicationData(byte[] data)
        {
            ClientEncryptedDatagram encryptedApplicationData = new ClientEncryptedDatagram(Session.ServerApplicationKeys, new ApplicationDataDatagram(data))
            {
                 Epoch = Session.Epoch,
                 RecordNumber = Session.RecordNumber++
            };
            var encryptedApplicationDataBytes = encryptedApplicationData.ToBytes();
            Session.ServerApplicationKeys.ClientKeyUseCounter++;
            ClientTransport.Send(encryptedApplicationDataBytes);
        }
    }   
}
