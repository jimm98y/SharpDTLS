using Dtls13Test.Messages;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System.Diagnostics;
using System.Text;

namespace Dtls13Test
{
    public class Dtls13Client
    {
        private ServerExtensionsDatagram _serverExtensionsDatagram = null;
        private ServerCertificateDatagram _serverCertificateDatagram = null;
        private ServerCertVerifyDatagram _serverCertVerifyDatagram = null;
        private HandshakeFinishedDatagram _serverFinishedDatagram = null;

        public Dtls13Session Session { get; } = new Dtls13Session();
        public ClientTransport ClientTransport { get; }

        public Dtls13Client(ClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += ClientTransport_OnDataReceived;
        }

        private void ClientTransport_OnDataReceived(object? sender, byte[] data)
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

                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();

                byte[] helloHash = CryptoUtils.CalculateHelloHash(clientHello.ToBytes(), serverHello.Bytes);
                Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, serverHello.PublicKey);
                Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                Session.ServerHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(helloHash, sharedSecret);
                Debug.WriteLine($"handshake_secret: {Convert.ToHexString(Session.ServerHandshakeKeys.Secret).ToLowerInvariant()}");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                // from now on the conneciton is encrypted
            }
            else if (_serverExtensionsDatagram == null)
            {
                ServerEncryptedDatagram encryptedExtensionsDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedExtensionsDatagram.FromBytes(data);
                var serverExtensionsDatagram = encryptedExtensionsDatagram.Datagram as ServerExtensionsDatagram;
                Session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server extensions: {serverExtensionsDatagram.Extensions.Count}");
                _serverExtensionsDatagram = serverExtensionsDatagram;
            }
            else if (_serverCertificateDatagram == null)
            {
                ServerEncryptedDatagram encryptedCertificateDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedCertificateDatagram.FromBytes(data);
                var serverCertificateDatagram = encryptedCertificateDatagram.Datagram as ServerCertificateDatagram;
                Session.HandshakeMessages.Add(encryptedCertificateDatagram);
                Session.ServerHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server certificate: {Convert.ToHexString(serverCertificateDatagram.Certificate).ToLowerInvariant()}");
                _serverCertificateDatagram = serverCertificateDatagram;
            }
            else if(_serverCertVerifyDatagram == null)
            {
                ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
                encryptedCertVerifyDatagram.FromBytes(data);
                var serverCertVerifyDatagram = encryptedCertVerifyDatagram.Datagram as ServerCertVerifyDatagram;

                Debug.WriteLine($"Received server cert verify: {Convert.ToHexString(serverCertVerifyDatagram.Signature).ToLowerInvariant()}");

                byte[] h = CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

                // TODO verify the signature
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
                var serverFinishedDatagram = encryptedFinishedDatagram.Datagram as HandshakeFinishedDatagram;

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

                ClientEncryptedDatagram encryptedClientFinishedDatagram = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, new HandshakeFinishedDatagram() { VerifyData = verifyClientData });
                var encryptedClientFinishedDatagramBytes = encryptedClientFinishedDatagram.ToBytes();
                Session.HandshakeMessages.Add(encryptedClientFinishedDatagram);
                ClientTransport.Send(encryptedClientFinishedDatagramBytes);
                Session.ServerHandshakeKeys.ClientKeyUseCounter++;

                // calculate application keys
                byte[] allMessagesHash = CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                Session.ServerApplicationKeys = CryptoUtils.CalculateApplicationKeys(allMessagesHash, Session.ServerHandshakeKeys.Secret);

                Debug.WriteLine("Client Application Keys:");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerSnKey).ToLowerInvariant()}");
                Debug.WriteLine("------------------------");
            }
        }

        // DTLS 1.3 impl
        public void BeginHandshake()
        {
            // generate X25519 key pair
            //var (privateX25519, publicX25519) = CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey = Convert.FromHexString("20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f".Replace(":", ""));
            Session.PublicKey = Convert.FromHexString("35:80:72:d6:36:58:80:d1:ae:ea:32:9a:df:91:21:38:38:51:ed:21:a2:8e:3b:75:e9:65:d0:d2:cd:16:62:54".Replace(":", ""));

            var clientHello = new ClientHelloDatagram(Session.PublicKey) 
            { 
                ClientRandom = Convert.FromHexString("e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff".Replace(" ", "")) 
            };                     

            Session.HandshakeMessages.Add(clientHello);
            ClientTransport.Send(clientHello.ToBytes());
        }                      
    }   
}
