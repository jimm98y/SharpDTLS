using Dtls13Test.Messages;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System.Diagnostics;
using System.Text;

namespace Dtls13Test
{
    public class Dtls13Client
    {
        private Dtls13CryptoContext _serverHandshakeKeys;
        private ServerExtensionsDatagram _serverExtensionsDatagram = null;
        private ServerCertificateDatagram _serverCertificateDatagram = null;
        private ServerCertVerifyDatagram _serverCertVerifyDatagram = null;
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

            if (_serverHandshakeKeys == null)
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

                _serverHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(helloHash, sharedSecret);
                Debug.WriteLine($"client_key: {Convert.ToHexString(_serverHandshakeKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(_serverHandshakeKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(_serverHandshakeKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(_serverHandshakeKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(_serverHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(_serverHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                // from now on the conneciton is encrypted
            }
            else if (_serverExtensionsDatagram == null)
            {
                ServerEncryptedExtensionsDatagram encryptedExtensionsDatagram = new ServerEncryptedExtensionsDatagram(_serverHandshakeKeys);
                encryptedExtensionsDatagram.FromBytes(data);
                var serverExtensionsDatagram = encryptedExtensionsDatagram.Datagram as ServerExtensionsDatagram;
                Session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                _serverHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server extensions: {serverExtensionsDatagram.Extensions.Count}");
                _serverExtensionsDatagram = serverExtensionsDatagram;
            }
            else if (_serverCertificateDatagram == null)
            {
                ServerEncryptedExtensionsDatagram encryptedCertificateDatagram = new ServerEncryptedExtensionsDatagram(_serverHandshakeKeys);
                encryptedCertificateDatagram.FromBytes(data);
                var serverCertificateDatagram = encryptedCertificateDatagram.Datagram as ServerCertificateDatagram;
                Session.HandshakeMessages.Add(encryptedCertificateDatagram);
                _serverHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server certificate: {Convert.ToHexString(serverCertificateDatagram.Certificate).ToLowerInvariant()}");
                _serverCertificateDatagram = serverCertificateDatagram;
            }
            else if(_serverCertVerifyDatagram == null)
            {
                ServerEncryptedExtensionsDatagram encryptedCertVerifyDatagram = new ServerEncryptedExtensionsDatagram(_serverHandshakeKeys);
                encryptedCertVerifyDatagram.FromBytes(data);
                var serverCertVerifyDatagram = encryptedCertVerifyDatagram.Datagram as ServerCertVerifyDatagram;
                Session.HandshakeMessages.Add(encryptedCertVerifyDatagram);
                _serverHandshakeKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server cert verify: {Convert.ToHexString(serverCertVerifyDatagram.Signature).ToLowerInvariant()}");

                Sha256Digest hash = new Sha256Digest();
                // find hash of all message up to this point
                foreach (var msg in Session.HandshakeMessages)
                {
                    int skip;
                    if (msg is ClientHelloDatagram || msg is ServerHelloDatagram)
                        skip = 13;
                    else
                        skip = 0;

                    var msgBytes = msg.Bytes.Skip(skip).Take(4).Skip(8).ToArray();
                    hash.BlockUpdate(msgBytes, 0, msgBytes.Length);
                }

                byte[] h = new byte[hash.GetDigestSize()];
                hash.DoFinal(h, 0);
                Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

                // TODO verify the signature
                X509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(_serverCertificateDatagram.Certificate);
                AsymmetricKeyParameter publicKey = serverCertificate.GetPublicKey();

                ISigner signer = SignerUtilities.GetSigner(serverCertificate.SigAlgName);
                signer.Init(false, publicKey);
                signer.BlockUpdate(toSign);

                if(!signer.VerifySignature(serverCertVerifyDatagram.Signature))
                {
                    throw new Exception("Signature invalid!");
                }

                _serverCertVerifyDatagram = serverCertVerifyDatagram;

                Debug.WriteLine($"Signature verified");
            }
            else
            {

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
