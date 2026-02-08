using Dtls13Test.Messages;
using SharpSRTP.UDP;
using System.Diagnostics;
using System.Net;
using System.Runtime.Intrinsics.Arm;
using System.Text;

namespace Dtls13Test
{
    public class Dtls13Session
    {
        public List<IMessage> HandshakeMessages { get; } = new List<IMessage>();
    }

    public class Dtls13Server
    {
        Dictionary<string, Dtls13Session> _sessions = new Dictionary<string, Dtls13Session>();

        public ServerTransport ServerTransport { get; }

        public Dtls13Server(ServerTransport serverTransport)
        {
            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        private void ServerTransport_OnDataReceived(object? sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            Console.WriteLine($"The server received: {Convert.ToHexString(data)}");

            if (!_sessions.TryGetValue(endpoint.ToString(), out var session))
            {
                session = new Dtls13Session();
                if (_sessions.TryAdd(endpoint.ToString(), session))
                {
                    var clientHello = new ClientHelloMessage();

                    try
                    {
                        clientHello.FromBytes(data);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Failed to parse ClientHello from {endpoint}: {ex.Message}");
                        return;
                    }

                    session.HandshakeMessages.Add(clientHello);

                    // now send ServerHello
                    byte[] privateKey = Convert.FromHexString("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
                    byte[] publicKey = Convert.FromHexString("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
                    var serverHello = new ServerHelloMessage(publicKey, clientHello.CipherSuites.First());
                    var serverHelloBytes = serverHello.ToBytes();

                    ServerTransport.Send(endpoint, serverHelloBytes);

                    byte[] sharedSecret = CalculateHandshakeKeys(clientHello.PublicKey, privateKey, clientHello.OriginalBytes, serverHelloBytes);

                }
            }

        }

        private byte[] CalculateHandshakeKeys(byte[] clientPublicKey, byte[] serverPrivateKey, byte[] clientHelloBytes, byte[] serverHelloBytes)
        {
            byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(serverPrivateKey, clientPublicKey);
            Debug.WriteLine($"Derived shared secret: {Convert.ToHexString(sharedSecret)}");

            byte[] hello_hash;
            

        }
    }
}
