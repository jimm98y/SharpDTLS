using Dtls13Test.Messages;
using SharpSRTP.UDP;
using System.Diagnostics;
using System.Net;

namespace Dtls13Test
{
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

                    session.HandshakeMessages.Add(clientHello);

                    // now send ServerHello
                    session.PrivateKey = Convert.FromHexString("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
                    session.PublicKey = Convert.FromHexString("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
                    var serverHello = new ServerHelloDatagram(session.PublicKey, clientHello.CipherSuites.First()) { ServerRandom = Convert.FromHexString("70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f".Replace(" ", "")) };
                    var serverHelloBytes = serverHello.ToBytes();

                    session.HandshakeMessages.Add(serverHello);
                    ServerTransport.Send(endpoint, serverHelloBytes);

                    byte[] helloHash = CryptoUtils.CalculateHelloHash(clientHello.OriginalBytes, serverHelloBytes);
                    Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                    byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, clientHello.PublicKey);
                    Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                    var serverHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(helloHash, sharedSecret);
                    Debug.WriteLine($"client_key: {Convert.ToHexString(serverHandshakeKeys.ClientKey).ToLowerInvariant()}");
                    Debug.WriteLine($"client_iv: {Convert.ToHexString(serverHandshakeKeys.ClientIv).ToLowerInvariant()}");
                    Debug.WriteLine($"server_key: {Convert.ToHexString(serverHandshakeKeys.ServerKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_iv: {Convert.ToHexString(serverHandshakeKeys.ServerIv).ToLowerInvariant()}");
                    Debug.WriteLine($"client_sn_key: {Convert.ToHexString(serverHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_sn_key: {Convert.ToHexString(serverHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                    // from now on the conneciton is encrypted

                }
            }

        }

        

      
    }
}
