using Org.BouncyCastle.Crypto;
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
        private readonly AsymmetricCipherKeyPair _serverCertificateKeyPair;
        private readonly X509Certificate _serverX509Certificate;
        Dictionary<string, Dtls13Session> _sessions = new Dictionary<string, Dtls13Session>();
        public event EventHandler<EventArgs> HandshakeFinished;

        public ServerTransport ServerTransport { get; }
        public bool ShouldSendHelloRetry { get; set; } = true;

        public Dtls13Server(ServerTransport serverTransport)
        {
            (_serverCertificateKeyPair, _serverX509Certificate) = Dtls13CryptoUtils.GenerateSelfSignedCertificate();

            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += ServerTransport_OnDataReceived;
        }

        private async void ServerTransport_OnDataReceived(object? sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            Console.WriteLine($"The server received: {Convert.ToHexString(data)}");

            if (!_sessions.TryGetValue(endpoint.ToString(), out var session))
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

                // now send ServerHello
                if (ShouldSendHelloRetry)
                {
                    if (clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault() == null)
                    {
                        var serverHelloRetry = new HelloRetryRequest(DateTime.UtcNow, ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);                       
                        var serverHelloRetryBytes = serverHelloRetry.ToBytes();
                        ServerTransport.Send(endpoint, serverHelloRetryBytes);
                        return;
                    }
                    else
                    {
                        // verify cookie
                        if (!Dtls13CryptoUtils.ValidateCookie(DateTime.UtcNow, ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port, clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault().Cookie))
                        {
                            throw new Exception("Invalid cookie!");
                        }
                    }
                }

                session = new Dtls13Session();
                session.HandshakeMessages.Add(clientHello);

                var (ecdhPrivateKey, ecdhPublicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
                session.PrivateKey = ecdhPrivateKey.GetEncoded();
                session.PublicKey = ecdhPublicKey.GetEncoded();

                if (_sessions.TryAdd(endpoint.ToString(), session))
                {
                    var serverHello = new ServerHelloDatagram(session.PublicKey, clientHello.CipherSuites.First(), Dtls13CryptoUtils.GenerateRandom(32));
                    var serverHelloBytes = serverHello.ToBytes();

                    session.HandshakeMessages.Add(serverHello);
                    ServerTransport.Send(endpoint, serverHelloBytes);

                    byte[] helloHash = Dtls13CryptoUtils.CalculateHelloHash(clientHello.Bytes, serverHelloBytes);
                    Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                    byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, clientHello.PublicKey);
                    Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                    session.ServerHandshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);
                    Debug.WriteLine($"handshake_secret: {Convert.ToHexString(session.ServerHandshakeKeys.Secret).ToLowerInvariant()}");
                    Debug.WriteLine($"client_key: {Convert.ToHexString(session.ServerHandshakeKeys.ClientKey).ToLowerInvariant()}");
                    Debug.WriteLine($"client_iv: {Convert.ToHexString(session.ServerHandshakeKeys.ClientIv).ToLowerInvariant()}");
                    Debug.WriteLine($"server_key: {Convert.ToHexString(session.ServerHandshakeKeys.ServerKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_iv: {Convert.ToHexString(session.ServerHandshakeKeys.ServerIv).ToLowerInvariant()}");
                    Debug.WriteLine($"client_sn_key: {Convert.ToHexString(session.ServerHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_sn_key: {Convert.ToHexString(session.ServerHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                    // from now on the connection is encrypted
                    session.Epoch = 2;

                    ServerEncryptedDatagram encryptedExtensionsDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new EncryptedExtensionsDatagram())
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++
                    };
                    var encryptedExtensionsDatagramBytes = encryptedExtensionsDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                    ServerTransport.Send(endpoint, encryptedExtensionsDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    var derCertificate = _serverX509Certificate.GetEncoded();

                    ServerEncryptedDatagram encryptedCertificateDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, 
                        new CertificateDatagram(derCertificate))
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++,
                    };
                    var encryptedCertificateDatagramBytes = encryptedCertificateDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedCertificateDatagram);
                    ServerTransport.Send(endpoint, encryptedCertificateDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    // find hash of all message up to this point
                    byte[] h = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                    byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

                    ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA/PSS");
                    signer.Init(true, _serverCertificateKeyPair.Private);
                    signer.BlockUpdate(toSign);

                    byte[] signature = signer.GenerateSignature();
                    Debug.WriteLine($"signature: {Convert.ToHexString(signature).ToLowerInvariant()}");

                    ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new CertificateVerifyDatagram(signature))
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++,
                    };

                    var encryptedCertVerifyDatagramBytes = encryptedCertVerifyDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedCertVerifyDatagram);
                    ServerTransport.Send(endpoint, encryptedCertVerifyDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    var crypto = new BcTlsCrypto();
                    var hashAlg = CryptoHashAlgorithm.sha256;
                    var finishedServerKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                    byte[] finishedHash = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    Debug.WriteLine("finished handshake hash:" + Convert.ToHexString(finishedHash));                    
                    byte[] verifyServerData = Dtls13CryptoUtils.CalculateHmac(finishedServerKey, finishedHash);

                    ServerEncryptedDatagram encryptedFinishedDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new FinishedDatagram() { VerifyData = verifyServerData })
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++,
                    };
                    var encryptedFinishedDatagramBytes = encryptedFinishedDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedFinishedDatagram);
                    ServerTransport.Send(endpoint, encryptedFinishedDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;
                }
                else
                {
                    throw new Exception("Failed to add new session");
                }
            }
            else if(session.ServerApplicationKeys == null)
            {
                // session was already added, we're waiting for Finished
                ClientEncryptedDatagram encryptedFinishedDatagram = new ClientEncryptedDatagram(session.ServerHandshakeKeys);
                encryptedFinishedDatagram.FromBytes(data);
                var clientFinishedDatagram = encryptedFinishedDatagram.Datagram as FinishedDatagram;

                var crypto = new BcTlsCrypto();
                var hashAlg = CryptoHashAlgorithm.sha256;
                var finishedClientKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] finishedHash = Dtls13CryptoUtils.HashAllMessages(session.HandshakeMessages);
                byte[] verifyClientData = Dtls13CryptoUtils.CalculateHmac(finishedClientKey, finishedHash);

                if (!verifyClientData.SequenceEqual(clientFinishedDatagram.VerifyData))
                {
                    throw new Exception("Client verify failed!");
                }

                Debug.WriteLine($"Client verify successful!");

                session.ServerHandshakeKeys.ClientKeyUseCounter++;

                var clientHello = session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
                session.ServerApplicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, finishedHash, session.ServerHandshakeKeys.Secret);

                Debug.WriteLine("Server Application Keys:");
                Debug.WriteLine($"client_key: {Convert.ToHexString(session.ServerApplicationKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(session.ServerApplicationKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(session.ServerApplicationKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(session.ServerApplicationKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(session.ServerApplicationKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(session.ServerApplicationKeys.ServerSnKey).ToLowerInvariant()}");
                Debug.WriteLine("------------------------");

                // new Epoch, reset
                session.RecordNumber = 0;
                session.Epoch = 3;

                // send ack
                var ack = new AcknowledgementDatagram();
                Debug.WriteLine($"ack: {Convert.ToHexString(ack.ToBytes()).ToLowerInvariant()}");
                var serverAckDatagram = new ServerEncryptedDatagram(session.ServerApplicationKeys, ack) 
                { 
                    Epoch = session.Epoch,
                    RecordNumber = session.RecordNumber++,
                };
                var encryptedAckDatagramBytes = serverAckDatagram.ToBytes();
                session.ServerApplicationKeys.ServerKeyUseCounter++;
                ServerTransport.Send(endpoint, encryptedAckDatagramBytes);
                Debug.WriteLine($"Server sent ACK: {Convert.ToHexString(encryptedAckDatagramBytes).ToLowerInvariant()}");

                HandshakeFinished?.Invoke(this, EventArgs.Empty);
                KeylogUtils.WriteKeys(
                    Convert.ToHexString(session.ServerHandshakeKeys.ClientRandom),
                    Convert.ToHexString(session.ServerHandshakeKeys.ClientSecret),
                    Convert.ToHexString(session.ServerApplicationKeys.ClientSecret),
                    Convert.ToHexString(session.ServerHandshakeKeys.ServerSecret),
                    Convert.ToHexString(session.ServerApplicationKeys.ServerSecret));
            }
            else
            {
                ClientEncryptedDatagram encryptedApplicationDatagram = new ClientEncryptedDatagram(session.ServerApplicationKeys);
                encryptedApplicationDatagram.FromBytes(data);
                var clientApplicationDatagram = encryptedApplicationDatagram.Datagram as ApplicationDataDatagram;
                session.ServerApplicationKeys.ClientKeyUseCounter++;

                Debug.WriteLine($"Received server application data: {Encoding.UTF8.GetString(clientApplicationDatagram.Data)}");

                await Task.Delay(1000);

                ServerEncryptedDatagram encryptedDatagram = new ServerEncryptedDatagram(session.ServerApplicationKeys, new ApplicationDataDatagram(Encoding.UTF8.GetBytes("Hello from server!")))
                {
                    Epoch = session.Epoch,
                    RecordNumber = session.RecordNumber++,
                };
                var bytes = encryptedDatagram.ToBytes();
                session.ServerApplicationKeys.ServerKeyUseCounter++;
                ServerTransport.Send(endpoint, bytes);
            }
        }
    }
}
