using SharpDTLS.DTLS13;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS
{
    public class Dtls13Server
    {
        private string _serverCertificatePrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP\r\n6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3\r\nbso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1\r\nypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB\r\nROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL\r\nrWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0\r\nN3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra\r\nZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3\r\nAXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0\r\nxEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD\r\n8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl\r\npYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22\r\nHP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S\r\nZ+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87\r\nmFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin\r\nmBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71\r\nhf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5\r\nlp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH\r\nBMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz\r\nuzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ\r\nsrZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq\r\neIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O\r\nUbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr\r\nnhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L\r\nJPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/\r\n-----END RSA PRIVATE KEY-----";
        private string _serverCertificate = "-----BEGIN CERTIFICATE-----\r\nMIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE\r\nBhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx\r\nMDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo\r\nZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr\r\nCJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK\r\nE+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng\r\nKBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2\r\nRm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP\r\neh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5\r\nBhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\r\nAQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB\r\nRjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+\r\n/zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5\r\njN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m\r\nf85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938\r\njiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4\r\ncSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==\r\n-----END CERTIFICATE-----";
        private string _privateKey = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        private string _publicKey = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        private string _serverRandom = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

        Dictionary<string, Dtls13Session> _sessions = new Dictionary<string, Dtls13Session>();
        public event EventHandler<EventArgs> HandshakeFinished;

        public ServerTransport ServerTransport { get; }
        public bool ShouldSendHelloRetry { get; set; } = true;

        public Dtls13Server(ServerTransport serverTransport)
        {
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
                        if (!CryptoUtils.ValidateCookie(DateTime.UtcNow, ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port, clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault().Cookie))
                        {
                            throw new Exception("Invalid cookie!");
                        }
                    }
                }

                session = new Dtls13Session();
                session.HandshakeMessages.Add(clientHello);

                session.PrivateKey = Convert.FromHexString(_privateKey);
                session.PublicKey = Convert.FromHexString(_publicKey);

                if (_sessions.TryAdd(endpoint.ToString(), session))
                {
                    var serverHello = new ServerHelloDatagram(session.PublicKey, clientHello.CipherSuites.First(), Convert.FromHexString(_serverRandom));
                    var serverHelloBytes = serverHello.ToBytes();

                    session.HandshakeMessages.Add(serverHello);
                    ServerTransport.Send(endpoint, serverHelloBytes);

                    byte[] helloHash = CryptoUtils.CalculateHelloHash(clientHello.Bytes, serverHelloBytes);
                    Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                    byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, clientHello.PublicKey);
                    Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                    session.ServerHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);
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

                    X509Certificate cert = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(_serverCertificate));
                    AsymmetricKeyParameter publicKey = cert.GetPublicKey();
                    var derCertificate = cert.GetEncoded();

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
                    byte[] h = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                    byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();
                    PemObject pemPrivateKey = new PemReader(new StringReader(_serverCertificatePrivateKey)).ReadPemObject();
                    string type = pemPrivateKey.Type.Substring(0, pemPrivateKey.Type.Length - "PRIVATE KEY".Length).Trim();
                    Asn1Sequence seq = Asn1Sequence.GetInstance(pemPrivateKey.Content);
                    AsymmetricKeyParameter privateKey = null;
                    switch (type)
                    {
                        case "RSA":
                            {
                                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(seq);
                                privateKey = new RsaPrivateCrtKeyParameters(
                                    rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent,
                                    rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2,
                                    rsa.Coefficient);
                            }
                            break;

                        default:
                            throw new NotImplementedException();
                    }

                    ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA/PSS");
                    signer.Init(true, privateKey);
                    signer.BlockUpdate(toSign);

                    byte[] signature = signer.GenerateSignature();
                    Debug.WriteLine($"signature: {Convert.ToHexString(signature).ToLowerInvariant()}");

                    ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new CertificateVerifyDatagram(signature))
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++,
                    };

                    // For testing with the sample to avoid getting random data in our SHA256/PSS
                    //ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys);
                    //encryptedCertVerifyDatagram.FromBytes(Convert.FromHexString("2e a4 3e 01 21 83 be df ea 0f 4a a5 78 45 3a f4 f4 a4 be 41 06 9b eb e5 9c e4 93 3b f2 f2 ff 35 36 f0 e6 11 45 9f 7a fc 07 14 1e 4a 80 e4 b1 10 f2 c5 48 24 4e 83 42 cd 13 46 26 f0 d6 bc 12 2c 6e e3 cc 81 64 e3 e1 1f b8 bc 7b 58 ff 8d ef af 99 c9 26 81 f7 42 64 cc 29 5d f2 69 b4 63 af e5 78 53 ba 86 04 bd 8e ef 74 91 a0 fc 5a 5d df c2 2b 87 f7 cc 55 94 fd 2b 13 69 68 ab 07 ce 1d 84 33 07 df 9f 41 37 27 11 0f e0 5a c6 df 33 7c 44 4c 9a 2d 8b 28 30 b3 50 48 13 72 dd a1 4b e3 04 63 cb 94 16 f8 15 b7 29 b8 20 be b9 1e df 34 f8 b2 29 fa 71 4d fa 58 68 61 c5 25 15 aa d2 8e 98 52 90 d2 a7 e1 97 df 5a 4f 73 20 4d 95 2c a3 e2 34 af 34 fa e6 5a 3a 34 c1 33 8b 52 dd b7 8e 87 a9 14 95 21 2c 8e da ed 59 6e 0b 4b ad 18 65 66 8d 5a 33 9f d7 61 31 43 bc b8 5d 96 10 41 22 f6 17 e5 39 3b 4c ba 44 d0 86 e5 32 c7 39 e8 15 ea dc 2a 84 07 c4 72 bd f0 f6 f0 06 0d b4 71 19 71 38 7c 21 89 39 4f".Replace(" ", "")));

                    var encryptedCertVerifyDatagramBytes = encryptedCertVerifyDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedCertVerifyDatagram);
                    ServerTransport.Send(endpoint, encryptedCertVerifyDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    var crypto = new BcTlsCrypto();
                    var hashAlg = CryptoHashAlgorithm.sha256;
                    var finishedServerKey = CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                    byte[] finishedHash = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    Debug.WriteLine("finished handshake hash:" + Convert.ToHexString(finishedHash));                    
                    byte[] verifyServerData = CryptoUtils.CalculateHmac(finishedServerKey, finishedHash);

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
                var finishedClientKey = CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] finishedHash = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                byte[] verifyClientData = CryptoUtils.CalculateHmac(finishedClientKey, finishedHash);

                if (!verifyClientData.SequenceEqual(clientFinishedDatagram.VerifyData))
                {
                    throw new Exception("Client verify failed!");
                }

                Debug.WriteLine($"Client verify successful!");

                session.ServerHandshakeKeys.ClientKeyUseCounter++;

                var clientHello = session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
                session.ServerApplicationKeys = CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, finishedHash, session.ServerHandshakeKeys.Secret);

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
