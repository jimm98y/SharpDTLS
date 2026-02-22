using Dtls13Test.Messages;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System.Diagnostics;
using System.Net;
using System.Text;

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

                    byte[] helloHash = CryptoUtils.CalculateHelloHash(clientHello.Bytes, serverHelloBytes);
                    Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                    byte[] sharedSecret = CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, clientHello.PublicKey);
                    Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                    session.ServerHandshakeKeys = CryptoUtils.CalculateHandshakeKeys(helloHash, sharedSecret);
                    Debug.WriteLine($"handshake_secret: {Convert.ToHexString(session.ServerHandshakeKeys.Secret).ToLowerInvariant()}");
                    Debug.WriteLine($"client_key: {Convert.ToHexString(session.ServerHandshakeKeys.ClientKey).ToLowerInvariant()}");
                    Debug.WriteLine($"client_iv: {Convert.ToHexString(session.ServerHandshakeKeys.ClientIv).ToLowerInvariant()}");
                    Debug.WriteLine($"server_key: {Convert.ToHexString(session.ServerHandshakeKeys.ServerKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_iv: {Convert.ToHexString(session.ServerHandshakeKeys.ServerIv).ToLowerInvariant()}");
                    Debug.WriteLine($"client_sn_key: {Convert.ToHexString(session.ServerHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                    Debug.WriteLine($"server_sn_key: {Convert.ToHexString(session.ServerHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                    // from now on the connection is encrypted
                    ServerEncryptedExtensionsDatagram encryptedExtensionsDatagram = new ServerEncryptedExtensionsDatagram(session.ServerHandshakeKeys, new ServerExtensionsDatagram());
                    var encryptedExtensionsDatagramBytes = encryptedExtensionsDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                    ServerTransport.Send(endpoint, encryptedExtensionsDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    ServerEncryptedExtensionsDatagram encryptedCertificateDatagram = new ServerEncryptedExtensionsDatagram(session.ServerHandshakeKeys, new ServerCertificateDatagram());
                    var encryptedCertificateDatagramBytes = encryptedCertificateDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedCertificateDatagram);
                    ServerTransport.Send(endpoint, encryptedCertificateDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    // find hash of all message up to this point
                    byte[] h = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                    byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();

                    string serverCertificatePrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP\r\n6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3\r\nbso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1\r\nypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB\r\nROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL\r\nrWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0\r\nN3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra\r\nZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3\r\nAXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0\r\nxEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD\r\n8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl\r\npYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22\r\nHP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S\r\nZ+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87\r\nmFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin\r\nmBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71\r\nhf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5\r\nlp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH\r\nBMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz\r\nuzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ\r\nsrZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq\r\neIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O\r\nUbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr\r\nnhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L\r\nJPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/\r\n-----END RSA PRIVATE KEY-----";
                    string serverCertificate = "-----BEGIN CERTIFICATE-----\r\nMIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE\r\nBhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx\r\nMDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo\r\nZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr\r\nCJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK\r\nE+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng\r\nKBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2\r\nRm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP\r\neh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5\r\nBhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\r\nAQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB\r\nRjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+\r\n/zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5\r\njN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m\r\nf85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938\r\njiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4\r\ncSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==\r\n-----END CERTIFICATE-----";

                    PemObject pemPrivateKey = new PemReader(new StringReader(serverCertificatePrivateKey)).ReadPemObject();
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

                    X509Certificate cert = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(serverCertificate));
                    AsymmetricKeyParameter publicKey = cert.GetPublicKey();

                    ISigner signer = SignerUtilities.GetSigner(cert.SigAlgName);
                    signer.Init(true, privateKey);
                    //signer.Init(false, publicKey);
                    signer.BlockUpdate(toSign);

                    byte[] signature = signer.GenerateSignature();
                    Debug.WriteLine($"signature: {Convert.ToHexString(signature).ToLowerInvariant()}");

                    ServerEncryptedExtensionsDatagram encryptedCertVerifyDatagram = new ServerEncryptedExtensionsDatagram(session.ServerHandshakeKeys, new ServerCertVerifyDatagram() { Signature = signature });
                    var encryptedCertVerifyDatagramBytes = encryptedCertVerifyDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedCertVerifyDatagram);
                    ServerTransport.Send(endpoint, encryptedCertVerifyDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    var crypto = new BcTlsCrypto();
                    var hashAlg = CryptoHashAlgorithm.sha256;
                    var finishedServerKey = CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                    byte[] finishedHash = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                    byte[] verifyServerData = CryptoUtils.CalculateHmac(finishedServerKey, finishedHash);

                    ServerEncryptedExtensionsDatagram encryptedFinishedDatagram = new ServerEncryptedExtensionsDatagram(session.ServerHandshakeKeys, new HandshakeFinishedDatagram() { VerifyData = verifyServerData });
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
            else
            {
                // session was already added, we're waiting for Finished
                ClientEncryptedExtensionsDatagram encryptedFinishedDatagram = new ClientEncryptedExtensionsDatagram(session.ServerHandshakeKeys);
                encryptedFinishedDatagram.FromBytes(data);
                var clientFinishedDatagram = encryptedFinishedDatagram.Datagram as HandshakeFinishedDatagram;

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

                session.HandshakeMessages.Add(encryptedFinishedDatagram);
                session.ServerHandshakeKeys.ClientKeyUseCounter++;

                // calculate application keys
                byte[] allMessagesHash = CryptoUtils.HashAllMessages(session.HandshakeMessages);
                session.ServerApplicationKeys = CryptoUtils.CalculateApplicationKeys(allMessagesHash, session.ServerHandshakeKeys.Secret);

                Debug.WriteLine("Server Application Keys:");
                Debug.WriteLine($"client_key: {Convert.ToHexString(session.ServerApplicationKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(session.ServerApplicationKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(session.ServerApplicationKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(session.ServerApplicationKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(session.ServerApplicationKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(session.ServerApplicationKeys.ServerSnKey).ToLowerInvariant()}");
                Debug.WriteLine("------------------------");
            }
        }
    }
}
