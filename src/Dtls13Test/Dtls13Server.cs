using Dtls13Test.Messages;
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
using System.Diagnostics;
using System.Net;
using System.Text;

namespace Dtls13Test
{
    public class Dtls13Server
    {
        private const string _certificate = "30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0";


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
                        const string HelloRetryRequestRandom = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";
                        var serverHelloRetry = new ServerHelloDatagram()
                        {
                            // the HelloRetryRequest message uses the same structure as the ServerHello, but with Random set to the special value
                            ServerRandom = Convert.FromHexString(HelloRetryRequestRandom)
                        };
                        serverHelloRetry.Extensions.Add(new ServerSupportedVersions());
                        serverHelloRetry.Extensions.Add(new CookieExtension(CryptoUtils.CreateCookie(((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port)));
                        var serverHelloRetryBytes = serverHelloRetry.ToBytes();
                        ServerTransport.Send(endpoint, serverHelloRetryBytes);
                        return;
                    }
                    else
                    {
                        // verify cookie
                        if (!CryptoUtils.ValidateCookie(((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port, clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault().Cookie))
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

                    ServerEncryptedDatagram encryptedExtensionsDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new ExtensionsDatagram())
                    {
                        Epoch = session.Epoch,
                        RecordNumber = session.RecordNumber++
                    };
                    var encryptedExtensionsDatagramBytes = encryptedExtensionsDatagram.ToBytes();
                    session.HandshakeMessages.Add(encryptedExtensionsDatagram);
                    ServerTransport.Send(endpoint, encryptedExtensionsDatagramBytes);
                    session.ServerHandshakeKeys.ServerKeyUseCounter++;

                    ServerEncryptedDatagram encryptedCertificateDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, 
                        new CertificateDatagram(Convert.FromHexString(_certificate.Replace(" ", ""))))
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

                    X509Certificate cert = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(_serverCertificate));
                    AsymmetricKeyParameter publicKey = cert.GetPublicKey();

                    ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA/PSS");
                    signer.Init(true, privateKey);
                    signer.BlockUpdate(toSign);

                    byte[] signature = signer.GenerateSignature();
                    Debug.WriteLine($"signature: {Convert.ToHexString(signature).ToLowerInvariant()}");

                    ServerEncryptedDatagram encryptedCertVerifyDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new CertVerifyDatagram(signature))
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

                    ServerEncryptedDatagram encryptedFinishedDatagram = new ServerEncryptedDatagram(session.ServerHandshakeKeys, new HandshakeFinishedDatagram() { VerifyData = verifyServerData })
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

                //session.HandshakeMessages.Add(encryptedFinishedDatagram);
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
                var ack = new AckDatagram();
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
