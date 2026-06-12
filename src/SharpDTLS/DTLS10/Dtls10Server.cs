using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10.Messages;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace SharpDTLS.DTLS10
{
    // DTLS 1.0 server handshake flow — identical to DTLS 1.2 except:
    //   - Version 0xFE 0xFF
    //   - TLS 1.0 PRF (P_MD5 XOR P_SHA1)
    //   - AES-128-CBC + HMAC-SHA1 instead of AES-128-GCM
    //   - SHA1WITHRSA signature on ServerKeyExchange
    public class Dtls10Server
    {
        private readonly string _serverCertificatePrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP\r\n6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3\r\nbso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1\r\nypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB\r\nROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL\r\nrWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0\r\nN3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra\r\nZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3\r\nAXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0\r\nxEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD\r\n8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl\r\npYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22\r\nHP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S\r\nZ+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87\r\nmFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin\r\nmBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71\r\nhf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5\r\nlp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH\r\nBMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz\r\nuzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ\r\nsrZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq\r\neIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O\r\nUbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr\r\nnhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L\r\nJPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/\r\n-----END RSA PRIVATE KEY-----";
        private readonly string _serverCertificate = "-----BEGIN CERTIFICATE-----\r\nMIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE\r\nBhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx\r\nMDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo\r\nZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr\r\nCJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK\r\nE+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng\r\nKBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2\r\nRm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP\r\neh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5\r\nBhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\r\nAQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB\r\nRjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+\r\n/zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5\r\njN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m\r\nf85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938\r\njiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4\r\ncSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==\r\n-----END CERTIFICATE-----";

        public bool ShouldSendHelloVerify { get; set; } = true;
        public event EventHandler<EventArgs> HandshakeFinished;
        public ServerTransport ServerTransport { get; }

        private readonly Dictionary<string, Dtls10Session>  _sessions             = new();
        private readonly Dictionary<string, HandshakeState> _states               = new();
        private readonly Dictionary<string, List<byte[]>>   _pendingEpoch1Records = new();

        private enum HandshakeState
        {
            WaitingForClientKeyExchange,
            WaitingForChangeCipherSpec,
            WaitingForFinished,
            Complete
        }

        public Dtls10Server(ServerTransport serverTransport)
        {
            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        private void OnDataReceived(object sender, byte[] data)
        {
            var endpoint = (EndPoint)sender;
            var key      = endpoint.ToString();

            Console.WriteLine($"[DTLS10 Server] received {data.Length} bytes from {endpoint}");

            try
            {
                byte recordType = data[0];

                if (!_sessions.TryGetValue(key, out var session))
                {
                    HandleInitialClientHello(endpoint, key, data);
                    return;
                }

                var state = _states[key];

                if (state == HandshakeState.WaitingForClientKeyExchange && recordType == 0x16)
                    HandleClientKeyExchange(endpoint, key, session, data);
                else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x14)
                {
                    var ccs = new ChangeCipherSpecDatagram();
                    ccs.FromBytes(data);
                    Debug.WriteLine($"[DTLS10 Server] Received ChangeCipherSpec from {endpoint}");
                    _states[key] = HandshakeState.WaitingForFinished;

                    if (_pendingEpoch1Records.TryGetValue(key, out var pending))
                    {
                        _pendingEpoch1Records.Remove(key);
                        foreach (var pendingData in pending)
                            HandleClientFinished(endpoint, key, session, pendingData);
                    }
                }
                else if (state == HandshakeState.WaitingForChangeCipherSpec && recordType == 0x16)
                {
                    // Encrypted Finished arrived before CCS — buffer it.
                    if (!_pendingEpoch1Records.TryGetValue(key, out var pending))
                        _pendingEpoch1Records[key] = pending = new List<byte[]>();
                    pending.Add(data);
                    Debug.WriteLine($"[DTLS10 Server] Buffered encrypted Finished pending CCS from {endpoint}");
                }
                else if (state == HandshakeState.WaitingForFinished && recordType == 0x16)
                    HandleClientFinished(endpoint, key, session, data);
                else if (state == HandshakeState.Complete && recordType == 0x17)
                    HandleApplicationData(endpoint, key, session, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DTLS10 Server] Error from {endpoint}: {ex.Message}");
            }
        }

        private void HandleInitialClientHello(EndPoint endpoint, string key, byte[] data)
        {
            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(data);

            if (ShouldSendHelloVerify && clientHello.Cookie.Length == 0)
            {
                var cookie = Dtls10CryptoUtils.CreateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
                var hvr = new HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = 0 };
                ServerTransport.Send(endpoint, hvr.ToBytes());
                Debug.WriteLine($"[DTLS10 Server] Sent HelloVerifyRequest to {endpoint}");
                return;
            }

            if (ShouldSendHelloVerify && clientHello.Cookie.Length > 0)
            {
                if (!Dtls10CryptoUtils.ValidateCookie(DateTime.UtcNow,
                    ((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port,
                    clientHello.Cookie))
                    throw new Exception("Invalid cookie");
            }

            var (privateX25519, publicX25519) = Dtls13CryptoUtils.CreateX25519KeyPair();
            byte[] serverPrivKey = privateX25519.GetEncoded();
            byte[] serverPubKey  = publicX25519.GetEncoded();

            var session = new Dtls10Session
            {
                PrivateKey   = serverPrivKey,
                PublicKey    = serverPubKey,
                ClientRandom = clientHello.ClientRandom,
                ServerRandom = Dtls13CryptoUtils.GenerateRandom(32),
            };

            bool clientWantsSrtp = clientHello.Extensions
                .OfType<DTLS12.Messages.UseSrtpExtension>().Any();
            ushort srtpProfile = clientWantsSrtp
                ? clientHello.Extensions.OfType<DTLS12.Messages.UseSrtpExtension>().First().ProtectionProfiles[0]
                : (ushort)0;

            ushort cipherSuite = clientHello.CipherSuites.Contains((ushort)0xC013)
                ? (ushort)0xC013
                : clientHello.CipherSuites.First();

            var serverHello = new ServerHelloDatagram(cipherSuite, session.ServerRandom,
                clientWantsSrtp, srtpProfile)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(clientHello);
            session.HandshakeMessages.Add(serverHello);
            ServerTransport.Send(endpoint, serverHello.ToBytes());

            X509Certificate cert = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(_serverCertificate));
            byte[] derCert = cert.GetEncoded();

            var certificate = new ServerCertificateDatagram(derCert)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(certificate);
            ServerTransport.Send(endpoint, certificate.ToBytes());

            byte[] ecParams = BuildEcParams(serverPubKey);
            byte[] toSign   = session.ClientRandom.Concat(session.ServerRandom).Concat(ecParams).ToArray();

            AsymmetricKeyParameter rsaPriv = LoadRsaPrivateKey(_serverCertificatePrivateKey);
            ISigner signer = SignerUtilities.GetSigner("SHA1WITHRSA");
            signer.Init(true, rsaPriv);
            signer.BlockUpdate(toSign, 0, toSign.Length);
            byte[] signature = signer.GenerateSignature();

            var serverKeyExchange = new ServerKeyExchangeDatagram(serverPubKey, signature)
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverKeyExchange);
            ServerTransport.Send(endpoint, serverKeyExchange.ToBytes());

            var serverHelloDone = new ServerHelloDoneDatagram
            {
                RecordSequenceNumber  = session.RecordSequenceNumber++,
                MessageSequenceNumber = session.MessageSequenceNumber++,
            };
            session.HandshakeMessages.Add(serverHelloDone);
            ServerTransport.Send(endpoint, serverHelloDone.ToBytes());

            _sessions[key] = session;
            _states[key]   = HandshakeState.WaitingForClientKeyExchange;
            Debug.WriteLine($"[DTLS10 Server] ServerHello flight sent to {endpoint}");
        }

        private void HandleClientKeyExchange(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var cke = new ClientKeyExchangeDatagram();
            cke.FromBytes(data);
            session.HandshakeMessages.Add(cke);

            byte[] preMaster = Dtls13CryptoUtils.DeriveSharedSecretX25519(session.PrivateKey, cke.PublicKey);
            byte[] master    = Dtls10CryptoUtils.CalculateMasterSecret(preMaster, session.ClientRandom, session.ServerRandom);
            session.CryptoContext = Dtls10CryptoUtils.DeriveKeys(master, session.ClientRandom, session.ServerRandom);

            Debug.WriteLine($"[DTLS10 Server] master_secret: {Convert.ToHexString(master).ToLower()}");
            Debug.WriteLine($"[DTLS10 Server] client_key: {Convert.ToHexString(session.CryptoContext.ClientKey).ToLower()}");
            Debug.WriteLine($"[DTLS10 Server] server_key: {Convert.ToHexString(session.CryptoContext.ServerKey).ToLower()}");

            _states[key] = HandshakeState.WaitingForChangeCipherSpec;
        }

        private void HandleClientFinished(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var encFinished = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            encFinished.FromBytes(data);
            var clientFinished = encFinished.Datagram as FinishedDatagram;

            byte[] transcriptHash = Dtls10CryptoUtils.HashTranscript(session.HandshakeMessages);
            byte[] expectedVerify = Dtls10CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "client finished", transcriptHash);

            if (!expectedVerify.SequenceEqual(clientFinished.VerifyData))
                throw new Exception("Client Finished verify_data mismatch!");

            Debug.WriteLine($"[DTLS10 Server] Client Finished verified");
            session.HandshakeMessages.Add(encFinished);

            var ccs = new ChangeCipherSpecDatagram
            {
                Epoch                = 0,
                RecordSequenceNumber = session.RecordSequenceNumber++,
            };
            ServerTransport.Send(endpoint, ccs.ToBytes());

            byte[] serverTranscriptHash = Dtls10CryptoUtils.HashTranscript(session.HandshakeMessages);
            byte[] serverVerify = Dtls10CryptoUtils.CalculateVerifyData(
                session.CryptoContext.MasterSecret, "server finished", serverTranscriptHash);

            var finished = new FinishedDatagram(serverVerify, session.MessageSequenceNumber++);
            var encServerFinished = new ServerEncryptedDatagram(session.CryptoContext, finished)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, encServerFinished.ToBytes());

            _states[key] = HandshakeState.Complete;
            session.Epoch = 1;
            session.RecordSequenceNumber = (ushort)session.CryptoContext.ServerSequenceNumber;

            Debug.WriteLine($"[DTLS10 Server] Handshake complete with {endpoint}");
            HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        private void HandleApplicationData(EndPoint endpoint, string key, Dtls10Session session, byte[] data)
        {
            var enc = new ClientEncryptedDatagram(session.CryptoContext)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ClientSequenceNumber++,
            };
            enc.FromBytes(data);
            var appData = enc.Datagram as ApplicationDataDatagram;

            Console.WriteLine($"[DTLS10 Server] AppData from {endpoint}: {Encoding.UTF8.GetString(appData.Data)}");

            var reply = new ServerEncryptedDatagram(session.CryptoContext,
                new ApplicationDataDatagram(Encoding.UTF8.GetBytes("Hello from DTLS 1.0 server!")), 0x17)
            {
                Epoch          = 1,
                SequenceNumber = session.CryptoContext.ServerSequenceNumber++,
            };
            ServerTransport.Send(endpoint, reply.ToBytes());
        }

        private static byte[] BuildEcParams(byte[] publicKey)
        {
            var result = new byte[1 + 2 + 1 + publicKey.Length];
            result[0] = 0x03;
            result[1] = 0x00; result[2] = 0x1D; // x25519
            result[3] = (byte)publicKey.Length;
            Buffer.BlockCopy(publicKey, 0, result, 4, publicKey.Length);
            return result;
        }

        private static AsymmetricKeyParameter LoadRsaPrivateKey(string pem)
        {
            var pemObj = new PemReader(new StringReader(pem)).ReadPemObject();
            var seq    = Asn1Sequence.GetInstance(pemObj.Content);
            var rsa    = RsaPrivateKeyStructure.GetInstance(seq);
            return new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent,
                rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);
        }
    }
}
