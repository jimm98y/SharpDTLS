using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
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
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS.DTLS13
{
    public class Dtls13Client
    {
        private EncryptedExtensionsDatagram    _serverExtensionsDatagram = null;
        private CertificateRequestDatagram     _certRequestDatagram      = null;
        private CertificateDatagram            _serverCertificateDatagram = null;
        private CertificateVerifyDatagram      _serverCertVerifyDatagram  = null;
        private FinishedDatagram               _serverFinishedDatagram    = null;
        private AcknowledgementDatagram        _serverAckDatagram         = null;

        private int _expectedServerRecordNumber = 0;
        private readonly SortedDictionary<int, byte[]> _handshakeReorderBuffer = new();
        private readonly HandshakeReassembler _reassembler = new();

        public event EventHandler<EventArgs>                 HandshakeFinished;
        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;
        public event EventHandler<KeyUpdateDatagram>        KeyUpdateReceived;

        public Dtls13Session Session { get; } = new Dtls13Session();
        public IClientTransport ClientTransport { get; }

        // Set these before BeginHandshake to enable client authentication.
        public AsymmetricCipherKeyPair ClientCertificateKeyPair { get; set; }
        public X509Certificate ClientCertificate { get; set; }

        public Dtls13Client(IClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            ClientTransport.OnDataReceived += ClientTransport_OnDataReceived;
        }

        private async void ClientTransport_OnDataReceived(object sender, byte[] data)
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
                    var originalClientRandom = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last().ClientRandom;
                    var clientHelloWithCookie = new ClientHelloDatagram(Session.PublicKey)
                    {
                        ClientRandom = originalClientRandom,
                    };
                    clientHelloWithCookie.Extensions.Add(new CookieExtension() { Cookie = serverHello.Extensions.OfType<CookieExtension>().First().Cookie });

                    // initial ClientHello and HelloVerifyRequest MUST NOT be in the MAC computations
                    Session.HandshakeMessages.Clear();
                    Session.HandshakeMessages.Add(clientHelloWithCookie);
                    ClientTransport.Send(clientHelloWithCookie.ToBytes());
                    return;
                }

                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();

                byte[] helloHash    = Dtls13CryptoUtils.CalculateHelloHash(clientHello.ToBytes(), serverHello.Bytes);
                byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, serverHello.PublicKey);

                Session.ServerHandshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);

                Session.Epoch = 2;
                Session.RecordNumber = 0;
            }
            else
            {
                int epoch = data[0] & 0x03;

                if (epoch == 2)
                {
                    ushort recNum = ServerEncryptedDatagram.PeekRecordNumber(data, Session.ServerHandshakeKeys);

                    if (recNum < _expectedServerRecordNumber)
                        return; // duplicate

                    if (recNum > _expectedServerRecordNumber)
                    {
                        _handshakeReorderBuffer[recNum] = data;
                        Debug.WriteLine($"[DTLS13 Client] Buffered out-of-order record_number={recNum}, expected={_expectedServerRecordNumber}");
                        return;
                    }

                    ProcessServerHandshakeRecord(data);
                    _expectedServerRecordNumber++;

                    while (_handshakeReorderBuffer.TryGetValue(_expectedServerRecordNumber, out var buffered))
                    {
                        _handshakeReorderBuffer.Remove(_expectedServerRecordNumber);
                        ProcessServerHandshakeRecord(buffered);
                        _expectedServerRecordNumber++;
                    }
                }
                else
                {
                    await ProcessServerApplicationRecord(data);
                }
            }
        }

        private void ProcessServerHandshakeRecord(byte[] data)
        {
            var enc = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
            byte[] plaintext = enc.Decrypt(data);
            Session.ServerHandshakeKeys.ServerKeyUseCounter++;

            if (!_reassembler.TryAddFragment(plaintext, out byte[] complete))
                return;

            enc.ParsePlaintext(complete);

            if (_serverExtensionsDatagram == null)
            {
                var extensions = enc.Datagram as EncryptedExtensionsDatagram;
                Session.HandshakeMessages.Add(enc);
                _serverExtensionsDatagram = extensions;
                Debug.WriteLine($"[DTLS13 Client] Received EncryptedExtensions: {extensions.Extensions.Count} ext");
            }
            else if (_serverCertificateDatagram == null)
            {
                // Could be CertificateRequest (if server requires client auth) or Certificate.
                if (enc.Datagram is CertificateRequestDatagram certReqDatagram)
                {
                    Session.HandshakeMessages.Add(enc);
                    _certRequestDatagram = certReqDatagram;
                    Debug.WriteLine($"[DTLS13 Client] Received CertificateRequest");
                }
                else
                {
                    var cert = enc.Datagram as CertificateDatagram;
                    Session.HandshakeMessages.Add(enc);
                    _serverCertificateDatagram = cert;
                    Debug.WriteLine($"[DTLS13 Client] Received server certificate: {Convert.ToHexString(cert.Certificate).ToLowerInvariant()}");
                }
            }
            else if (_serverCertVerifyDatagram == null)
            {
                var certVerify = enc.Datagram as CertificateVerifyDatagram;

                byte[] h = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();
                X509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(_serverCertificateDatagram.Certificate);
                AsymmetricKeyParameter pubKey = serverCertificate.GetPublicKey();
                bool isEcKey = pubKey is ECPublicKeyParameters;
                ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA/PSS");
                signer.Init(false, pubKey);
                signer.BlockUpdate(toSign);

                if (!signer.VerifySignature(certVerify.Signature))
                    throw new Exception("Server CertificateVerify signature invalid!");

                Session.HandshakeMessages.Add(enc);
                _serverCertVerifyDatagram = certVerify;
                Debug.WriteLine("[DTLS13 Client] Server CertificateVerify verified");
            }
            else if (_serverFinishedDatagram == null)
            {
                var serverFinished = enc.Datagram as FinishedDatagram;

                var crypto          = new BcTlsCrypto();
                var hashAlg         = CryptoHashAlgorithm.sha256;
                var finishedServerKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] finishedServerHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                byte[] verifyServerData = Dtls13CryptoUtils.CalculateHmac(finishedServerKey, finishedServerHash);

                if (!verifyServerData.SequenceEqual(serverFinished.VerifyData))
                    throw new Exception("Server verify failed!");

                Debug.WriteLine("[DTLS13 Client] Server Finished verified");
                Session.HandshakeMessages.Add(enc);
                _serverFinishedDatagram = serverFinished;

                // ── Client Certificate + CertificateVerify (if requested) ──────────
                if (_certRequestDatagram != null)
                {
                    SendClientCertificateFlight();
                }

                // ── Client Finished ────────────────────────────────────────────────
                byte[] finishedClientHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                var finishedClientKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] verifyClientData = Dtls13CryptoUtils.CalculateHmac(finishedClientKey, finishedClientHash);

                // Derive application keys BEFORE sending client Finished so that the ACK
                // that arrives synchronously in mock transport contexts finds them set.
                byte[] allMessagesHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
                Session.ServerApplicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, allMessagesHash, Session.ServerHandshakeKeys.Secret);

                var encClientFinished = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, new FinishedDatagram { VerifyData = verifyClientData })
                {
                    Epoch        = Session.Epoch,
                    RecordNumber = Session.RecordNumber++,
                };
                ClientTransport.Send(encClientFinished.ToBytes());
                Session.ServerHandshakeKeys.ClientKeyUseCounter++;
            }
            else
            {
                Debug.WriteLine("[DTLS13 Client] ProcessServerHandshakeRecord: unexpected record in epoch 2");
            }
        }

        private void SendClientCertificateFlight()
        {
            bool sendingCert = ClientCertificate != null;
            byte[] certBytes = sendingCert ? ClientCertificate.GetEncoded() : Array.Empty<byte>();

            var certDatagram = new CertificateDatagram(certBytes);
            certDatagram.ToBytes(); // ensure Bytes is set for transcript
            var encClientCert = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, certDatagram)
            {
                Epoch        = Session.Epoch,
                RecordNumber = Session.RecordNumber++,
            };
            ClientTransport.Send(encClientCert.ToBytes());
            Session.ServerHandshakeKeys.ClientKeyUseCounter++;
            Session.HandshakeMessages.Add(encClientCert);
            Debug.WriteLine($"[DTLS13 Client] Sent Certificate (len={certBytes.Length})");

            if (sendingCert && ClientCertificateKeyPair != null)
            {
                byte[] h = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, client CertificateVerify\0").Concat(h).ToArray();

                bool isEcKey = ClientCertificateKeyPair.Private is ECPrivateKeyParameters;
                ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA/PSS");
                signer.Init(true, ClientCertificateKeyPair.Private);
                signer.BlockUpdate(toSign);
                byte[] signature = signer.GenerateSignature();

                uint sigType = isEcKey ? 0x0403u : 0x0804u;
                var certVerify = new CertificateVerifyDatagram(signature, sigType);
                certVerify.ToBytes(); // ensure Bytes is set for transcript
                var encCertVerify = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, certVerify)
                {
                    Epoch        = Session.Epoch,
                    RecordNumber = Session.RecordNumber++,
                };
                ClientTransport.Send(encCertVerify.ToBytes());
                Session.ServerHandshakeKeys.ClientKeyUseCounter++;
                Session.HandshakeMessages.Add(encCertVerify);
                Debug.WriteLine($"[DTLS13 Client] Sent CertificateVerify");
            }
        }

        private async Task ProcessServerApplicationRecord(byte[] data)
        {
            if (_serverAckDatagram == null)
            {
                Debug.WriteLine($"[DTLS13 Client] Received ACK: {Convert.ToHexString(data).ToLowerInvariant()}");
                var enc = new ServerEncryptedDatagram(Session.ServerApplicationKeys);
                enc.FromBytes(data);
                var ack = enc.Datagram as AcknowledgementDatagram;
                Session.ServerApplicationKeys.ServerKeyUseCounter++;
                _serverAckDatagram = ack;

                Session.Epoch = 3;
                Session.RecordNumber = 0;

                HandshakeFinished?.Invoke(this, EventArgs.Empty);
                return;
            }

            var record = new ServerEncryptedDatagram(Session.ServerApplicationKeys);
            record.FromBytes(data);
            Session.ServerApplicationKeys.ServerKeyUseCounter++;

            switch (record.Datagram)
            {
                case ApplicationDataDatagram appData:
                    Debug.WriteLine($"[DTLS13 Client] Received app data: {Encoding.UTF8.GetString(appData.Data)}");
                    await Task.Delay(1000);
                    SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
                    break;

                case NewSessionTicketDatagram nst:
                    Debug.WriteLine($"[DTLS13 Client] Received NewSessionTicket (lifetime={nst.TicketLifetime}s)");
                    NewSessionTicketReceived?.Invoke(this, nst);
                    break;

                case KeyUpdateDatagram keyUpdate:
                    Debug.WriteLine($"[DTLS13 Client] Received KeyUpdate (update_request=0x{keyUpdate.UpdateRequest:X2})");
                    Session.ServerApplicationKeys = Dtls13CryptoUtils.UpdateServerTrafficSecret(Session.ServerApplicationKeys);
                    KeyUpdateReceived?.Invoke(this, keyUpdate);
                    if (keyUpdate.UpdateRequest == 0x01)
                        SendKeyUpdate(requestUpdate: false);
                    break;

                default:
                    Debug.WriteLine($"[DTLS13 Client] Received unknown post-handshake record, ignoring");
                    break;
            }
        }

        public void BeginHandshake()
        {
            var (privateKey, publicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey = privateKey.GetEncoded();
            Session.PublicKey  = publicKey.GetEncoded();

            var clientHello = new ClientHelloDatagram(Session.PublicKey);
            clientHello.Extensions.Add(new UseSrtpExtension());

            Session.HandshakeMessages.Add(clientHello);
            ClientTransport.Send(clientHello.ToBytes());
        }

        public void SendApplicationData(byte[] data)
        {
            var encryptedApplicationData = new ClientEncryptedDatagram(Session.ServerApplicationKeys, new ApplicationDataDatagram(data))
            {
                Epoch        = Session.Epoch,
                RecordNumber = Session.RecordNumber++,
            };
            var encryptedApplicationDataBytes = encryptedApplicationData.ToBytes();
            Session.ServerApplicationKeys.ClientKeyUseCounter++;
            ClientTransport.Send(encryptedApplicationDataBytes);
        }

        // Sends a KeyUpdate handshake message and updates the client write keys.
        // Set requestUpdate=true to ask the peer to perform a key update as well.
        public void SendKeyUpdate(bool requestUpdate = false)
        {
            var keyUpdate = new KeyUpdateDatagram(requestUpdate ? (byte)0x01 : (byte)0x00);
            var enc = new ClientEncryptedDatagram(Session.ServerApplicationKeys, keyUpdate)
            {
                Epoch        = Session.Epoch,
                RecordNumber = Session.RecordNumber++,
            };
            ClientTransport.Send(enc.ToBytes());
            Session.ServerApplicationKeys.ClientKeyUseCounter++;
            Session.ServerApplicationKeys = Dtls13CryptoUtils.UpdateClientTrafficSecret(Session.ServerApplicationKeys);
            Debug.WriteLine($"[DTLS13 Client] Sent KeyUpdate (update_request=0x{keyUpdate.UpdateRequest:X2}), rotated client write keys");
        }
    }
}
