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
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS.DTLS13
{
    public class Dtls13Client
    {
        private EncryptedExtensionsDatagram _serverExtensionsDatagram = null;
        private CertificateDatagram _serverCertificateDatagram = null;
        private CertificateVerifyDatagram _serverCertVerifyDatagram = null;
        private FinishedDatagram _serverFinishedDatagram = null;
        private AcknowledgementDatagram _serverAckDatagram = null;

        private int _expectedServerRecordNumber = 0;
        private readonly SortedDictionary<int, byte[]> _handshakeReorderBuffer = new();
        private readonly HandshakeReassembler _reassembler = new();

        public event EventHandler<EventArgs> HandshakeFinished;

        public Dtls13Session Session { get; } = new Dtls13Session();
        public ClientTransport ClientTransport { get; }

        public Dtls13Client(ClientTransport clientTransport)
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

                    // in cases where the cookie exchange is used, the initial ClientHello and HelloVerifyRequest MUST NOT be included in the CertificateVerify or Finished MAC computations
                    Session.HandshakeMessages.Clear();

                    Session.HandshakeMessages.Add(clientHelloWithCookie);
                    ClientTransport.Send(clientHelloWithCookie.ToBytes());
                    return;
                }

                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();

                byte[] helloHash = Dtls13CryptoUtils.CalculateHelloHash(clientHello.ToBytes(), serverHello.Bytes);
                Debug.WriteLine($"hello_hash: {Convert.ToHexString(helloHash).ToLowerInvariant()}");

                byte[] sharedSecret = Dtls13CryptoUtils.DeriveSharedSecretX25519(Session.PrivateKey, serverHello.PublicKey);
                Debug.WriteLine($"shared_secret: {Convert.ToHexString(sharedSecret).ToLowerInvariant()}");

                Session.ServerHandshakeKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(clientHello.ClientRandom, helloHash, sharedSecret);
                Debug.WriteLine($"handshake_secret: {Convert.ToHexString(Session.ServerHandshakeKeys.Secret).ToLowerInvariant()}");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerHandshakeKeys.ServerSnKey).ToLowerInvariant()}");

                // from now on the conneciton is encrypted
                Session.Epoch = 2;
                Session.RecordNumber = 0;
            }
            else
            {
                int epoch = data[0] & 0x03;

                if (epoch == 2)
                {
                    // Handshake flight — buffer by record number so out-of-order packets are
                    // held until all preceding records have been decrypted and processed.
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
            // Decrypt the individual record first; each fragment is independently decryptable.
            var enc = new ServerEncryptedDatagram(Session.ServerHandshakeKeys);
            byte[] plaintext = enc.Decrypt(data);
            Session.ServerHandshakeKeys.ServerKeyUseCounter++;

            // Reassemble if this is a fragment; return early until the message is complete.
            if (!_reassembler.TryAddFragment(plaintext, out byte[] complete))
                return;

            enc.ParsePlaintext(complete);

            if (_serverExtensionsDatagram == null)
            {
                var extensions = enc.Datagram as EncryptedExtensionsDatagram;
                Session.HandshakeMessages.Add(enc);
                _serverExtensionsDatagram = extensions;
                Debug.WriteLine($"Received server extensions: {extensions.Extensions.Count}");
            }
            else if (_serverCertificateDatagram == null)
            {
                var cert = enc.Datagram as CertificateDatagram;
                Session.HandshakeMessages.Add(enc);
                _serverCertificateDatagram = cert;
                Debug.WriteLine($"Received server certificate: {Convert.ToHexString(cert.Certificate).ToLowerInvariant()}");
            }
            else if (_serverCertVerifyDatagram == null)
            {
                var certVerify = enc.Datagram as CertificateVerifyDatagram;

                byte[] h = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                Debug.WriteLine($"handshake_hash: {Convert.ToHexString(h).ToLowerInvariant()}");

                byte[] toSign = Encoding.UTF8.GetBytes("                                                                TLS 1.3, server CertificateVerify\0").Concat(h).ToArray();
                X509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(_serverCertificateDatagram.Certificate);
                ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA/PSS");
                signer.Init(false, serverCertificate.GetPublicKey());
                signer.BlockUpdate(toSign);

                if (!signer.VerifySignature(certVerify.Signature))
                    throw new Exception("Signature invalid!");

                Session.HandshakeMessages.Add(enc);
                _serverCertVerifyDatagram = certVerify;
                Debug.WriteLine("Signature verified");
            }
            else if (_serverFinishedDatagram == null)
            {
                var serverFinished = enc.Datagram as FinishedDatagram;

                var crypto = new BcTlsCrypto();
                var hashAlg = CryptoHashAlgorithm.sha256;
                var finishedServerKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ServerSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] finishedServerHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                byte[] verifyServerData = Dtls13CryptoUtils.CalculateHmac(finishedServerKey, finishedServerHash);

                if (!verifyServerData.SequenceEqual(serverFinished.VerifyData))
                    throw new Exception("Server verify failed!");

                Debug.WriteLine("Server verify successful!");
                Session.HandshakeMessages.Add(enc);

                byte[] finishedClientHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                var finishedClientKey = Dtls13CryptoUtils.HkdfExpandLabel(new BcTlsSecret(crypto, Session.ServerHandshakeKeys.ClientSecret), hashAlg, "finished", new byte[0], 32).Extract();
                byte[] verifyClientData = Dtls13CryptoUtils.CalculateHmac(finishedClientKey, finishedClientHash);

                var encClientFinished = new ClientEncryptedDatagram(Session.ServerHandshakeKeys, new FinishedDatagram { VerifyData = verifyClientData })
                {
                    Epoch = Session.Epoch,
                    RecordNumber = Session.RecordNumber++,
                };
                ClientTransport.Send(encClientFinished.ToBytes());
                Session.ServerHandshakeKeys.ClientKeyUseCounter++;

                byte[] allMessagesHash = Dtls13CryptoUtils.HashAllMessages(Session.HandshakeMessages);
                var clientHello = Session.HandshakeMessages.OfType<ClientHelloDatagram>().Last();
                Session.ServerApplicationKeys = Dtls13CryptoUtils.CalculateApplicationKeys(clientHello.ClientRandom, allMessagesHash, Session.ServerHandshakeKeys.Secret);

                Debug.WriteLine("Client Application Keys:");
                Debug.WriteLine($"client_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientKey).ToLowerInvariant()}");
                Debug.WriteLine($"client_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ClientIv).ToLowerInvariant()}");
                Debug.WriteLine($"server_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_iv: {Convert.ToHexString(Session.ServerApplicationKeys.ServerIv).ToLowerInvariant()}");
                Debug.WriteLine($"client_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ClientSnKey).ToLowerInvariant()}");
                Debug.WriteLine($"server_sn_key: {Convert.ToHexString(Session.ServerApplicationKeys.ServerSnKey).ToLowerInvariant()}");
                Debug.WriteLine("------------------------");

                _serverFinishedDatagram = serverFinished;
            }
            else
            {
                Debug.WriteLine("[DTLS13 Client] ProcessServerHandshakeRecord: unexpected record in epoch 2");
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
            }
            else
            {
                var enc = new ServerEncryptedDatagram(Session.ServerApplicationKeys);
                enc.FromBytes(data);
                var appData = enc.Datagram as ApplicationDataDatagram;
                Session.ServerApplicationKeys.ServerKeyUseCounter++;

                Debug.WriteLine($"Received server application data: {Encoding.UTF8.GetString(appData.Data)}");

                await Task.Delay(1000);

                SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
            }
        }

        // DTLS 1.3 impl
        public void BeginHandshake()
        {
            var (privateKey, publicKey) = Dtls13CryptoUtils.CreateX25519KeyPair();
            Session.PrivateKey = privateKey.GetEncoded();
            Session.PublicKey = publicKey.GetEncoded();

            var clientHello = new ClientHelloDatagram(Session.PublicKey);
            clientHello.Extensions.Add(new UseSrtpExtension());

            Session.HandshakeMessages.Add(clientHello);
            ClientTransport.Send(clientHello.ToBytes());
        }

        public void SendApplicationData(byte[] data)
        {
            ClientEncryptedDatagram encryptedApplicationData = new ClientEncryptedDatagram(Session.ServerApplicationKeys, new ApplicationDataDatagram(data))
            {
                 Epoch = Session.Epoch,
                 RecordNumber = Session.RecordNumber++
            };
            var encryptedApplicationDataBytes = encryptedApplicationData.ToBytes();
            Session.ServerApplicationKeys.ClientKeyUseCounter++;
            ClientTransport.Send(encryptedApplicationDataBytes);
        }
    }   
}
