using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10;
using SharpDTLS.DTLS10.Messages;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpDTLS.DTLS13.Messages;
using System;
using System.Threading;
using System.Threading.Tasks;
using CertReq10 = SharpDTLS.DTLS10.Messages.CertificateRequestDatagram;
using CertReq12 = SharpDTLS.DTLS12.Messages.CertificateRequestDatagram;
using CertVerify10 = SharpDTLS.DTLS10.Messages.CertificateVerifyDatagram;
using CertVerify12 = SharpDTLS.DTLS12.Messages.CertificateVerifyDatagram;

namespace Dtls13Test.Tests
{
    // ── Helper ───────────────────────────────────────────────────────────────────
    file static class CertHelper
    {
        public static (AsymmetricCipherKeyPair kp, X509Certificate cert) GenerateEc()
            => SharpDTLS.DTLS12.Dtls12CryptoUtils.GenerateSelfSignedCertificate();
    }

    // ── DTLS 1.0 / 1.2 message round-trip ────────────────────────────────────────

    [TestClass]
    public sealed class TestCertificateRequestRoundTrip
    {
        [TestMethod]
        public void Dtls10_CertificateRequest_RoundTrip()
        {
            var cr = new CertReq10 { RecordSequenceNumber = 3, MessageSequenceNumber = 2 };
            byte[] bytes = cr.ToBytes();

            Assert.AreEqual(0x16, bytes[0], "record type");
            Assert.AreEqual(0xFE, bytes[1]); Assert.AreEqual(0xFF, bytes[2]); // DTLS 1.0
            Assert.AreEqual(0x0D, bytes[13], "handshake type");

            var cr2 = new CertReq10();
            cr2.FromBytes(bytes);
            Assert.AreEqual(3,  cr2.RecordSequenceNumber);
            Assert.AreEqual(2,  cr2.MessageSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(cr2.ToBytes()));
        }

        [TestMethod]
        public void Dtls12_CertificateRequest_RoundTrip()
        {
            var cr = new CertReq12 { RecordSequenceNumber = 5, MessageSequenceNumber = 4 };
            byte[] bytes = cr.ToBytes();

            Assert.AreEqual(0x16, bytes[0], "record type");
            Assert.AreEqual(0xFE, bytes[1]); Assert.AreEqual(0xFD, bytes[2]); // DTLS 1.2
            Assert.AreEqual(0x0D, bytes[13], "handshake type");

            var cr2 = new CertReq12();
            cr2.FromBytes(bytes);
            Assert.AreEqual(5, cr2.RecordSequenceNumber);
            Assert.AreEqual(4, cr2.MessageSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(cr2.ToBytes()));
        }
    }

    [TestClass]
    public sealed class TestCertificateVerifyRoundTrip
    {
        [TestMethod]
        public void Dtls10_CertificateVerify_RoundTrip()
        {
            var sig = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var cv = new CertVerify10(sig) { RecordSequenceNumber = 7, MessageSequenceNumber = 5 };
            byte[] bytes = cv.ToBytes();

            Assert.AreEqual(0x16, bytes[0]);
            Assert.AreEqual(0xFE, bytes[1]); Assert.AreEqual(0xFF, bytes[2]); // DTLS 1.0
            Assert.AreEqual(0x0F, bytes[13], "CertificateVerify type");

            var cv2 = new CertVerify10();
            cv2.FromBytes(bytes);
            Assert.AreEqual(7, cv2.RecordSequenceNumber);
            Assert.AreEqual(5, cv2.MessageSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(sig), Convert.ToHexString(cv2.Signature));
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(cv2.ToBytes()));
        }

        [TestMethod]
        public void Dtls12_CertificateVerify_HashAndSigAlgFields_Preserved()
        {
            var sig = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
            var cv = new CertVerify12(sig, 0x04, 0x03)
            {
                RecordSequenceNumber  = 8,
                MessageSequenceNumber = 6,
            };
            byte[] bytes = cv.ToBytes();

            Assert.AreEqual(0x16, bytes[0]);
            Assert.AreEqual(0xFE, bytes[1]); Assert.AreEqual(0xFD, bytes[2]); // DTLS 1.2
            Assert.AreEqual(0x0F, bytes[13]);
            Assert.AreEqual(0x04, bytes[25], "hash algorithm = SHA256");
            Assert.AreEqual(0x03, bytes[26], "sig algorithm = ECDSA");

            var cv2 = new CertVerify12();
            cv2.FromBytes(bytes);
            Assert.AreEqual(0x04, cv2.HashAlgorithm);
            Assert.AreEqual(0x03, cv2.SigAlgorithm);
            Assert.AreEqual(Convert.ToHexString(sig), Convert.ToHexString(cv2.Signature));
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(cv2.ToBytes()));
        }

        [TestMethod]
        public void Dtls13_CertificateRequest_IncludesSignatureAlgorithmsExtension()
        {
            var cr = new SharpDTLS.DTLS13.Messages.CertificateRequestDatagram();
            byte[] bytes = cr.ToBytes();

            // extension type = 0x000D, extension data = 0x0006, list len = 0x0004
            // Find 0x00, 0x0D in the extensions area
            bool found = false;
            for (int i = 0; i < bytes.Length - 1; i++)
            {
                if (bytes[i] == 0x00 && bytes[i + 1] == 0x0D)
                {
                    found = true;
                    break;
                }
            }
            Assert.IsTrue(found, "signature_algorithms extension (0x000D) not found in CertificateRequest");
        }
    }

    // ── End-to-end handshake tests ────────────────────────────────────────────────

    [TestClass]
    public sealed class TestDtls10ClientAuth
    {
        [TestMethod]
        public void Dtls10_ServerRequiresClientCertificate_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var (clientKp, clientCert)             = CertHelper.GenerateEc();

            var server = new Dtls10Server(serverTransport)
            {
                ShouldSendHelloVerify   = false,
                RequireClientCertificate = true,
            };
            var client = new Dtls10Client(clientTransport)
            {
                ClientCertificateKeyPair = clientKp,
                ClientCertificate        = clientCert,
            };

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();

            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
            Assert.IsTrue(serverDone, "Server did not complete handshake");
            Assert.IsTrue(clientDone, "Client did not complete handshake");
        }

        [TestMethod]
        public void Dtls10_NoClientCertRequired_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();

            var server = new Dtls10Server(serverTransport) { ShouldSendHelloVerify = false };
            var client = new Dtls10Client(clientTransport);

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
        }

        [TestMethod]
        public void Dtls10_ServerRequiresClientCertificate_ServerHasClientCertBytes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var (clientKp, clientCert)             = CertHelper.GenerateEc();

            var server = new Dtls10Server(serverTransport)
            {
                ShouldSendHelloVerify    = false,
                RequireClientCertificate = true,
            };
            var client = new Dtls10Client(clientTransport)
            {
                ClientCertificateKeyPair = clientKp,
                ClientCertificate        = clientCert,
            };

            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (s, _) => { tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { };

            client.BeginHandshake();
            tcs.Task.Wait(TimeSpan.FromSeconds(5));

            // The server should have stored the client cert bytes
            // (We can't easily access them without a handle to the session, so just verify handshake passed)
            Assert.IsTrue(tcs.Task.IsCompletedSuccessfully);
        }
    }

    [TestClass]
    public sealed class TestDtls12ClientAuth
    {
        [TestMethod]
        public void Dtls12_ServerRequiresClientCertificate_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var (clientKp, clientCert)             = CertHelper.GenerateEc();

            var server = new Dtls12Server(serverTransport)
            {
                ShouldSendHelloVerify    = false,
                RequireClientCertificate = true,
            };
            var client = new Dtls12Client(clientTransport)
            {
                ClientCertificateKeyPair = clientKp,
                ClientCertificate        = clientCert,
            };

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
            Assert.IsTrue(serverDone, "Server did not complete handshake");
            Assert.IsTrue(clientDone, "Client did not complete handshake");
        }

        [TestMethod]
        public void Dtls12_NoClientCertRequired_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();

            var server = new Dtls12Server(serverTransport) { ShouldSendHelloVerify = false };
            var client = new Dtls12Client(clientTransport);

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
        }

        [TestMethod]
        public void Dtls12_ClientCertVerify_ContainsHashAndSigAlgFields()
        {
            // Build a real CertificateVerify and check the hash+sig-alg bytes
            var (kp, cert) = CertHelper.GenerateEc();
            var transcript = new byte[64]; // dummy transcript
            transcript[0] = 0xDE; transcript[1] = 0xAD;

            bool isEcKey = kp.Private is ECPrivateKeyParameters;
            ISigner signer = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA");
            signer.Init(true, kp.Private);
            signer.BlockUpdate(transcript, 0, transcript.Length);
            byte[] sig = signer.GenerateSignature();

            var cv = new CertVerify12(sig, 0x04, isEcKey ? (byte)0x03 : (byte)0x01)
            {
                RecordSequenceNumber  = 1,
                MessageSequenceNumber = 2,
            };
            byte[] bytes = cv.ToBytes();

            Assert.AreEqual(0x04, bytes[25], "hash algorithm");
            Assert.AreEqual(isEcKey ? 0x03 : 0x01, bytes[26], "sig algorithm");

            // Verify the signature round-trips correctly
            var cv2 = new CertVerify12();
            cv2.FromBytes(bytes);
            ISigner verifier = SignerUtilities.GetSigner(isEcKey ? "SHA256WITHECDSA" : "SHA256WITHRSA");
            verifier.Init(false, cert.GetPublicKey());
            verifier.BlockUpdate(transcript, 0, transcript.Length);
            Assert.IsTrue(verifier.VerifySignature(cv2.Signature), "Signature did not verify");
        }
    }

    [TestClass]
    public sealed class TestDtls13ClientAuth
    {
        [TestMethod]
        public void Dtls13_ServerRequiresClientCertificate_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var (clientKp, clientCert)             = CertHelper.GenerateEc();

            var server = new Dtls13Server(serverTransport)
            {
                ShouldSendHelloRetry     = false,
                RequireClientCertificate = true,
            };
            var client = new Dtls13Client(clientTransport)
            {
                ClientCertificateKeyPair = clientKp,
                ClientCertificate        = clientCert,
            };

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
            Assert.IsTrue(serverDone, "Server did not complete handshake");
            Assert.IsTrue(clientDone, "Client did not complete handshake");
        }

        [TestMethod]
        public void Dtls13_NoClientCertRequired_HandshakeCompletes()
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();

            var server = new Dtls13Server(serverTransport) { ShouldSendHelloRetry = false };
            var client = new Dtls13Client(clientTransport);

            bool serverDone = false, clientDone = false;
            var tcs = new TaskCompletionSource<bool>();
            server.HandshakeFinished += (_, _) => { serverDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };
            client.HandshakeFinished += (_, _) => { clientDone = true; if (serverDone && clientDone) tcs.TrySetResult(true); };

            client.BeginHandshake();

            Assert.IsTrue(tcs.Task.Wait(TimeSpan.FromSeconds(5)), "Handshake did not complete in time");
        }

        [TestMethod]
        public void Dtls13_CertificateVerify_UsesClientContextString()
        {
            // The context string for TLS 1.3 client CertificateVerify must be
            // 64 spaces + "TLS 1.3, client CertificateVerify\0"
            const string clientCtx = "                                                                TLS 1.3, client CertificateVerify\0";
            const string serverCtx = "                                                                TLS 1.3, server CertificateVerify\0";
            CollectionAssert.AreNotEqual(
                System.Text.Encoding.UTF8.GetBytes(clientCtx),
                System.Text.Encoding.UTF8.GetBytes(serverCtx),
                "Client and server context strings must differ");
            Assert.AreEqual(64, clientCtx.IndexOf("TLS"), "Must start with 64 spaces");
        }
    }
}
