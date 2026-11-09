using SharpDTLS;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    [TestClass]
    public sealed class TestDtls12Engine
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;

        private static void Handshake(Tls12ClientConnection client, Dtls12ServerBase server, Action begin)
        {
            var clientDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => clientDone.TrySetResult(true);
            client.Failed += (_, ex) => clientDone.TrySetException(ex);
            begin();
            Assert.IsTrue(clientDone.Task.Wait(Timeout), "Handshake did not complete in time");
        }

        [DataRow((ushort)0xC023)]
        [DataRow((ushort)0xC027)]
        [DataRow((ushort)0xC028)]
        [DataRow((ushort)0xC013)]
        [DataRow((ushort)0xC02F)]
        [DataRow((ushort)0xCCA8)]
        [TestMethod]
        public void Dtls12_EachCipherSuite_NegotiatesAndExchangesData(ushort suite)
        {
            var pair = new ScriptedTransportPair();
            var info = CipherSuites.Get(suite);
            var credentials = info.ServerCertificateType == CertificateKeyType.Ecdsa
                ? SharpDTLS.Protocol13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate()
                : Dtls12CryptoUtils.GenerateSelfSignedCertificate();
            var server = new Dtls12Server(pair.Server, credentials.keyPair, credentials.certificate);
            var client = new Dtls12Client(pair.Client) { CipherSuites = new List<ushort> { suite } };
            var received = new List<string>();
            server.ApplicationDataReceived += (_, e) => received.Add(Encoding.UTF8.GetString(e.Data));

            Handshake(client, server, client.BeginHandshake);

            Assert.AreEqual(suite, client.CipherSuite.Id);
            Assert.AreEqual(info.IsCbc, client.EncryptThenMacNegotiated, "encrypt_then_mac applies to CBC suites only");
            Assert.IsTrue(client.ExtendedMasterSecretNegotiated);

            for (int i = 0; i < 300; i++)
                client.SendApplicationData(Encoding.UTF8.GetBytes($"m{i}"));
            Assert.HasCount(300, received);
        }

        [TestMethod]
        public void VersionNegotiation_Dtls12ClientAcceptingDtls10_TalksToDtls10Server()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10 };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = DtlsVersion.Dtls10 };

            Handshake(client, server, client.BeginHandshake);

            Assert.AreEqual(DtlsVersion.Dtls10, client.NegotiatedVersion);
            Assert.IsTrue(client.CipherSuite.IsCbc);
        }

        [TestMethod]
        public void VersionNegotiation_Dtls10Client_TalksToServerAcceptingBoth()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { MinimumVersion = DtlsVersion.Dtls10 };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10 };

            Handshake(client, server, client.BeginHandshake);

            Assert.AreEqual(DtlsVersion.Dtls10, client.NegotiatedVersion);
        }

        [TestMethod]
        public void FallbackScsv_BelowServerMaximum_IsRejected()
        {
            // RFC 7507: a DTLS 1.0 retry marked as a fallback reaches a server that supports DTLS 1.2.
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { MinimumVersion = DtlsVersion.Dtls10 };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, IsFallback = true };
            var failed = new TaskCompletionSource<Exception>();
            client.Failed += (_, ex) => failed.TrySetResult(ex);

            client.BeginHandshake();

            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.InappropriateFallback, ((DtlsException)failed.Task.Result).Alert);
        }

        [TestMethod]
        public void FallbackScsv_AtServerMaximum_IsAccepted()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10 };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, IsFallback = true };

            Handshake(client, server, client.BeginHandshake);

            Assert.AreEqual(DtlsVersion.Dtls10, client.NegotiatedVersion);
        }

        [TestMethod]
        public void VersionNegotiation_Dtls12OnlyServer_RejectsDtls10Client()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server);
            var client = new Dtls12Client(pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10 };
            var failed = new TaskCompletionSource<Exception>();
            client.Failed += (_, ex) => failed.TrySetResult(ex);

            client.BeginHandshake();

            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.ProtocolVersion, ((DtlsException)failed.Task.Result).Alert);
        }

        [TestMethod]
        public void ChangeCipherSpecOvertakingClientKeyExchange_IsApplied()
        {
            // Hold back the client's ClientKeyExchange so its ChangeCipherSpec and Finished arrive first.
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { ShouldSendHelloVerify = false };
            var client = new Dtls12Client(pair.Client) { InitialRetransmitTimeout = TimeSpan.FromSeconds(30) };
            byte[] heldKeyExchange = null;
            pair.ClientToServer = d =>
            {
                if (d[0] == 0x16 && d[3] == 0 && d[4] == 0 && d[13] == HandshakeType.ClientKeyExchange)
                {
                    heldKeyExchange = d;
                    return Array.Empty<byte[]>();
                }
                if (d[3] == 0 && d[4] == 1 && heldKeyExchange != null)
                {
                    var reordered = new[] { d, heldKeyExchange };
                    heldKeyExchange = null;
                    return reordered;
                }
                return new[] { d };
            };

            Handshake(client, server, client.BeginHandshake);
        }
    }

    [TestClass]
    public sealed class TestRecordCiphers
    {
        private static (IRecordCipher, IRecordCipher) Create(ushort suiteId, bool encryptThenMac)
        {
            var suite = CipherSuites.Get(suiteId);
            byte[] keyBlock = new byte[RecordCiphers.KeyBlockLength(suite)];
            new Random(42).NextBytes(keyBlock);
            return RecordCiphers.Create(suite, keyBlock, encryptThenMac);
        }

        [DataRow((ushort)0xC02F, false)]
        [DataRow((ushort)0xC030, false)]
        [DataRow((ushort)0xCCA8, false)]
        [DataRow((ushort)0xC013, false)]
        [DataRow((ushort)0xC013, true)]
        [DataRow((ushort)0xC028, false)]
        [DataRow((ushort)0xC028, true)]
        [TestMethod]
        public void RoundTrip_AndTamperDetection(ushort suiteId, bool encryptThenMac)
        {
            var (writer, _) = Create(suiteId, encryptThenMac);
            var (reader, _) = Create(suiteId, encryptThenMac);

            foreach (int length in new[] { 0, 1, 15, 16, 17, 255, 1000 })
            {
                byte[] plaintext = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
                byte[] record = writer.Encrypt(0x17, DtlsVersion.Dtls12, 1, (ulong)length, plaintext);
                CollectionAssert.AreEqual(plaintext, reader.Decrypt(0x17, DtlsVersion.Dtls12, 1, (ulong)length, record));

                for (int position = 0; position < record.Length; position += Math.Max(1, record.Length / 7))
                {
                    byte[] tampered = (byte[])record.Clone();
                    tampered[position] ^= 0x01;
                    Assert.ThrowsExactly<DtlsRecordDiscardedException>(() => reader.Decrypt(0x17, DtlsVersion.Dtls12, 1, (ulong)length, tampered));
                }

                // header fields are authenticated too
                Assert.ThrowsExactly<DtlsRecordDiscardedException>(() => reader.Decrypt(0x17, DtlsVersion.Dtls12, 1, (ulong)length + 1, record));
                Assert.ThrowsExactly<DtlsRecordDiscardedException>(() => reader.Decrypt(0x16, DtlsVersion.Dtls12, 1, (ulong)length, record));
            }
        }
    }
}
