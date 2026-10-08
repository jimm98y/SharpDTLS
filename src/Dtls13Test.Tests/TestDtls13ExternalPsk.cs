using SharpDTLS;
using SharpDTLS.DTLS13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.3 external PSKs (RFC 8446 §2.2, §4.2.9, §4.2.11).</summary>
    [TestClass]
    public sealed class TestDtls13ExternalPsk
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly byte[] Identity = Encoding.ASCII.GetBytes("device-17");
        private static readonly byte[] Key = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public Exception ClientError;
            public Dtls13ServerConnection ServerConnection => Server.GetConnection(ScriptedTransportPair.ClientEndpoint);
            public List<string> ServerReceived = new();
        }

        private static Dtls13ExternalPsk Resolve(byte[] identity) => identity.AsSpan().SequenceEqual(Identity) ? new Dtls13ExternalPsk(Identity, Key) : null;

        private static Run Connect(Action<Dtls13Server> configureServer, Action<Dtls13Client> configureClient, bool expectSuccess = true,
            bool certificate = true)
        {
            var r = new Run();
            r.Server = certificate ? new Dtls13Server(r.Pair.Server) : new Dtls13Server(r.Pair.Server, null, null);
            r.Server.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50);
            r.Server.ExternalPskResolver = Resolve;
            configureServer?.Invoke(r.Server);
            r.Server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Client = new Dtls13Client(r.Pair.Client) { ExternalPsk = new Dtls13ExternalPsk(Identity, Key), InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
            configureClient?.Invoke(r.Client);

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => { r.ClientError = ex; done.TrySetResult(false); };
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            if (expectSuccess)
            {
                Assert.IsTrue(done.Task.Result, "handshake failed: " + r.ClientError);
                Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerConnection?.IsHandshakeComplete == true, Timeout));
                r.Client.SendApplicationData(Encoding.UTF8.GetBytes("hello"));
                Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerReceived.Contains("hello"), Timeout));
            }
            return r;
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void ExternalPsk_WithEcdhe_AuthenticatesWithoutCertificates(bool helloRetry)
        {
            var r = Connect(s => s.ShouldSendHelloRetry = helloRetry, null);
            Assert.IsTrue(r.Client.IsExternalPsk);
            Assert.IsFalse(r.Client.IsResumed);
            Assert.IsNull(r.Client.ServerCertificate, "no Certificate in a PSK handshake");
            Assert.IsTrue(r.ServerConnection.IsExternalPsk);
            Assert.IsFalse(r.ServerConnection.IsPskOnlyKeyExchange);
            CollectionAssert.AreEqual(Identity, r.ServerConnection.ExternalPskIdentity);
        }

        [TestMethod]
        public void ExternalPsk_WithSha384()
        {
            var psk = new Dtls13ExternalPsk(Identity, Key, Dtls13CipherSuite.TLS_AES_256_GCM_SHA384);
            var r = Connect(s => { s.ExternalPskResolver = _ => psk; s.CipherSuites = new List<ushort> { 0x1302 }; },
                c => { c.ExternalPsk = psk; c.CipherSuites = new List<ushort> { 0x1302 }; });
            Assert.IsTrue(r.Client.IsExternalPsk);
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void PskOnlyKeyExchange_HasNoKeyShare(bool helloRetry)
        {
            var r = Connect(s => { s.AllowPskOnlyKeyExchange = true; s.ShouldSendHelloRetry = helloRetry; },
                c => c.PskKeyExchangeModes = new[] { PskKeyExchangeModesExtension.PskKe });
            Assert.IsTrue(r.ServerConnection.IsPskOnlyKeyExchange);
            Assert.IsTrue(r.Client.IsExternalPsk);

            // Neither hello carries a key share.
            byte[] clientHello = r.Pair.ClientSent.Last(d => d[0] == 0x16 && d[13] == 0x01);
            Assert.IsFalse(ContainsExtension(clientHello, 0x0033), "ClientHello key_share");
            byte[] serverHello = r.Pair.ServerSent.Last(d => d[0] == 0x16 && d[13] == 0x02);
            Assert.IsFalse(ContainsExtension(serverHello, 0x0033), "ServerHello key_share");
        }

        [TestMethod]
        public void PskOnlyKeyExchange_NotAllowedByTheServer_Fails()
        {
            var r = Connect(null, c => c.PskKeyExchangeModes = new[] { PskKeyExchangeModesExtension.PskKe }, expectSuccess: false);
            Assert.AreEqual(AlertDescription.HandshakeFailure, (r.ClientError as DtlsException)?.Alert, r.ClientError?.ToString());
        }

        [TestMethod]
        public void WrongKey_FailsTheBinderWithDecryptError()
        {
            byte[] wrong = (byte[])Key.Clone();
            wrong[^1] ^= 1;
            var r = Connect(null, c => c.ExternalPsk = new Dtls13ExternalPsk(Identity, wrong), expectSuccess: false);
            Assert.AreEqual(AlertDescription.DecryptError, (r.ClientError as DtlsException)?.Alert, r.ClientError?.ToString());
        }

        [TestMethod]
        public void UnknownIdentity_FallsBackToACertificateHandshake()
        {
            var r = Connect(null, c => c.ExternalPsk = new Dtls13ExternalPsk(Encoding.ASCII.GetBytes("stranger"), Key));
            Assert.IsFalse(r.Client.IsExternalPsk);
            Assert.IsNotNull(r.Client.ServerCertificate);
        }

        [TestMethod]
        public void PskOnlyServer_RejectsUnknownIdentities()
        {
            var ok = Connect(null, null, certificate: false);
            Assert.IsTrue(ok.Client.IsExternalPsk);

            var r = Connect(null, c => c.ExternalPsk = new Dtls13ExternalPsk(Encoding.ASCII.GetBytes("stranger"), Key),
                expectSuccess: false, certificate: false);
            Assert.AreEqual(AlertDescription.HandshakeFailure, (r.ClientError as DtlsException)?.Alert, r.ClientError?.ToString());
        }

        [TestMethod]
        public void TicketAndExternalPsk_TheServerPicksTheFirstItAccepts()
        {
            var keys = new SessionTicketKeys();
            var first = Connect(s => s.TicketKeys = keys, null);
            Assert.IsTrue(SpinWait.SpinUntil(() => first.Client.SessionTicket != null, Timeout));
            var ticket = first.Client.SessionTicket;

            // Both offered: the ticket (identity 0) wins with the right keys, the external PSK (identity 1) otherwise.
            var resumed = Connect(s => s.TicketKeys = keys, c => c.ResumptionTicket = ticket);
            Assert.IsTrue(resumed.Client.IsResumed);
            Assert.IsFalse(resumed.Client.IsExternalPsk);

            var external = Connect(s => s.TicketKeys = new SessionTicketKeys(), c => c.ResumptionTicket = ticket);
            Assert.IsFalse(external.Client.IsResumed);
            Assert.IsTrue(external.Client.IsExternalPsk);
        }

        [TestMethod]
        public void ClientCertificateRequired_IgnoresExternalPsks()
        {
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            var r = Connect(s => s.RequireClientCertificate = true, c => { c.ClientCertificate = cert; c.ClientCertificateKeyPair = key; });
            Assert.IsFalse(r.Client.IsExternalPsk);
            Assert.AreEqual(cert, r.ServerConnection.ClientCertificate);
        }

        // Extensions of a plaintext hello record (13-byte record header, 12-byte handshake header).
        private static bool ContainsExtension(byte[] record, ushort type)
        {
            int p = 25 + 2 + 32;
            p += 1 + record[p];                                       // session id
            if (record[13] == 0x01)
            {
                p += 1 + record[p];                                   // legacy cookie
                p += 2 + ((record[p] << 8) | record[p + 1]);          // cipher suites
                p += 1 + record[p];                                   // compression methods
            }
            else
            {
                p += 3;                                               // cipher suite, compression
            }
            int end = p + 2 + ((record[p] << 8) | record[p + 1]);
            for (p += 2; p < end; p += 4 + ((record[p + 2] << 8) | record[p + 3]))
                if (((record[p] << 8) | record[p + 1]) == type)
                    return true;
            return false;
        }
    }
}
