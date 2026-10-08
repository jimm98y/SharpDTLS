using SharpDTLS;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.3 key exchange groups: ECDHE, X25519/X448, FFDHE, ML-KEM and the ECDHE + ML-KEM hybrids.</summary>
    [TestClass]
    public sealed class TestDtls13Groups
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        public static IEnumerable<object[]> AllGroups => Dtls13Groups.All.Select(g => new object[] { g, Dtls13Groups.Name(g) });

        private static (Dtls13Client Client, Dtls13Server Server, ScriptedTransportPair Pair) Connect(
            IList<ushort> clientShares, IList<ushort> clientSupported, IList<ushort> serverSupported, bool helloRetry = false)
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls13Server(pair.Server) { SupportedGroups = serverSupported, ShouldSendHelloRetry = helloRetry };
            var received = new List<string>();
            server.ApplicationDataReceived += (_, e) => { lock (received) received.Add(Encoding.UTF8.GetString(e.Data)); };
            var client = new Dtls13Client(pair.Client) { KeyShareGroups = clientShares, SupportedGroups = clientSupported };
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            client.SendApplicationData(Encoding.UTF8.GetBytes("data"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("data"), Timeout));
            return (client, server, pair);
        }

        private static int HelloRetryRequests(ScriptedTransportPair pair)
            => pair.ServerSent.Count(d => d[0] == 0x16 && d.Length > 59 && d[13] == 0x02
                                         && d.AsSpan(27, 32).SequenceEqual(SharpDTLS.DTLS13.Messages.HelloRetryRequest.HelloRetryRequestRandom));

        [DynamicData(nameof(AllGroups))]
        [TestMethod]
        public void EachGroup_Handshakes(ushort group, string name)
        {
            var (client, server, _) = Connect(new[] { group }, new[] { group }, new[] { group });
            Assert.AreEqual(group, client.NegotiatedGroup, name);
            Assert.AreEqual(group, server.Connections.Single().NegotiatedGroup, name);
        }

        [DataRow(Dtls13Groups.X25519MlKem768)]
        [DataRow(Dtls13Groups.SecP384r1MlKem1024)]
        [TestMethod]
        public void LargeHybridShares_SurviveTheCookieExchangeAndFragmentation(ushort group)
        {
            // A ClientHello with ~1.2-1.7 KB of key share is fragmented, and sent twice around the cookie exchange.
            var (client, _, pair) = Connect(new[] { group }, new[] { group }, new[] { group }, helloRetry: true);
            Assert.AreEqual(group, client.NegotiatedGroup);
            Assert.IsGreaterThan(2, pair.ClientSent.Count(d => d[0] == 0x16 && d[13] == 0x01), "the ClientHello needed several records");
        }

        [TestMethod]
        public void ServerPrefersAnExistingShare_OverAHelloRetryRequest()
        {
            // The server's favourite is the hybrid, but the client only sent x25519: no HelloRetryRequest.
            var (client, _, pair) = Connect(new[] { Dtls13Groups.X25519 }, Dtls13Groups.DefaultPreference.ToList(), Dtls13Groups.DefaultPreference.ToList());
            Assert.AreEqual(Dtls13Groups.X25519, client.NegotiatedGroup);
            Assert.AreEqual(0, HelloRetryRequests(pair));
        }

        [TestMethod]
        public void HelloRetryRequest_AsksForAGroupWithoutAShare()
        {
            var (client, _, pair) = Connect(new[] { Dtls13Groups.X25519 }, new[] { Dtls13Groups.X25519, Dtls13Groups.Secp384r1 }, new[] { Dtls13Groups.Secp384r1 });
            Assert.AreEqual(Dtls13Groups.Secp384r1, client.NegotiatedGroup);
            Assert.AreEqual(1, HelloRetryRequests(pair));
        }

        [TestMethod]
        public void NoCommonGroup_IsAHandshakeFailure()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls13Server(pair.Server) { SupportedGroups = new[] { Dtls13Groups.Secp521r1 } };
            var client = new Dtls13Client(pair.Client) { KeyShareGroups = new[] { Dtls13Groups.X25519 }, SupportedGroups = new[] { Dtls13Groups.X25519 } };
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.Failed += (_, ex) => failed.TrySetResult(ex);
            client.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(20);
            client.BeginHandshake();
            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.HandshakeFailure, (failed.Task.Result as DtlsException)?.Alert, failed.Task.Result.ToString());
        }

        [DataRow(Dtls13Groups.X25519, 31)]
        [DataRow(Dtls13Groups.Secp256r1, 64)]
        [DataRow(Dtls13Groups.Ffdhe2048, 255)]
        [DataRow(Dtls13Groups.MlKem768, 1183)]
        [DataRow(Dtls13Groups.X25519MlKem768, 1215)]
        [TestMethod]
        public void MalformedShares_AreIllegalParameter(ushort group, int length)
            => Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => Dtls13Groups.Respond(group, new byte[length])).Alert);

        [TestMethod]
        public void SmallOrderX25519Share_IsRejected()
            => Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => Dtls13Groups.Respond(Dtls13Groups.X25519, new byte[32])).Alert);

        [TestMethod]
        public void FfdheShareOutOfRange_IsRejected()
        {
            byte[] one = new byte[256];
            one[^1] = 1;
            Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => Dtls13Groups.Respond(Dtls13Groups.Ffdhe2048, one)).Alert);
        }

        // ── wolfSSL ──────────────────────────────────────────────────────────────────────────

        // The stock wolfSSL build has no standalone ML-KEM groups (--enable-tls-mlkem-standalone), only the hybrids.
        public static IEnumerable<object[]> WolfSslGroups => new ushort[]
        {
            Dtls13Groups.X25519, Dtls13Groups.Secp256r1, Dtls13Groups.Secp384r1, Dtls13Groups.Secp521r1, Dtls13Groups.X448,
            Dtls13Groups.Ffdhe2048, Dtls13Groups.Ffdhe3072,
            Dtls13Groups.X25519MlKem768, Dtls13Groups.SecP256r1MlKem768, Dtls13Groups.SecP384r1MlKem1024,
        }.Select(g => new object[] { g, Dtls13Groups.Name(g) });

        [DynamicData(nameof(WolfSslGroups))]
        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSslClient_To_SharpDtlsServer(ushort group, string name)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            // wolfSSL also sends its default share; only accepting the group under test makes the choice deterministic.
            var server = new Dtls13Server(transport) { SupportedGroups = new[] { group } };
            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -group {group}", dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), name + ":\n" + client.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            Assert.AreEqual(group, server.Connections.Single().NegotiatedGroup, name);
        }

        [DynamicData(nameof(WolfSslGroups))]
        [TestCategory("Interop")]
        [TestMethod]
        public void SharpDtlsClient_To_WolfSslServer(ushort group, string name)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -group {group}", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            // Only an x25519 share: the server asks for its group with a HelloRetryRequest (unless it is x25519). wolfSSL
            // needs this for the hybrids: it only accepts a fragmented ClientHello once it carries a cookie.
            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(clientTransport) { SupportedGroups = new[] { Dtls13Groups.X25519, group }.Distinct().ToList() };
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), name + ":\n" + server.Output);
            Assert.AreEqual(group, client.NegotiatedGroup, name);
            client.SendApplicationData(Encoding.UTF8.GetBytes("hello\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:hello", Timeout), server.Output);
        }
    }
}
