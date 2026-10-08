using SharpDTLS;
using SharpDTLS.DTLS12;
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
    /// <summary>Application-Layer Protocol Negotiation (RFC 7301) in both engines.</summary>
    [TestClass]
    public sealed class TestAlpn
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static (Exception Error, string Client, string Server) Run12(string[] client, string[] server)
        {
            var pair = new ScriptedTransportPair();
            var dtlsServer = new Dtls12Server(pair.Server) { ApplicationProtocols = server };
            var dtlsClient = new Dtls12Client(pair.Client) { ApplicationProtocols = client };
            var error = Wait(dtlsClient.BeginHandshake, s => dtlsClient.HandshakeFinished += (_, _) => s(), f => dtlsClient.Failed += (_, ex) => f(ex));
            return (error, dtlsClient.ApplicationProtocol, dtlsServer.Connections.SingleOrDefault()?.ApplicationProtocol);
        }

        private static (Exception Error, string Client, string Server) Run13(string[] client, string[] server)
        {
            var pair = new ScriptedTransportPair();
            var dtlsServer = new Dtls13Server(pair.Server) { ApplicationProtocols = server };
            var dtlsClient = new Dtls13Client(pair.Client) { ApplicationProtocols = client };
            var error = Wait(dtlsClient.BeginHandshake, s => dtlsClient.HandshakeFinished += (_, _) => s(), f => dtlsClient.Failed += (_, ex) => f(ex));
            return (error, dtlsClient.ApplicationProtocol, dtlsServer.Connections.SingleOrDefault()?.ApplicationProtocol);
        }

        private static Exception Wait(Action begin, Action<Action> onSuccess, Action<Action<Exception>> onFailure)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onSuccess(() => done.TrySetResult(null));
            onFailure(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        private static (Exception, string, string) Run(int version, string[] client, string[] server)
            => version == 12 ? Run12(client, server) : Run13(client, server);

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ServerPreferenceWins(int version)
        {
            var (error, client, server) = Run(version, new[] { "h2", "coap" }, new[] { "coap", "h2" });
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual("coap", client);
            Assert.AreEqual("coap", server);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void NoCommonProtocol_IsFatal(int version)
        {
            var (error, _, _) = Run(version, new[] { "h2" }, new[] { "coap" });
            Assert.AreEqual(AlertDescription.NoApplicationProtocol, (error as DtlsException)?.Alert, error?.ToString());
        }

        [DataRow(12, true)]
        [DataRow(12, false)]
        [DataRow(13, true)]
        [DataRow(13, false)]
        [TestMethod]
        public void EitherSideWithoutAlpn_NegotiatesNone(int version, bool clientOffers)
        {
            var (error, client, server) = Run(version, clientOffers ? new[] { "coap" } : null, clientOffers ? null : new[] { "coap" });
            Assert.IsNull(error, error?.ToString());
            Assert.IsNull(client);
            Assert.IsNull(server);
        }

        [TestMethod]
        public void EarlyData_RequiresTheTicketsProtocol()
        {
            var keys = new SessionTicketKeys();
            (Dtls13Client Client, List<string> Early) Connect(string[] protocols, Dtls13SessionTicket ticket)
            {
                var pair = new ScriptedTransportPair();
                var early = new List<string>();
                var server = new Dtls13Server(pair.Server)
                {
                    TicketKeys = keys, MaxEarlyDataSize = 100, ShouldSendHelloRetry = false, ApplicationProtocols = new[] { "coap", "h2" },
                };
                server.EarlyDataReceived += (_, e) => { lock (early) early.Add(Encoding.UTF8.GetString(e.Data)); };
                var client = new Dtls13Client(pair.Client) { ApplicationProtocols = protocols, ResumptionTicket = ticket, EarlyData = ticket == null ? null : Encoding.UTF8.GetBytes("early") };
                Assert.IsNull(Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex)));
                return (client, early);
            }

            var first = Connect(new[] { "coap" }, null).Client;
            Assert.IsTrue(SpinWait.SpinUntil(() => first.SessionTicket != null, Timeout));
            Assert.AreEqual("coap", first.SessionTicket.ApplicationProtocol);

            var same = Connect(new[] { "coap" }, first.SessionTicket);
            Assert.IsTrue(same.Client.EarlyDataAccepted);
            CollectionAssert.AreEqual(new[] { "early" }, same.Early);

            // Not offering the ticket's protocol: still resumes, but without 0-RTT.
            var other = Connect(new[] { "h2" }, first.SessionTicket);
            Assert.IsTrue(other.Client.IsResumed);
            Assert.IsFalse(other.Client.EarlyDataAccepted);
            Assert.IsEmpty(other.Early);
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSsl_BothDirections()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Rsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            // OpenSSL server, our client
            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -alpn coap,h2", dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport) { ApplicationProtocols = new[] { "h2", "coap" } };
                Assert.IsNull(Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex)));
                Assert.AreEqual("coap", client.ApplicationProtocol, server.Output);
            }

            // OpenSSL client, our server
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls12Server(serverTransport) { ApplicationProtocols = new[] { "coap" } };
            using var openSslClient = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -alpn h2,coap", dir);
            Assert.IsTrue(openSslClient.WaitForOutput("ALPN protocol: coap", Timeout), openSslClient.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSsl_BothDirections()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            using (var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -alpn coap", dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls13Client(transport) { ApplicationProtocols = new[] { "h2", "coap" } };
                Assert.IsNull(Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex)));
                Assert.AreEqual("coap", client.ApplicationProtocol, server.Output);
                Assert.IsTrue(server.WaitForOutput("ALPN:coap", Timeout), server.Output);
            }

            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls13Server(serverTransport) { ApplicationProtocols = new[] { "coap", "h2" } };
            using var wolfClient = new OpenSslProcess($"client {serverTransport.LocalEndpoint.Port} -alpn h2,coap", dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("ALPN:coap", Timeout), wolfClient.Output);
        }
    }
}
