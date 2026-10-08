using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>server_name (RFC 6066 §3): certificate selection by host name, and sessions bound to one name.</summary>
    [TestClass]
    public sealed class TestServerName
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("SNI"));
        private static TestPki Pki => _pki.Value;
        private static readonly Lazy<ServerCredentials> _a = new(() => Credentials("a.test"));
        private static readonly Lazy<ServerCredentials> _b = new(() => Credentials("b.test"));
        private static readonly Lazy<ServerCredentials> _default = new(() => Credentials("default.test"));

        private static ServerCredentials Credentials(string name)
        {
            var leaf = Pki.Leaf(new[] { name });
            return new ServerCredentials(leaf.Key, leaf.Cert, new[] { Pki.Intermediate.Cert });
        }

        private static ServerCredentials Select(string name) => name switch { "a.test" => _a.Value, "b.test" => _b.Value, _ => null };

        private static Exception Wait(Action begin, Action<Action> onSuccess, Action<Action<Exception>> onFailure)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onSuccess(() => done.TrySetResult(null));
            onFailure(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        private static (Dtls12Client Client, Dtls12Server Server, List<string> Asked) Connect12(string serverName, string expectedCertificateName,
            Dtls12SessionState resume = null, SessionTicketKeys keys = null)
        {
            var pair = new ScriptedTransportPair();
            var asked = new List<string>();
            var server = new Dtls12Server(pair.Server, _default.Value.KeyPair, _default.Value.Certificate)
            {
                IntermediateCertificates = _default.Value.IntermediateCertificates,
                CertificateSelector = name => { lock (asked) asked.Add(name); return Select(name); },
                TicketKeys = keys,
            };
            var client = new Dtls12Client(pair.Client)
            {
                ServerName = serverName,
                ResumptionSession = resume,
                ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer(expectedCertificateName),
            };
            var error = Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex));
            Assert.IsNull(error, error?.ToString());
            return (client, server, asked);
        }

        private static (Dtls13Client Client, Dtls13Server Server) Connect13(string serverName, string expectedCertificateName,
            Dtls13SessionTicket resume = null, SessionTicketKeys keys = null)
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls13Server(pair.Server, _default.Value.KeyPair, _default.Value.Certificate)
            {
                IntermediateCertificates = _default.Value.IntermediateCertificates,
                CertificateSelector = Select,
                TicketKeys = keys,
                InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50),
            };
            var client = new Dtls13Client(pair.Client)
            {
                ServerName = serverName,
                ResumptionTicket = resume,
                ServerCertificateValidator = expectedCertificateName == null ? null : new CertificateValidator(new[] { Pki.Root.Cert }).ForServer(expectedCertificateName),
            };
            var error = Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex));
            Assert.IsNull(error, error?.ToString());
            Assert.IsTrue(SpinWait.SpinUntil(() => server.GetConnection(ScriptedTransportPair.ClientEndpoint)?.IsHandshakeComplete == true, Timeout));
            return (client, server);
        }

        [DataRow("a.test", "a.test")]
        [DataRow("b.test", "b.test")]
        [DataRow("unknown.test", "default.test")]
        [DataRow(null, "default.test")]
        [TestMethod]
        public void Dtls12_SelectsTheCertificateByName(string serverName, string expected)
        {
            var (_, server, asked) = Connect12(serverName, expected);
            CollectionAssert.AreEqual(new[] { serverName }, asked);
            Assert.AreEqual(serverName, server.Connections.Single().ServerName);
        }

        [DataRow("a.test", "a.test")]
        [DataRow("unknown.test", "default.test")]
        [DataRow(null, "default.test")]
        [TestMethod]
        public void Dtls13_SelectsTheCertificateByName(string serverName, string expected)
        {
            var (_, server) = Connect13(serverName, expected);
            Assert.AreEqual(serverName, server.Connections.Single().ServerName);
        }

        [TestMethod]
        public void Dtls12_SessionsAreBoundToTheServerName()
        {
            var keys = new SessionTicketKeys();
            var session = Connect12("a.test", "a.test", keys: keys).Client.SessionState;
            Assert.AreEqual("a.test", session.ServerName);
            Assert.IsTrue(Connect12("a.test", "a.test", session, keys).Client.IsResumed);
            Assert.IsFalse(Connect12("b.test", "b.test", session, keys).Client.IsResumed);
        }

        [TestMethod]
        public void Dtls13_TicketsAreBoundToTheServerName()
        {
            var keys = new SessionTicketKeys();
            var first = Connect13("a.test", "a.test", keys: keys).Client;
            Assert.IsTrue(SpinWait.SpinUntil(() => first.SessionTicket != null, Timeout));
            var ticket = first.SessionTicket;
            Assert.AreEqual("a.test", ticket.ServerName);
            Assert.IsTrue(Connect13("a.test", null, ticket, keys).Client.IsResumed);
            Assert.IsFalse(Connect13("b.test", "b.test", ticket, keys).Client.IsResumed);
        }

        [DataRow("192.0.2.1")]
        [DataRow("::1")]
        [DataRow("trailing.dot.")]
        [DataRow("")]
        [DataRow("bad name")]
        [TestMethod]
        public void InvalidHostNames_AreNotSent(string name)
            => Assert.ThrowsExactly<ArgumentException>(() => new ServerNameExtension(name));

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslServer_PicksItsSecondCertificateByName()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            // s_server has no chain option for -cert2, so both certificates are issued directly by the root.
            var defaultLeaf = Pki.Leaf(new[] { "default.test" }, fromRoot: true);
            var bLeaf = Pki.Leaf(new[] { "b.test" }, fromRoot: true);
            string defaultCert = OpenSsl.WritePem(dir, "default.pem", defaultLeaf.Cert);
            string defaultKey = OpenSsl.WritePem(dir, "default.key", defaultLeaf.Key.Private);
            string bCert = OpenSsl.WritePem(dir, "b.pem", bLeaf.Cert);
            string bKey = OpenSsl.WritePem(dir, "b.key", bLeaf.Key.Private);
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {defaultCert} -key {defaultKey} -servername b.test -cert2 {bCert} -key2 {bKey}",
                dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            // The default certificate would fail the host name check, so success shows the name selected cert2.
            var client = new Dtls12Client(transport)
            {
                ServerName = "b.test",
                ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer("b.test"),
            };
            var error = Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex));
            Assert.IsNull(error, error + "\n" + server.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_ServerNameReachesTheSelector()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport, _default.Value.KeyPair, _default.Value.Certificate)
            {
                IntermediateCertificates = _default.Value.IntermediateCertificates,
                CertificateSelector = Select,
            };
            using var client = new OpenSslProcess(
                $"s_client -dtls1_2 -connect 127.0.0.1:{transport.LocalEndpoint.Port} -servername a.test -CAfile {root} -verify_return_error -verify_hostname a.test", dir);
            Assert.IsTrue(client.WaitForOutput("Verify return code: 0 (ok)", Timeout), client.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.ServerName == "a.test"), Timeout));
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSslClient_ServerNameReachesTheSelector()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport, _default.Value.KeyPair, _default.Value.Certificate)
            {
                IntermediateCertificates = _default.Value.IntermediateCertificates,
                CertificateSelector = Select,
            };
            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -sni b.test -verify {root} -host b.test", dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), client.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.ServerName == "b.test"), Timeout));
        }
    }
}
