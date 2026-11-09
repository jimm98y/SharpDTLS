using Org.BouncyCastle.Asn1.X509;
using SharpDTLS;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>TLS 1.3 handshake features over TCP, self-tested and against OpenSSL.</summary>
    [TestClass]
    public sealed class TestTls13Features
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("TLS13"));
        private static TestPki Pki => _pki.Value;

        // s_client writes -sess_out from its new-session callback; its stdout is only flushed later, so wait for the file.
        private static Dtls13SessionTicket WaitForTicket(Tls13Client client)
        {
            Assert.IsTrue(SpinWait.SpinUntil(() => client.SessionTicket != null, Timeout), "no ticket was issued");
            return client.SessionTicket;
        }

        [TestMethod]
        public void TicketResumption_AndExternalPsk()
        {
            using var server = new Tls13Server();
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var first = TestTls13.Connect(server.LocalEndpoint);
            var ticket = WaitForTicket(first);
            first.Close();
            var second = TestTls13.Connect(server.LocalEndpoint, c => c.ResumptionTicket = ticket);
            Assert.IsTrue(second.IsResumed);
            second.Close();

            byte[] identity = Encoding.ASCII.GetBytes("tls13 psk"), key = new byte[32];
            server.ExternalPskResolver = id => id.AsSpan().SequenceEqual(identity) ? new TlsExternalPsk(identity, key) : null;
            var psk = TestTls13.Connect(server.LocalEndpoint, c => c.ExternalPsk = new TlsExternalPsk(identity, key));
            Assert.IsTrue(psk.IsExternalPsk);
        }

        [TestMethod]
        public void KeyUpdate_BothWays()
        {
            using var server = new Tls13Server();
            var received = new System.Collections.Concurrent.ConcurrentQueue<string>();
            Tls13ServerConnection connection = null;
            server.ApplicationDataReceived += (_, e) => { connection = e.Connection; received.Enqueue(Encoding.UTF8.GetString(e.Data)); };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var client = TestTls13.Connect(server.LocalEndpoint);
            var clientReceived = new System.Collections.Concurrent.ConcurrentQueue<string>();
            client.ApplicationDataReceived += (_, d) => clientReceived.Enqueue(Encoding.UTF8.GetString(d));

            client.SendApplicationData(Encoding.UTF8.GetBytes("before"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("before"), Timeout));
            client.SendKeyUpdate(requestUpdate: true); // the server answers with its own KeyUpdate
            client.SendApplicationData(Encoding.UTF8.GetBytes("after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("after"), Timeout));
            connection.SendApplicationData(Encoding.UTF8.GetBytes("server after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => clientReceived.Contains("server after"), Timeout));
            connection.SendKeyUpdate();
            connection.SendApplicationData(Encoding.UTF8.GetBytes("server after second update"));
            Assert.IsTrue(SpinWait.SpinUntil(() => clientReceived.Contains("server after second update"), Timeout));
        }

        // RFC 9846 §4.7.3: until the peer's KeyUpdate arrives, a second KeyUpdate must not ask for another.
        [TestMethod]
        public void KeyUpdate_DoesNotRequestAgainBeforeThePeersUpdate()
        {
            using var server = new Tls13Server();
            var requests = new System.Collections.Concurrent.ConcurrentQueue<byte>();
            var received = new System.Collections.Concurrent.ConcurrentQueue<string>();
            server.KeyUpdateReceived += (_, k) => requests.Enqueue(k.UpdateRequest);
            server.ApplicationDataReceived += (_, e) => received.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var client = TestTls13.Connect(server.LocalEndpoint);

            // Holding the connection's lock keeps the server's answer from being processed between the two.
            object sync = typeof(TlsConnectionBase).GetField("_sync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetValue(client);
            lock (sync)
            {
                client.SendKeyUpdate(requestUpdate: true);
                client.SendKeyUpdate(requestUpdate: true);
            }
            client.SendApplicationData(Encoding.UTF8.GetBytes("after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("after"), Timeout));
            CollectionAssert.AreEqual(new byte[] { 1, 0 }, requests.ToArray());

            // Once the server's KeyUpdate has arrived, the client may ask again.
            Assert.IsTrue(SpinWait.SpinUntil(() => client.Session.ReadKeys.Last().Epoch == 4, Timeout), "the server's KeyUpdate did not arrive");
            client.SendKeyUpdate(requestUpdate: true);
            client.SendApplicationData(Encoding.UTF8.GetBytes("again"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("again"), Timeout));
            CollectionAssert.AreEqual(new byte[] { 1, 0, 1 }, requests.ToArray());
        }

        [TestMethod]
        public void ClientAuthentication_InHandshakeAndPostHandshake()
        {
            var (key, cert) = Pki.Leaf(commonName: "tls13 client", usage: KeyPurposeID.id_kp_clientAuth);
            using var server = new Tls13Server { RequireClientCertificate = true, ClientCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForClient() };
            var established = new TaskCompletionSource<Tls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, c) => established.TrySetResult(c);
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            TestTls13.Connect(server.LocalEndpoint, c => { (c.ClientCertificateKeyPair, c.ClientCertificate) = (key, cert); c.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert }; });
            Assert.IsTrue(established.Task.Wait(Timeout));
            Assert.AreEqual(cert, established.Task.Result.ClientCertificate);

            server.RequireClientCertificate = false;
            var later = new TaskCompletionSource<Tls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, c) => later.TrySetResult(c);
            TestTls13.Connect(server.LocalEndpoint, c =>
            {
                (c.ClientCertificateKeyPair, c.ClientCertificate) = (key, cert);
                c.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
                c.AllowPostHandshakeAuthentication = true;
            });
            Assert.IsTrue(SpinWait.SpinUntil(() => later.Task.IsCompleted && later.Task.Result != established.Task.Result, Timeout));
            var connection = later.Task.Result;
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.PostHandshakeAuthenticationCompleted += (_, _) => done.TrySetResult(true);
            connection.RequestClientCertificate();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.AreEqual(cert, connection.ClientCertificate);
        }

        // ── OpenSSL ──────────────────────────────────────────────────────────────────────────

        private static (string Cert, string Key, string Chain, string Root, string Dir) Files()
        {
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Pki.Leaf(new[] { "server.test" });
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string intermediate = OpenSsl.WritePem(dir, "int.pem", Pki.Intermediate.Cert);
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            string chain = Path.Combine(dir, "chain.pem");
            File.WriteAllText(chain, File.ReadAllText(intermediate) + File.ReadAllText(root));
            return (certPath, OpenSsl.WritePem(dir, "key.pem", key.Private), chain, root, dir);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslServer_TicketsClientKeyUpdateAlpnAndHelloRetry()
        {
            OpenSsl.RequireOpenSsl();
            var f = Files();
            // P-384 only: our x25519 share needs a HelloRetryRequest.
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -tls1_3 -accept 127.0.0.1:{p} -cert {f.Cert} -key {f.Key} -cert_chain {Path.Combine(f.Dir, "int.pem")} -groups P-384 -alpn h2", f.Dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
            var endpoint = new IPEndPoint(IPAddress.Loopback, port);

            var client = TestTls13.Connect(endpoint, c =>
            {
                c.SupportedGroups = new[] { Dtls13Groups.X25519, Dtls13Groups.Secp384r1 };
                c.ApplicationProtocols = new[] { "h2" };
                c.ServerName = "server.test";
                c.ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer("server.test");
            });
            Assert.AreEqual(Dtls13Groups.Secp384r1, client.NegotiatedGroup);
            Assert.AreEqual("h2", client.ApplicationProtocol);
            client.SendKeyUpdate(requestUpdate: true);
            client.SendApplicationData(Encoding.UTF8.GetBytes("after client key update\n"));
            Assert.IsTrue(server.WaitForOutput("after client key update", Timeout), server.Output);

            var ticket = WaitForTicket(client);
            client.Close();
            var resumed = TestTls13.Connect(endpoint, c =>
            {
                c.SupportedGroups = new[] { Dtls13Groups.X25519, Dtls13Groups.Secp384r1 };
                c.ApplicationProtocols = new[] { "h2" };
                c.ServerName = "server.test";
                c.ResumptionTicket = ticket;
            });
            Assert.IsTrue(resumed.IsResumed, server.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_ResumesAndUpdatesKeys()
        {
            OpenSsl.RequireOpenSsl();
            var f = Files();
            var (key, cert) = Pki.Leaf(new[] { "server.test" });
            using var server = new Tls13Server(key, cert) { IntermediateCertificates = new[] { Pki.Intermediate.Cert }, ApplicationProtocols = new[] { "h2" } };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            string session = Path.Combine(f.Dir, "session.pem");
            using (var first = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_out {session} -alpn h2 -servername server.test -CAfile {f.Chain} -verify_return_error", f.Dir))
            {
                Assert.IsTrue(first.WaitForOutput("ALPN protocol: h2", Timeout), first.Output);
                Assert.IsTrue(first.WaitForOutput("Verify return code: 0 (ok)", Timeout), first.Output);
                Assert.IsTrue(SpinWait.SpinUntil(() => File.Exists(session) && new FileInfo(session).Length > 0, Timeout), first.Output);
            }
            // The ticket is bound to the server name of the first handshake (RFC 6066 §3).
            using var second = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_in {session} -alpn h2 -servername server.test", f.Dir);
            Assert.IsTrue(second.WaitForOutput("Reused, TLSv1.3", Timeout), second.Output);

            // s_client's "keyup:req" sends a KeyUpdate asking for ours; data keeps flowing both ways under the new keys.
            var received = new System.Collections.Concurrent.ConcurrentQueue<(Tls13ServerConnection, string)>();
            server.ApplicationDataReceived += (_, e) => received.Enqueue((e.Connection, Encoding.UTF8.GetString(e.Data)));
            second.WriteLine("keyup:req");
            Assert.IsTrue(second.WaitForOutput("KEYUPDATE", Timeout), second.Output);
            second.WriteLine("after key update");
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Any(r => r.Item2.Contains("after key update")), Timeout), second.Output);
            received.First(r => r.Item2.Contains("after key update")).Item1.SendApplicationData(Encoding.UTF8.GetBytes("server after key update\n"));
            Assert.IsTrue(second.WaitForOutput("server after key update", Timeout), second.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_ClientCertificate_AndRejectedEarlyData()
        {
            OpenSsl.RequireOpenSsl();
            var f = Files();
            var (clientKey, clientCert) = Pki.Leaf(commonName: "openssl client", usage: KeyPurposeID.id_kp_clientAuth);
            string clientCertPath = OpenSsl.WritePem(f.Dir, "client.pem", clientCert);
            string clientKeyPath = OpenSsl.WritePem(f.Dir, "client-key.pem", clientKey.Private);
            using var server = new Tls13Server { RequireClientCertificate = true, ClientCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForClient() };
            var established = new TaskCompletionSource<Tls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, c) => established.TrySetResult(c);
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            using (var client = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -cert {clientCertPath} -key {clientKeyPath} -cert_chain {Path.Combine(f.Dir, "int.pem")}", f.Dir))
            {
                Assert.IsTrue(established.Task.Wait(Timeout), client.Output);
                Assert.AreEqual(clientCert, established.Task.Result.ClientCertificate);
            }

            // OpenSSL resuming with 0-RTT data: we decline early data and must skip its records.
            server.RequireClientCertificate = false;
            var received = new System.Collections.Concurrent.ConcurrentQueue<string>();
            server.ApplicationDataReceived += (_, e) => received.Enqueue(Encoding.UTF8.GetString(e.Data));
            string session = Path.Combine(f.Dir, "session.pem");
            string early = Path.Combine(f.Dir, "early.txt");
            File.WriteAllText(early, "early data\n");
            using (var first = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_out {session}", f.Dir))
                Assert.IsTrue(SpinWait.SpinUntil(() => File.Exists(session) && new FileInfo(session).Length > 0, Timeout), first.Output);
            using var second = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_in {session} -early_data {early}", f.Dir);
            Assert.IsTrue(second.WaitForOutput("Reused, TLSv1.3", Timeout), second.Output);
            second.WriteLine("after the handshake");
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Any(r => r.Contains("after the handshake")), Timeout), second.Output);
            Assert.IsFalse(received.Any(r => r.Contains("early data")), "declined early data must not be delivered");
        }
    }
}
