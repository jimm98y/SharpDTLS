using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>TLS 1.3 against wolfSSL (over TCP with the harness's -tls) and BouncyCastle, in both directions.</summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestTls13Interop
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static readonly Dictionary<ushort, string> WolfSuites = new()
        {
            [0x1301] = "TLS13-AES128-GCM-SHA256", [0x1302] = "TLS13-AES256-GCM-SHA384", [0x1303] = "TLS13-CHACHA20-POLY1305-SHA256",
            [0x1304] = "TLS13-AES128-CCM-SHA256", [0x1305] = "TLS13-AES128-CCM-8-SHA256",
        };

        public static IEnumerable<object[]> Suites => WolfSuites.Keys.Select(id => new object[] { id });

        public static IEnumerable<object[]> Groups => new ushort[]
        {
            Dtls13Groups.X25519, Dtls13Groups.Secp256r1, Dtls13Groups.Secp384r1, Dtls13Groups.X448, Dtls13Groups.Ffdhe2048,
            Dtls13Groups.X25519MlKem768, Dtls13Groups.SecP256r1MlKem768, Dtls13Groups.SecP384r1MlKem1024,
        }.Select(g => new object[] { g, Dtls13Groups.Name(g) });

        private static (string Cert, string Key, string Dir) EcFiles()
        {
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            return (OpenSsl.WritePem(dir, "cert.pem", cert), OpenSsl.WritePem(dir, "key.pem", key.Private), dir);
        }

        private static Tls13Server EchoServer(Action<Tls13Server> configure = null)
        {
            var server = new Tls13Server();
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        // ── wolfSSL ──────────────────────────────────────────────────────────────────────────

        [DynamicData(nameof(Suites))]
        [TestMethod]
        public void WolfSsl_Suites_BothDirections(ushort suite)
        {
            WolfSsl.RequireWolfSsl();
            var f = EcFiles();
            using (var server = OpenSslProcess.StartServer(p => $"server {p} {f.Cert} {f.Key} -tls -cipher {WolfSuites[suite]}", f.Dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                var client = TestTls13.Connect(new IPEndPoint(IPAddress.Loopback, port), c => c.CipherSuites = new List<ushort> { suite });
                Assert.AreEqual(suite, client.Session.CipherSuite.Id);
                client.SendApplicationData(Encoding.UTF8.GetBytes("to wolfssl\n"));
                Assert.IsTrue(server.WaitForOutput("RECV:to wolfssl", Timeout), server.Output);
            }

            using var ours = EchoServer(s => s.CipherSuites = new List<ushort> { suite });
            using var wolfClient = new OpenSslProcess($"client {ours.LocalEndpoint.Port} -tls -cipher {WolfSuites[suite]}", f.Dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CONNECTED", Timeout), wolfClient.Output);
            wolfClient.WriteLine("ping");
            Assert.IsTrue(wolfClient.WaitForOutput("RECV:pong:ping", Timeout), wolfClient.Output);
        }

        [DynamicData(nameof(Groups))]
        [TestMethod]
        public void WolfSsl_Groups_BothDirections(ushort group, string name)
        {
            WolfSsl.RequireWolfSsl();
            var f = EcFiles();
            // wolfSSL server accepting only the group; our client shares the defaults, so others need a HelloRetryRequest.
            using (var server = OpenSslProcess.StartServer(p => $"server {p} {f.Cert} {f.Key} -tls -group {group}", f.Dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                Tls13Client client;
                try { client = TestTls13.Connect(new IPEndPoint(IPAddress.Loopback, port), c => c.SupportedGroups = new[] { Dtls13Groups.X25519MlKem768, Dtls13Groups.X25519, group }.Distinct().ToList()); }
                catch (Exception) { Thread.Sleep(300); throw new Exception("WOLF:" + server.Output); }
                Assert.AreEqual(group, client.NegotiatedGroup, name);
            }

            using var ours = EchoServer(s => s.SupportedGroups = new[] { group });
            using var wolfClient = new OpenSslProcess($"client {ours.LocalEndpoint.Port} -tls -group {group}", f.Dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CONNECTED", Timeout), name + ":\n" + wolfClient.Output);
            Assert.AreEqual(group, ours.Connections.Single().NegotiatedGroup, name);
        }

        [TestMethod]
        public void WolfSsl_Resumption_BothDirections()
        {
            WolfSsl.RequireWolfSsl();
            var f = EcFiles();
            using var ours = EchoServer();
            using (var wolfClient = new OpenSslProcess($"client {ours.LocalEndpoint.Port} -tls -resume", f.Dir, WolfSsl.Harness))
            {
                Assert.IsTrue(wolfClient.WaitForOutput("RESUMED", Timeout), wolfClient.Output);
                Assert.DoesNotContain("NOT RESUMED", wolfClient.Output, wolfClient.Output);
            }

            using var server = OpenSslProcess.StartServer(p => $"server {p} {f.Cert} {f.Key} -tls -resume", f.Dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
            var endpoint = new IPEndPoint(IPAddress.Loopback, port);
            var first = TestTls13.Connect(endpoint);
            Assert.IsTrue(SpinWait.SpinUntil(() => first.SessionTicket != null, Timeout), server.Output);
            first.Close();
            var second = TestTls13.Connect(endpoint, c => c.ResumptionTicket = first.SessionTicket);
            Assert.IsTrue(second.IsResumed, server.Output);
        }

        [TestMethod]
        public void WolfSsl_KeyUpdateAndPostHandshakeAuth()
        {
            WolfSsl.RequireWolfSsl();
            var f = EcFiles();
            var (clientKey, clientCert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string clientCertPath = OpenSsl.WritePem(f.Dir, "client.pem", clientCert);
            string clientKeyPath = OpenSsl.WritePem(f.Dir, "client-key.pem", clientKey.Private);

            using var ours = EchoServer();
            using var wolfClient = new OpenSslProcess($"client {ours.LocalEndpoint.Port} -tls -pha -cert {clientCertPath} -key {clientKeyPath}", f.Dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CONNECTED", Timeout), wolfClient.Output);
            wolfClient.WriteLine("KEYUPDATE");
            Assert.IsTrue(wolfClient.WaitForOutput("KEYUPDATE SENT", Timeout), wolfClient.Output);
            wolfClient.WriteLine("after update");
            Assert.IsTrue(wolfClient.WaitForOutput("RECV:pong:after update", Timeout), wolfClient.Output);

            var connection = ours.Connections.Single();
            connection.SendKeyUpdate(requestUpdate: true);
            wolfClient.WriteLine("after our update");
            Assert.IsTrue(wolfClient.WaitForOutput("RECV:pong:after our update", Timeout), wolfClient.Output);

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.PostHandshakeAuthenticationCompleted += (_, _) => done.TrySetResult(true);
            connection.RequestClientCertificate();
            Assert.IsTrue(done.Task.Wait(Timeout), wolfClient.Output);
            Assert.AreEqual(clientCert, connection.ClientCertificate);
        }

        // ── BouncyCastle ─────────────────────────────────────────────────────────────────────

        private static Task<T> RunBlocking<T>(Func<T> work)
            => Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        [DynamicData(nameof(Suites))]
        [TestMethod]
        public void BouncyCastle_Suites_BothDirections(ushort suite)
        {
            var crypto = new BcTlsCrypto(new SecureRandom());
            if (!TlsUtilities.IsSupportedCipherSuite(crypto, suite))
                Assert.Inconclusive($"BouncyCastle does not support 0x{suite:X4}");
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();

            // BouncyCastle server, our client.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var bcServer = RunBlocking(() =>
            {
                using var tcp = listener.AcceptTcpClient();
                var protocol = new TlsServerProtocol(tcp.GetStream());
                protocol.Accept(new BcTestServer(crypto, suite, ProtocolVersion.TLSv13, key.Private, cert.GetEncoded()));
                byte[] buffer = new byte[256];
                int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                byte[] reply = Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(buffer, 0, n));
                protocol.Stream.Write(reply, 0, reply.Length);
                protocol.Stream.Flush();
                Thread.Sleep(100);
                return true;
            });
            try
            {
                Tls13Client client;
                try { client = TestTls13.Connect((IPEndPoint)listener.LocalEndpoint, c => c.CipherSuites = new List<ushort> { suite }); }
                catch (Exception) { try { bcServer.Wait(2000); } catch (AggregateException ex) { throw new Exception("BC:" + ex.GetBaseException()); } throw; }
                var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.ApplicationDataReceived += (_, d) => received.TrySetResult(Encoding.UTF8.GetString(d));
                client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
                Assert.IsTrue(received.Task.Wait(Timeout), bcServer.IsFaulted ? bcServer.Exception.GetBaseException().ToString() : "no reply");
                Assert.AreEqual("pong:ping", received.Task.Result);
                Assert.AreEqual(suite, client.Session.CipherSuite.Id);
            }
            finally
            {
                listener.Stop();
            }

            // BouncyCastle client, our server.
            var (serverKey, serverCert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            using var ours = new Tls13Server(serverKey, serverCert) { CipherSuites = new List<ushort> { suite } };
            ours.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            ours.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var bcClient = RunBlocking(() =>
            {
                using var tcp = new TcpClient();
                tcp.Connect(ours.LocalEndpoint);
                var protocol = new TlsClientProtocol(tcp.GetStream());
                protocol.Connect(new BcTestClient(crypto, suite, ProtocolVersion.TLSv13));
                byte[] ping = Encoding.UTF8.GetBytes("ping");
                protocol.Stream.Write(ping, 0, ping.Length);
                protocol.Stream.Flush();
                byte[] buffer = new byte[256];
                int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                return Encoding.UTF8.GetString(buffer, 0, n);
            });
            Assert.IsTrue(bcClient.Wait(Timeout), "BouncyCastle client did not finish");
            Assert.AreEqual("pong:ping", bcClient.Result);
        }
    }
}
