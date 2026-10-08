using SharpDTLS;
using SharpDTLS.DTLS10;
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
    /// <summary>
    /// One DTLS client (<see cref="DtlsClient"/>) and one DTLS server (<see cref="DtlsServer"/>) for every version, with
    /// RFC 9147 §5.3 downgrade protection.
    /// </summary>
    [TestClass]
    public sealed class TestDtlsVersionNegotiation
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly byte[] Downgrade12 = Encoding.ASCII.GetBytes("DOWNGRD").Append((byte)1).ToArray();

        private sealed class Endpoints : IDisposable
        {
            public ServerTransport Server = new(new IPEndPoint(IPAddress.Loopback, 0));
            public ClientTransport Client;

            public ClientTransport NewClient()
            {
                Client?.Dispose();
                Client = new ClientTransport(new IPEndPoint(IPAddress.Loopback, Server.LocalEndpoint.Port));
                return Client;
            }

            public void Dispose()
            {
                Client?.Dispose();
                Server.Dispose();
            }
        }

        private static DtlsServer EchoServer(IServerTransport transport, Action<DtlsServer> configure = null)
        {
            var server = new DtlsServer(transport);
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            return server;
        }

        private static Dtls12Server Echo12(IServerTransport transport, Action<Dtls12Server> configure = null)
        {
            var server = new Dtls12Server(transport);
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => server.SendApplicationData(e.RemoteEndPoint, Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            return server;
        }

        internal static (DtlsClient Client, Exception Error) Connect(IClientTransport transport, Action<DtlsClient> configure = null)
        {
            var client = new DtlsClient(transport);
            configure?.Invoke(client);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return (client, done.Task.Result);
        }

        private static void AssertEcho(DtlsClient client)
        {
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => received.TrySetResult(Encoding.UTF8.GetString(d));
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(received.Task.Wait(Timeout), "no reply");
            Assert.AreEqual("pong:ping", received.Task.Result);
        }

        private static TlsConnectionBase WaitForConnection(DtlsServer server)
        {
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            return server.Connections.First(c => c.IsHandshakeComplete);
        }

        // ── DtlsClient ───────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void Client_NegotiatesDtls13_WithADtls13Server()
        {
            using var e = new Endpoints();
            var server = new Dtls13Server(e.Server);
            server.ApplicationDataReceived += (_, d) => d.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(d.Data)));
            var (client, error) = Connect(e.NewClient());
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls13, client.NegotiatedVersion);
            Assert.AreSame(client.Dtls13, client.Connection);
            AssertEcho(client);
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Client_FallsBackToDtls12_WithADtls12Server(bool helloVerify)
        {
            using var e = new Endpoints();
            Echo12(e.Server, s => s.ShouldSendHelloVerify = helloVerify);
            var (client, error) = Connect(e.NewClient(), c => c.ApplicationProtocols = new[] { "h2" });
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls12, client.NegotiatedVersion);
            Assert.AreSame(client.Dtls12, client.Connection);
            AssertEcho(client);
        }

        [TestMethod]
        public void Client_ReachesDtls10_OnlyWhenAllowed()
        {
            using var e = new Endpoints();
            var server = new Dtls10Server(e.Server);
            server.ApplicationDataReceived += (_, d) => server.SendApplicationData(d.RemoteEndPoint, Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(d.Data)));

            var (client, error) = Connect(e.NewClient(), c => c.MinimumVersion = DtlsVersion.Dtls10);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls10, client.NegotiatedVersion);
            AssertEcho(client);

            var (_, refused) = Connect(e.NewClient());
            Assert.IsNotNull(refused, "DTLS 1.0 is off by default");
        }

        [TestMethod]
        public void Client_RejectsTheDowngradeSentinel()
        {
            // A DTLS 1.2 server marking its random as if it spoke DTLS 1.3: a client that offered DTLS 1.3 must refuse it.
            using var e = new Endpoints();
            Echo12(e.Server, s => s.SignalTls13Downgrade = true);
            var (_, error) = Connect(e.NewClient());
            Assert.AreEqual(AlertDescription.IllegalParameter, (error as DtlsException)?.Alert, error?.ToString());

            // Without DTLS 1.3 in its offer the client accepts the same server.
            var (client, plainError) = Connect(e.NewClient(), c => c.MaximumVersion = DtlsVersion.Dtls12);
            Assert.IsNull(plainError, plainError?.ToString());
            AssertEcho(client);
        }

        [TestMethod]
        public void Client_KeepsTheConnectionIdItOffered_AfterFallingBack()
        {
            // The merged ClientHello carries the 1.3 engine's CID; the 1.2 engine must expect that one.
            using var e = new Endpoints();
            var server = Echo12(e.Server, s => s.UseConnectionIds = true);
            var (client, error) = Connect(e.NewClient(), c =>
            {
                c.Dtls12.UseConnectionId = c.Dtls13.UseConnectionId = true;
                c.Dtls12.ConnectionIdLength = c.Dtls13.ConnectionIdLength = 4;
            });
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls12, client.NegotiatedVersion);
            Assert.IsNotNull(client.Dtls12.ConnectionId);
            CollectionAssert.AreEqual(client.Dtls12.ConnectionId, server.Connections.Single().PeerConnectionId);
            AssertEcho(client);
        }

        [TestMethod]
        public void Client_ResumesADtls12Session_ThroughTheMergedHello()
        {
            using var e = new Endpoints();
            Echo12(e.Server);
            var (first, error) = Connect(e.NewClient());
            Assert.IsNull(error, error?.ToString());
            Assert.IsNotNull(first.Dtls12.SessionState);
            first.Close();

            var (second, error2) = Connect(e.NewClient(), c => c.Dtls12.ResumptionSession = first.Dtls12.SessionState);
            Assert.IsNull(error2, error2?.ToString());
            Assert.IsTrue(second.Dtls12.IsResumed);
            AssertEcho(second);
        }

        [TestMethod]
        public void Client_HandsOffMessagesThatOvertookTheServerHello()
        {
            // The DTLS 1.2 server's flight arrives with its ServerHello last: the 1.3 engine keeps the rest for the 1.2 one.
            var pair = new ScriptedTransportPair();
            byte[] heldServerHello = null;
            pair.ServerToClient = d =>
            {
                if (d.Length > 13 && d[0] == 0x16 && d[13] == HandshakeType.ServerHello)
                {
                    heldServerHello = d;
                    return Array.Empty<byte[]>();
                }
                if (d.Length > 13 && d[0] == 0x16 && d[13] == HandshakeType.ServerHelloDone && heldServerHello != null)
                {
                    var serverHello = heldServerHello;
                    heldServerHello = null;
                    return new[] { d, serverHello };
                }
                return new[] { d };
            };
            var server = Echo12(pair.Server, s => s.ShouldSendHelloVerify = false);
            var (client, error) = Connect(pair.Client);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls12, client.NegotiatedVersion);
            AssertEcho(client);
        }

        // ── DtlsServer ───────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void Server_ServesEveryClientOnOnePort()
        {
            using var e = new Endpoints();
            var server = EchoServer(e.Server);

            var (merged, error) = Connect(e.NewClient());
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls13, merged.NegotiatedVersion);
            AssertEcho(merged);

            var dtls13 = new Dtls13Client(e.NewClient());
            var done13 = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            dtls13.HandshakeFinished += (_, _) => done13.TrySetResult(true);
            dtls13.BeginHandshake();
            Assert.IsTrue(done13.Task.Wait(Timeout));

            var dtls12 = new Dtls12Client(e.NewClient());
            var done12 = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            dtls12.HandshakeFinished += (_, _) => done12.TrySetResult(true);
            dtls12.BeginHandshake();
            Assert.IsTrue(done12.Task.Wait(Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.OfType<Tls12ServerConnection>().Any(c => c.IsHandshakeComplete), Timeout));
            var connection = server.Connections.OfType<Tls12ServerConnection>().Single();
            CollectionAssert.AreEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray(), "DTLS 1.2 from a DTLS 1.3 server carries the sentinel");
            Assert.AreSame(connection, server.GetConnection(connection.RemoteEndPoint));

            var reply = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            dtls12.ApplicationDataReceived += (_, d) => reply.TrySetResult(Encoding.UTF8.GetString(d));
            dtls12.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(reply.Task.Wait(Timeout));
            Assert.AreEqual("pong:ping", reply.Task.Result);
            Assert.AreEqual(2, server.Connections.OfType<Tls13ServerConnection>().Count());
        }

        [TestMethod]
        public void Server_WithDtls13Off_NegotiatesDtls12WithoutTheSentinel()
        {
            using var e = new Endpoints();
            var server = EchoServer(e.Server, s => s.MaximumVersion = DtlsVersion.Dtls12);
            var (client, error) = Connect(e.NewClient());
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(DtlsVersion.Dtls12, client.NegotiatedVersion);
            var connection = (Tls12ServerConnection)WaitForConnection(server);
            CollectionAssert.AreNotEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray());
            AssertEcho(client);
        }

        [TestMethod]
        public void Server_ReportsHandshakesDataAndClosures()
        {
            using var e = new Endpoints();
            var server = EchoServer(e.Server);
            var finished = new List<TlsConnectionBase>();
            var closed = new List<TlsConnectionBase>();
            server.HandshakeFinished += (_, c) => { lock (finished) finished.Add(c); };
            server.ConnectionClosed += (_, c) => { lock (closed) closed.Add(c); };

            foreach (ushort version in new[] { DtlsVersion.Dtls13, DtlsVersion.Dtls12 })
            {
                var (client, error) = Connect(e.NewClient(), c => c.MaximumVersion = version);
                Assert.IsNull(error, error?.ToString());
                AssertEcho(client);
                client.Close();
            }
            Assert.IsTrue(SpinWait.SpinUntil(() => { lock (closed) return closed.Count == 2; }, Timeout));
            CollectionAssert.AreEquivalent(finished, closed);
            Assert.IsInstanceOfType<Tls13ServerConnection>(finished[0]);
            Assert.IsInstanceOfType<Tls12ServerConnection>(finished[1]);
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void Client_FallsBackToDtls12_WithOpenSsl()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -dtls -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var (client, error) = Connect(transport);
            Assert.IsNull(error, error + "\n" + server.Output);
            Assert.AreEqual(DtlsVersion.Dtls12, client.NegotiatedVersion);
            client.SendApplicationData(Encoding.UTF8.GetBytes("hello over DTLS 1.2\n"));
            Assert.IsTrue(server.WaitForOutput("hello over DTLS 1.2", Timeout), server.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void Server_ServesOpenSslDtls12Client()
        {
            OpenSsl.RequireOpenSsl();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = EchoServer(transport);
            using var client = new OpenSslProcess($"s_client -dtls -connect 127.0.0.1:{transport.LocalEndpoint.Port}", OpenSsl.NewTempDirectory());
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout), client.Output);
            Assert.IsInstanceOfType<Tls12ServerConnection>(server.Connections.Single());
            client.WriteLine("ping");
            Assert.IsTrue(client.WaitForOutput("pong:ping", Timeout), client.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void Client_NegotiatesDtls13_WithWolfSsl()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -hrr", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var (client, error) = Connect(transport);
            Assert.IsNull(error, error + "\n" + server.Output);
            Assert.AreEqual(DtlsVersion.Dtls13, client.NegotiatedVersion);
            client.SendApplicationData(Encoding.UTF8.GetBytes("hello over DTLS 1.3\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:hello over DTLS 1.3", Timeout), server.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void Server_ServesWolfSslDtls13Client()
        {
            WolfSsl.RequireWolfSsl();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = EchoServer(transport);
            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port}", OpenSsl.NewTempDirectory(), WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), client.Output);
            Assert.IsInstanceOfType<Tls13ServerConnection>(WaitForConnection(server));
            client.WriteLine("ping");
            Assert.IsTrue(client.WaitForOutput("RECV:pong:ping", Timeout), client.Output);
        }
    }
}
