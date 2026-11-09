using SharpDTLS;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>One TLS server for every version (<see cref="TlsServer"/>), with RFC 8446 downgrade protection.</summary>
    [TestClass]
    public sealed class TestTlsVersionNegotiation
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;
        private static readonly byte[] Downgrade12 = Encoding.ASCII.GetBytes("DOWNGRD").Append((byte)1).ToArray();

        private static TlsServer Start(Action<TlsServer> configure = null)
        {
            var server = new TlsServer();
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        private static TlsConnectionBase WaitForConnection(TlsServer server)
        {
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            return server.Connections.First(c => c.IsHandshakeComplete);
        }

        [TestMethod]
        public void OnePort_ServesTls12AndTls13Clients()
        {
            using var server = Start();
            var tls13 = TestTls13.Connect(server.LocalEndpoint);
            Assert.IsInstanceOfType<Tls13ServerConnection>(WaitForConnection(server));
            tls13.Close();
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Count == 0, Timeout));

            var tls12 = TestTls12.Connect(server.LocalEndpoint);
            var connection = (Tls12ServerConnection)WaitForConnection(server);
            Assert.AreEqual(TlsVersion.Tls12, tls12.NegotiatedVersion);
            CollectionAssert.AreEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray(), "TLS 1.2 from a TLS 1.3 server carries the sentinel");
        }

        [TestMethod]
        public void Tls12OnlyServer_HasNoSentinel_AndOldVersionsAreOff()
        {
            using var server = Start(s => s.MaximumVersion = TlsVersion.Tls12);
            TestTls12.Connect(server.LocalEndpoint);
            var connection = (Tls12ServerConnection)WaitForConnection(server);
            CollectionAssert.AreNotEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray());

            var tcp = new System.Net.Sockets.TcpClient();
            tcp.Connect(server.LocalEndpoint);
            var old = new SharpDTLS.Protocol12.TLS12.Tls12Client(tcp.GetStream()) { MinimumVersion = TlsVersion.Tls11, MaximumVersion = TlsVersion.Tls11 };
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            old.Failed += (_, ex) => failed.TrySetResult(ex);
            old.BeginHandshake();
            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.ProtocolVersion, (failed.Task.Result as DtlsException)?.Alert);
        }

        [DataRow("", "TLSv1.3")]
        [DataRow("-tls1_2", "TLSv1.2")]
        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_GetsTheVersionItOffers(string versionFlag, string expected)
        {
            OpenSsl.RequireOpenSsl();
            using var server = Start();
            using var client = new OpenSslProcess($"s_client {versionFlag} -connect 127.0.0.1:{server.LocalEndpoint.Port}", OpenSsl.NewTempDirectory());
            Assert.IsTrue(client.WaitForOutput($"New, {expected}", Timeout), client.Output);
            client.WriteLine("ping");
            Assert.IsTrue(client.WaitForOutput("pong:ping", Timeout), client.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_Tls12Server_NegotiatesTls12()
        {
            OpenSsl.RequireOpenSsl();
            // OpenSSL offers TLS 1.3 and would reject a sentinel: a TLS 1.2-only server must not send one.
            using var server = Start(s => s.MaximumVersion = TlsVersion.Tls12);
            using var client = new OpenSslProcess($"s_client -connect 127.0.0.1:{server.LocalEndpoint.Port}", OpenSsl.NewTempDirectory());
            Assert.IsTrue(client.WaitForOutput("New, TLSv1.2", Timeout), client.Output);
        }
    }
}

namespace SharpDTLS.Tests
{
    using SharpDTLS;
    using SharpDTLS.Protocol12.TLS12;
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>One TLS client for every version (<see cref="TlsClient"/>): a merged ClientHello and downgrade protection.</summary>
    [TestClass]
    public sealed class TestTlsClient
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;

        internal static (TlsClient Client, Exception Error) Connect(IPEndPoint endpoint, Action<TlsClient> configure = null)
        {
            var tcp = new TcpClient();
            tcp.Connect(endpoint);
            var client = new TlsClient(tcp.GetStream());
            configure?.Invoke(client);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return (client, done.Task.Result);
        }

        private static void AssertEcho(TlsClient client)
        {
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var text = new StringBuilder();
            client.ApplicationDataReceived += (_, d) => { lock (text) { text.Append(Encoding.UTF8.GetString(d)); if (text.ToString().Contains("ping")) received.TrySetResult(text.ToString()); } };
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(received.Task.Wait(Timeout), "no reply");
            StringAssert.Contains(received.Task.Result, "pong:ping");
        }

        private static TlsServer EchoServer(Action<TlsServer> configure = null)
        {
            var server = new TlsServer();
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        [TestMethod]
        public void NegotiatesTls13_OrTls12WithAnOlderServer()
        {
            using (var server = EchoServer())
            {
                var (client, error) = Connect(server.LocalEndpoint);
                Assert.IsNull(error, error?.ToString());
                Assert.AreEqual(TlsVersion.Tls13, client.NegotiatedVersion);
                AssertEcho(client);
            }

            // A TLS 1.2-only server (no sentinel) and our plain TLS 1.2 server both get TLS 1.2 from the merged hello.
            using (var server = EchoServer(s => s.MaximumVersion = TlsVersion.Tls12))
            {
                var (client, error) = Connect(server.LocalEndpoint, c => c.ApplicationProtocols = new[] { "h2" });
                Assert.IsNull(error, error?.ToString());
                Assert.AreEqual(TlsVersion.Tls12, client.NegotiatedVersion);
                AssertEcho(client);
            }
            using var plain = new Tls12Server();
            plain.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            plain.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var (c12, e12) = Connect(plain.LocalEndpoint);
            Assert.IsNull(e12, e12?.ToString());
            Assert.AreEqual(TlsVersion.Tls12, c12.NegotiatedVersion);
            AssertEcho(c12);
        }

        [TestMethod]
        public void DowngradeSentinel_IsRejected()
        {
            // A TLS 1.2 server marking its random as if it spoke TLS 1.3: a client that offered TLS 1.3 must refuse it.
            using var server = new Tls12Server();
            typeof(Tls12Server).GetProperty("SignalTls13Downgrade", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).SetValue(server, true);
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var (_, error) = Connect(server.LocalEndpoint);
            Assert.AreEqual(AlertDescription.IllegalParameter, (error as DtlsException)?.Alert, error?.ToString());

            // Without TLS 1.3 in its offer the client accepts the same server.
            var (client, plainError) = Connect(server.LocalEndpoint, c => c.MaximumVersion = TlsVersion.Tls12);
            Assert.IsNull(plainError, plainError?.ToString());
        }

        [TestMethod]
        public void Tls12SessionResumption_ThroughTheMergedHello()
        {
            using var server = EchoServer(s => s.MaximumVersion = TlsVersion.Tls12);
            var (first, error) = Connect(server.LocalEndpoint);
            Assert.IsNull(error, error?.ToString());
            Assert.IsNotNull(first.Tls12.SessionState);
            first.Close();
            var (second, error2) = Connect(server.LocalEndpoint, c => c.Tls12.ResumptionSession = first.Tls12.SessionState);
            Assert.IsNull(error2, error2?.ToString());
            Assert.IsTrue(second.Tls12.IsResumed);
        }

        [DataRow(TlsVersion.Tls12)]
        [DataRow(TlsVersion.Tls13)]
        [TestMethod]
        public void Alerts_AreRaisedByTheWrappers_WhateverTheVersion(ushort version)
        {
            using var server = EchoServer(s => s.MaximumVersion = version);
            var serverAlert = new TaskCompletionSource<TlsAlertEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.AlertReceived += (_, a) => serverAlert.TrySetResult(a);

            // client → server
            var (client, error) = Connect(server.LocalEndpoint);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(version, client.NegotiatedVersion);
            TlsConnectionBase first = null;
            Assert.IsTrue(SpinWait.SpinUntil(() => (first = server.Connections.FirstOrDefault(c => c.IsHandshakeComplete)) != null, Timeout));
            client.Close();
            Assert.IsTrue(serverAlert.Task.Wait(Timeout), "the server raised no alert");
            Assert.AreEqual(AlertDescription.CloseNotify, serverAlert.Task.Result.Description);
            Assert.AreSame(first, serverAlert.Task.Result.Connection);

            // server → client
            var clientAlert = new TaskCompletionSource<AlertDescription>(TaskCreationOptions.RunContinuationsAsynchronously);
            var (second, secondError) = Connect(server.LocalEndpoint, c => c.AlertReceived += (_, a) => clientAlert.TrySetResult(a));
            Assert.IsNull(secondError, secondError?.ToString());
            TlsConnectionBase serverSide = null;
            Assert.IsTrue(SpinWait.SpinUntil(() => (serverSide = server.Connections.FirstOrDefault(c => c != first && c.IsHandshakeComplete)) != null, Timeout));
            serverSide.Close();
            Assert.IsTrue(clientAlert.Task.Wait(Timeout), "the client raised no alert");
            Assert.AreEqual(AlertDescription.CloseNotify, clientAlert.Task.Result);
            GC.KeepAlive(second);
        }

        [TestMethod]
        public void Close_RightAfterTheHandshake_StillDeliversCloseNotify()
        {
            // The server's NewSessionTicket is still unread when the client closes: closing the socket at once would
            // reset the connection (on Windows), and the reset could discard the close_notify (about one close in three).
            const int closes = 20;
            using var server = EchoServer(s => s.MaximumVersion = TlsVersion.Tls13);
            // What each server connection saw first: the close_notify, or the stream ending without one.
            var first = new System.Collections.Concurrent.ConcurrentDictionary<TlsConnectionBase, string>();
            server.AlertReceived += (_, a) => first.TryAdd(a.Connection, a.Description.ToString());
            server.ConnectionClosed += (_, c) => first.TryAdd(c, "closed without an alert");
            for (int i = 0; i < closes; i++)
            {
                var (client, error) = Connect(server.LocalEndpoint);
                Assert.IsNull(error, error?.ToString());
                client.Close();
            }
            Assert.IsTrue(SpinWait.SpinUntil(() => first.Count == closes, Timeout), $"the server noticed {first.Count} of {closes} closes");
            CollectionAssert.AreEqual(Enumerable.Repeat(nameof(AlertDescription.CloseNotify), closes).ToList(), first.Values.ToList());
        }

        [DataRow("", "TLSv1.3", TlsVersion.Tls13)]
        [DataRow("-tls1_2", "TLSv1.2", TlsVersion.Tls12)]
        [DataRow("-tls1_1 -cipher ALL@SECLEVEL=0", "TLSv1.1", TlsVersion.Tls11)]
        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslServer_NegotiatesItsVersion(string versionFlag, string name, ushort expected)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server {versionFlag} -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
            var (client, error) = Connect(new IPEndPoint(IPAddress.Loopback, port), c => c.MinimumVersion = TlsVersion.Tls11);
            Assert.IsNull(error, error + "\n" + server.Output);
            Assert.AreEqual(expected, client.NegotiatedVersion);
            client.SendApplicationData(Encoding.UTF8.GetBytes($"hello over {name}\n"));
            Assert.IsTrue(server.WaitForOutput($"hello over {name}", Timeout), server.Output);
        }
    }
}
