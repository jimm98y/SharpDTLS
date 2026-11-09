using SharpDTLS;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>TLS 1.3 over TCP: the DTLS 1.3 handshake engine with TLS records (RFC 8446).</summary>
    [TestClass]
    public sealed class TestTls13
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;

        internal static Tls13Client Connect(IPEndPoint server, Action<Tls13Client> configure = null)
        {
            var tcp = new TcpClient();
            tcp.Connect(server);
            tcp.NoDelay = true;
            var client = new Tls13Client(tcp.GetStream());
            configure?.Invoke(client);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the TLS 1.3 handshake neither completed nor failed");
            Assert.IsNull(done.Task.Result, done.Task.Result?.ToString());
            return client;
        }

        private static (string Received, string Reply) PingPong(Tls13Server server, Tls13Client client)
        {
            var clientReceived = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => clientReceived.TrySetResult(Encoding.UTF8.GetString(d));
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(clientReceived.Task.Wait(Timeout), "no reply");
            return ("ping", clientReceived.Task.Result);
        }

        private static Tls13Server EchoServer(Action<Tls13Server> configure = null)
        {
            var server = new Tls13Server();
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        [TestMethod]
        public void SharpTlsClient_To_SharpTlsServer()
        {
            using var server = EchoServer();
            var client = Connect(server.LocalEndpoint);
            Assert.AreEqual("pong:ping", PingPong(server, client).Reply);
            Assert.IsTrue(client.Session.CipherSuite.IsTls);

            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ConnectionClosed += (_, _) => closed.TrySetResult(true);
            client.Close();
            Assert.IsTrue(closed.Task.Wait(Timeout), "the server did not see close_notify");
        }

        [TestMethod]
        public void HelloRetryRequest_OverTcp()
        {
            using var server = EchoServer(s => s.SupportedGroups = new[] { Dtls13Groups.Secp384r1 });
            var client = Connect(server.LocalEndpoint, c => { c.KeyShareGroups = new[] { Dtls13Groups.X25519 }; c.SupportedGroups = new[] { Dtls13Groups.X25519, Dtls13Groups.Secp384r1 }; });
            Assert.AreEqual(Dtls13Groups.Secp384r1, client.NegotiatedGroup);
            Assert.AreEqual("pong:ping", PingPong(server, client).Reply);
        }

        // ── OpenSSL ──────────────────────────────────────────────────────────────────────────

        private static readonly Dictionary<ushort, string> OpenSslSuites = new()
        {
            [0x1301] = "TLS_AES_128_GCM_SHA256", [0x1302] = "TLS_AES_256_GCM_SHA384", [0x1303] = "TLS_CHACHA20_POLY1305_SHA256",
        };

        [DataRow((ushort)0x1301)]
        [DataRow((ushort)0x1302)]
        [DataRow((ushort)0x1303)]
        [TestCategory("Interop")]
        [TestMethod]
        public void SharpTlsClient_To_OpenSslServer(ushort suite)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -tls1_3 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -ciphersuites {OpenSslSuites[suite]}",
                dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            var client = Connect(new IPEndPoint(IPAddress.Loopback, port), c => c.CipherSuites = new List<ushort> { suite });
            Assert.AreEqual(suite, client.Session.CipherSuite.Id);
            client.SendApplicationData(Encoding.UTF8.GetBytes("hello over tls 1.3\n"));
            Assert.IsTrue(server.WaitForOutput("hello over tls 1.3", Timeout), server.Output);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => received.TrySetResult(Encoding.UTF8.GetString(d));
            server.WriteLine("reply from openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), server.Output);
            StringAssert.Contains(received.Task.Result, "reply from openssl");
        }

        [DataRow((ushort)0x1301)]
        [DataRow((ushort)0x1302)]
        [DataRow((ushort)0x1303)]
        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_To_SharpTlsServer(ushort suite)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var server = new Tls13Server() { CipherSuites = new List<ushort> { suite } };
            var received = new TaskCompletionSource<(Tls13ServerConnection, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => received.TrySetResult((e.Connection, Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            using var client = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -ciphersuites {OpenSslSuites[suite]}", dir);
            Assert.IsTrue(client.WaitForOutput("Verify return code", Timeout), client.Output);
            client.WriteLine("hello from openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), client.Output);
            StringAssert.Contains(received.Task.Result.Item2, "hello from openssl");
            Assert.AreEqual(suite, received.Task.Result.Item1.Session.CipherSuite.Id);
            received.Task.Result.Item1.SendApplicationData(Encoding.UTF8.GetBytes("reply from sharp\n"));
            Assert.IsTrue(client.WaitForOutput("reply from sharp", Timeout), client.Output);
        }
    }
}
