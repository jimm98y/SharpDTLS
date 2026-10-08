using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpDTLS.TLS13;
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>One TLS server for every version (<see cref="TlsServer"/>), with RFC 8446 downgrade protection.</summary>
    [TestClass]
    public sealed class TestTlsVersionNegotiation
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly byte[] Downgrade12 = Encoding.ASCII.GetBytes("DOWNGRD").Append((byte)1).ToArray();

        private static TlsServer Start(Action<TlsServer> configure = null)
        {
            var server = new TlsServer();
            configure?.Invoke(server);
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        private static DtlsConnectionBase WaitForConnection(TlsServer server)
        {
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            return server.Connections.First(c => c.IsHandshakeComplete);
        }

        [TestMethod]
        public void OnePort_ServesTls12AndTls13Clients()
        {
            using var server = Start();
            var tls13 = TestTls13.Connect(server.LocalEndpoint);
            Assert.IsInstanceOfType<Dtls13ServerConnection>(WaitForConnection(server));
            tls13.Close();
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Count == 0, Timeout));

            var tls12 = TestTls12.Connect(server.LocalEndpoint);
            var connection = (Dtls12ServerConnection)WaitForConnection(server);
            Assert.AreEqual(TlsVersion.Tls12, tls12.NegotiatedVersion);
            CollectionAssert.AreEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray(), "TLS 1.2 from a TLS 1.3 server carries the sentinel");
        }

        [TestMethod]
        public void Tls12OnlyServer_HasNoSentinel_AndOldVersionsAreOff()
        {
            using var server = Start(s => s.MaximumVersion = TlsVersion.Tls12);
            TestTls12.Connect(server.LocalEndpoint);
            var connection = (Dtls12ServerConnection)WaitForConnection(server);
            CollectionAssert.AreNotEqual(Downgrade12, connection.ServerRandomBytes.AsSpan(24).ToArray());

            var tcp = new System.Net.Sockets.TcpClient();
            tcp.Connect(server.LocalEndpoint);
            var old = new SharpDTLS.TLS12.Tls12Client(tcp.GetStream()) { MinimumVersion = TlsVersion.Tls11, MaximumVersion = TlsVersion.Tls11 };
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
