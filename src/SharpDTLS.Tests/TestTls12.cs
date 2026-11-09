using SharpDTLS;
using SharpDTLS.Protocol12.TLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>TLS 1.2 over TCP: the DTLS 1.0/1.2 handshake engine with stream framing.</summary>
    [TestClass]
    public sealed class TestTls12
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;

        internal static Tls12Client Connect(IPEndPoint server, Action<Tls12Client> configure = null)
        {
            var tcp = new TcpClient();
            tcp.Connect(server);
            tcp.NoDelay = true;
            var client = new Tls12Client(tcp.GetStream());
            configure?.Invoke(client);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the TLS handshake neither completed nor failed");
            Assert.IsNull(done.Task.Result, done.Task.Result?.ToString());
            return client;
        }

        [TestMethod]
        public void SharpTlsClient_To_SharpTlsServer()
        {
            using var server = new Tls12Server();
            var serverReceived = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) =>
            {
                serverReceived.TrySetResult(Encoding.UTF8.GetString(e.Data));
                e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong"));
            };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            var client = Connect(server.LocalEndpoint);
            var clientReceived = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => clientReceived.TrySetResult(Encoding.UTF8.GetString(d));
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(serverReceived.Task.Wait(Timeout));
            Assert.AreEqual("ping", serverReceived.Task.Result);
            Assert.IsTrue(clientReceived.Task.Wait(Timeout));
            Assert.AreEqual("pong", clientReceived.Task.Result);
            Assert.AreEqual(TlsVersion.Tls12, client.NegotiatedVersion);

            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ConnectionClosed += (_, _) => closed.TrySetResult(true);
            client.Close();
            Assert.IsTrue(closed.Task.Wait(Timeout), "the server did not see close_notify");
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void SharpTlsClient_To_OpenSslServer()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -tls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            var client = Connect(new IPEndPoint(IPAddress.Loopback, port));
            client.SendApplicationData(Encoding.UTF8.GetBytes("hello over tls\n"));
            Assert.IsTrue(server.WaitForOutput("hello over tls", Timeout), server.Output);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => received.TrySetResult(Encoding.UTF8.GetString(d));
            server.WriteLine("reply from openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), server.Output);
            StringAssert.Contains(received.Task.Result, "reply from openssl");
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_To_SharpTlsServer()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Rsa);
            using var server = new Tls12Server(key, cert);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) =>
            {
                received.TrySetResult(Encoding.UTF8.GetString(e.Data));
                e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("reply from sharp\n"));
            };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            using var client = new OpenSslProcess($"s_client -tls1_2 -connect 127.0.0.1:{server.LocalEndpoint.Port}", dir);
            Assert.IsTrue(client.WaitForOutput("Verify return code", Timeout), client.Output);
            client.WriteLine("hello from openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), client.Output);
            StringAssert.Contains(received.Task.Result, "hello from openssl");
            Assert.IsTrue(client.WaitForOutput("reply from sharp", Timeout), client.Output);
        }
    }
}
