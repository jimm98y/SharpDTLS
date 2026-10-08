using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.TLS10;
using SharpDTLS.TLS12;
using SharpDTLS.TLS13;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>The fixed-version TLS 1.0 and 1.1 clients and servers (<see cref="Tls10Client"/>, <see cref="Tls11Server"/>...).</summary>
    [TestClass]
    public sealed class TestTls10
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static Tls12Server Echo(Tls12Server server)
        {
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            return server;
        }

        private static Tls12Server NewServer(ushort version) => version == TlsVersion.Tls10 ? new Tls10Server() : new Tls11Server();

        private static Tls12Client NewClient(ushort version, NetworkStream stream) => version == TlsVersion.Tls10 ? new Tls10Client(stream) : new Tls11Client(stream);

        private static Exception Handshake(Tls12Client client, Action begin)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        private static (Tls12Client Client, Exception Error) Connect(ushort version, IPEndPoint endpoint)
        {
            var tcp = new TcpClient();
            tcp.Connect(endpoint);
            var client = NewClient(version, tcp.GetStream());
            return (client, Handshake(client, client.BeginHandshake));
        }

        private static void AssertEcho(Tls12Client client)
        {
            var reply = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var text = new StringBuilder();
            // TLS 1.0 splits records 1/n-1 (BEAST), so the server sees "p" and "ing" and answers each.
            client.ApplicationDataReceived += (_, d) =>
            {
                lock (text)
                {
                    text.Append(Encoding.UTF8.GetString(d));
                    if (text.ToString().Replace("pong:", "") == "ping")
                        reply.TrySetResult(text.ToString());
                }
            };
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            Assert.IsTrue(reply.Task.Wait(Timeout), "no reply: " + text);
        }

        [DataRow(TlsVersion.Tls10)]
        [DataRow(TlsVersion.Tls11)]
        [TestMethod]
        public void Client_To_Server_NegotiatesTheirVersion(ushort version)
        {
            using var server = Echo(NewServer(version));
            var (client, error) = Connect(version, server.LocalEndpoint);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(version, client.NegotiatedVersion);
            AssertEcho(client);
        }

        [DataRow(TlsVersion.Tls10)]
        [DataRow(TlsVersion.Tls11)]
        [TestMethod]
        public void OnlyTheirVersion_IsSpoken(ushort version)
        {
            // Against a default (TLS 1.2) server the client refuses or is refused...
            using (var server = Echo(new Tls12Server()))
            {
                var (_, error) = Connect(version, server.LocalEndpoint);
                Assert.AreEqual(AlertDescription.ProtocolVersion, (error as DtlsException)?.Alert, error?.ToString());
            }

            // ...and a default TlsClient does not reach the server, until it allows the old version.
            using var old = Echo(NewServer(version));
            var (_, refused) = TestTlsClient.Connect(old.LocalEndpoint);
            Assert.IsNotNull(refused, "TLS 1.0 and 1.1 are off by default");
            var (client, accepted) = TestTlsClient.Connect(old.LocalEndpoint, c => c.MinimumVersion = TlsVersion.Tls10);
            Assert.IsNull(accepted, accepted?.ToString());
            Assert.AreEqual(version, client.NegotiatedVersion);
        }

        [DataRow(TlsVersion.Tls10)]
        [DataRow(TlsVersion.Tls11)]
        [TestMethod]
        public void Client_To_TlsServer_ThatAllowsOldVersions(ushort version)
        {
            using var server = new TlsServer { MinimumVersion = TlsVersion.Tls10 };
            server.ApplicationDataReceived += (_, e) => e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var (client, error) = Connect(version, server.LocalEndpoint);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(version, client.NegotiatedVersion);
            AssertEcho(client);
        }

        [DataRow(TlsVersion.Tls10, "-tls1")]
        [DataRow(TlsVersion.Tls11, "-tls1_1")]
        [TestCategory("Interop")]
        [TestMethod]
        public void Client_To_OpenSslServer(ushort version, string versionFlag)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server {versionFlag} -cipher ALL@SECLEVEL=0 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
            var (client, error) = Connect(version, new IPEndPoint(IPAddress.Loopback, port));
            Assert.IsNull(error, error + "\n" + server.Output);
            Assert.AreEqual(version, client.NegotiatedVersion);
            client.SendApplicationData(Encoding.UTF8.GetBytes($"hello over {versionFlag}\n"));
            Assert.IsTrue(server.WaitForOutput($"hello over {versionFlag}", Timeout), server.Output);
        }

        [DataRow(TlsVersion.Tls10, "-tls1", "TLSv1")]
        [DataRow(TlsVersion.Tls11, "-tls1_1", "TLSv1.1")]
        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_To_Server(ushort version, string versionFlag, string name)
        {
            OpenSsl.RequireOpenSsl();
            using var server = Echo(NewServer(version));
            using var client = new OpenSslProcess($"s_client {versionFlag} -cipher ALL@SECLEVEL=0 -connect 127.0.0.1:{server.LocalEndpoint.Port}", OpenSsl.NewTempDirectory());
            // "New, ..." names the cipher's version; the session's protocol is on its own line.
            Assert.IsTrue(client.WaitForOutput($"Protocol: {name}{Environment.NewLine}", Timeout), client.Output);
            client.WriteLine("ping");
            Assert.IsTrue(client.WaitForOutput("pong:", Timeout), client.Output);
        }
    }
}
