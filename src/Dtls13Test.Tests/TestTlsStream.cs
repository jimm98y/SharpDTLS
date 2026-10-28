using SharpDTLS;
using SharpDTLS.Protocol12.TLS12;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary><see cref="TlsStream"/>: TLS as a <see cref="Stream"/>.</summary>
    [TestClass]
    public sealed class TestTlsStream
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        [TestMethod]
        public async Task LargeTransfer_EchoesAndEndsCleanly()
        {
            using var server = new Tls12Server();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var serverSide = Task.Run(async () =>
            {
                var tcp = await listener.AcceptTcpClientAsync();
                using var tls = await TlsStream.AcceptAsync(server, tcp.GetStream());
                byte[] buffer = new byte[5000];
                long total = 0;
                int n;
                while ((n = await tls.ReadAsync(buffer)) > 0)
                {
                    await tls.WriteAsync(buffer.AsMemory(0, n));
                    total += n;
                }
                return total; // the client's close_notify ends the stream
            });

            byte[] payload = RandomNumberGenerator.GetBytes(200_000);
            using (var tcp = new TcpClient())
            {
                await tcp.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
                using var tls = await TlsStream.ConnectAsync(tcp.GetStream()).WaitAsync(Timeout);
                Assert.AreEqual(TlsVersion.Tls12, tls.NegotiatedVersion); // a TLS 1.2 server answers the TLS 1.3 + 1.2 offer
                await tls.WriteAsync(payload);
                byte[] echoed = new byte[payload.Length];
                await tls.ReadExactlyAsync(echoed).AsTask().WaitAsync(Timeout);
                CollectionAssert.AreEqual(payload, echoed);
            }
            Assert.AreEqual(payload.Length, await serverSide.WaitAsync(Timeout));
            listener.Stop();
        }

        [TestMethod]
        public async Task FailedHandshake_IsAnIOException()
        {
            // A client that only offers PSK suites against a certificate-only server.
            using var server = new Tls12Server();
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(server.LocalEndpoint);
            var error = await Assert.ThrowsExactlyAsync<IOException>(() => TlsStream.ConnectAsync(tcp.GetStream(), c =>
            {
                c.MaximumVersion = TlsVersion.Tls12;
                c.Tls12.CipherSuites = new[] { (ushort)0x00A8 }; // TLS_PSK_WITH_AES_128_GCM_SHA256
                (c.Tls12.PskIdentity, c.Tls12.PskKey) = (TestCredentials.PskIdentity, TestCredentials.PskKey);
            }).WaitAsync(Timeout));
            StringAssert.Contains(error.Message, "handshake");
        }

        [TestMethod]
        public async Task AnyVersion_TlsServerAndClient()
        {
            using var server = new TlsServer();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var serverSide = Task.Run(async () =>
            {
                var tcp = await listener.AcceptTcpClientAsync();
                using var tls = await TlsStream.AcceptAsync(server, tcp.GetStream());
                byte[] line = new byte[4];
                await tls.ReadExactlyAsync(line);
                await tls.WriteAsync(line);
                return tls.NegotiatedVersion;
            });
            using var client = new TcpClient();
            await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            using var tls = await TlsStream.ConnectAsync(client.GetStream()).WaitAsync(Timeout);
            Assert.AreEqual(TlsVersion.Tls13, tls.NegotiatedVersion);
            await tls.WriteAsync(Encoding.ASCII.GetBytes("ping"));
            byte[] echoed = new byte[4];
            await tls.ReadExactlyAsync(echoed).AsTask().WaitAsync(Timeout);
            Assert.AreEqual("ping", Encoding.ASCII.GetString(echoed));
            Assert.AreEqual(TlsVersion.Tls13, await serverSide.WaitAsync(Timeout));
            listener.Stop();
        }

        [DataRow("-tls1_2", TlsVersion.Tls12)]
        [DataRow("", TlsVersion.Tls13)]
        [TestCategory("Interop")]
        [TestMethod]
        public async Task HttpRequest_ToOpenSslWwwServer(string versionFlag, ushort expected)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server {versionFlag} -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -www", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            using var tls = await TlsStream.ConnectAsync(tcp.GetStream()).WaitAsync(Timeout);
            await tls.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"));
            using var reader = new StreamReader(tls, Encoding.ASCII);
            string response = await reader.ReadToEndAsync().WaitAsync(Timeout);
            StringAssert.StartsWith(response, "HTTP/1.0 200 ok");
            Assert.AreEqual(expected, tls.NegotiatedVersion);
            StringAssert.Contains(response, "Ciphers supported in s_server binary");
        }
    }
}
