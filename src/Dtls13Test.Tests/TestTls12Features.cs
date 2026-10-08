using Org.BouncyCastle.Asn1.X509;
using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.TLS12;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>TLS 1.2 stream framing edge cases, and handshake features over TLS against OpenSSL.</summary>
    [TestClass]
    public sealed class TestTls12Features
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("TLS"));
        private static TestPki Pki => _pki.Value;

        /// <summary>Reads at most <see cref="Chunk"/> bytes at a time, so records arrive split across reads.</summary>
        private sealed class TrickleStream(Stream inner, int chunk) : Stream
        {
            public int Chunk => chunk;
            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => inner.Flush();
            public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(count, chunk));
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => inner.ReadAsync(buffer.Slice(0, Math.Min(buffer.Length, chunk)), cancellationToken);
            public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
        }

        private static (Tls12Server Server, TcpListener Listener) TrickleServer(Tls12Server server, int chunk)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            _ = Task.Run(async () =>
            {
                var tcp = await listener.AcceptTcpClientAsync();
                server.Accept(new TrickleStream(tcp.GetStream(), chunk), tcp.Client.RemoteEndPoint);
            });
            return (server, listener);
        }

        [DataRow(1)]
        [DataRow(7)]
        [TestMethod]
        public void RecordsSplitAcrossReads_AndLargeMessages(int chunk)
        {
            // A long chain makes the Certificate message span several records.
            var (key, cert) = Pki.Leaf(new[] { "server.test" });
            var intermediates = Enumerable.Range(0, 40).Select(_ => Pki.Intermediate.Cert).ToList();
            using var server = new Tls12Server(key, cert) { IntermediateCertificates = intermediates };
            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => { received.TrySetResult(e.Data); e.Connection.SendApplicationData(new byte[16384]); };
            var (_, listener) = TrickleServer(server, chunk);
            try
            {
                int certificateLength = 0;
                var client = TestTls12.Connect((IPEndPoint)listener.LocalEndpoint, c => c.ServerCertificateValidator = (_, chain) => { certificateLength = chain.Sum(x => x.Length); return true; });
                Assert.IsGreaterThan(16384, certificateLength, "the Certificate message should span records");
                var reply = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.ApplicationDataReceived += (_, d) => reply.TrySetResult(d);
                client.SendApplicationData(new byte[16384]);
                Assert.IsTrue(received.Task.Wait(Timeout));
                Assert.HasCount(16384, received.Task.Result);
                Assert.IsTrue(reply.Task.Wait(Timeout));
                Assert.HasCount(16384, reply.Task.Result);
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public void StreamClosedDuringHandshake_FailsTheClient()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            _ = Task.Run(async () => { using var tcp = await listener.AcceptTcpClientAsync(); await tcp.GetStream().ReadAsync(new byte[100]); });
            try
            {
                var tcp = new TcpClient();
                tcp.Connect((IPEndPoint)listener.LocalEndpoint);
                var client = new Tls12Client(tcp.GetStream());
                var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.Failed += (_, ex) => failed.TrySetResult(ex);
                client.BeginHandshake();
                Assert.IsTrue(failed.Task.Wait(Timeout));
                Assert.IsInstanceOfType<IOException>(failed.Task.Result);
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public void ResumesWithTicketAndSessionId()
        {
            using var server = new Tls12Server();
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            foreach (bool tickets in new[] { true, false })
            {
                var first = TestTls12.Connect(server.LocalEndpoint, c => c.UseSessionTickets = tickets);
                Assert.IsNotNull(first.SessionState);
                first.Close();
                var second = TestTls12.Connect(server.LocalEndpoint, c => { c.UseSessionTickets = tickets; c.ResumptionSession = first.SessionState; });
                Assert.IsTrue(second.IsResumed, tickets ? "ticket" : "session ID");
                second.Close();
            }
        }

        [TestMethod]
        public void Tls10_IsOffByDefault()
        {
            using var server = new Tls12Server();
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            var tcp = new TcpClient();
            tcp.Connect(server.LocalEndpoint);
            var client = new Tls12Client(tcp.GetStream()) { MinimumVersion = TlsVersion.Tls10, MaximumVersion = TlsVersion.Tls10 };
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.Failed += (_, ex) => failed.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.ProtocolVersion, (failed.Task.Result as DtlsException)?.Alert, failed.Task.Result.ToString());

            server.MinimumVersion = TlsVersion.Tls10;
            var accepted = TestTls12.Connect(server.LocalEndpoint, c => { c.MinimumVersion = TlsVersion.Tls10; c.MaximumVersion = TlsVersion.Tls10; });
            Assert.AreEqual(TlsVersion.Tls10, accepted.NegotiatedVersion);
        }

        // ── OpenSSL ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_ResumesWithSharpTlsServer()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var server = new Tls12Server();
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            foreach (string mode in new[] { "", " -no_ticket" })
            {
                using var client = new OpenSslProcess($"s_client -tls1_2 -connect 127.0.0.1:{server.LocalEndpoint.Port} -reconnect{mode}", dir);
                Assert.IsTrue(client.WaitForOutput("Reused, TLSv1.2", Timeout), mode + "\n" + client.Output);
            }
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void SharpTlsClient_ResumesWithOpenSslServer()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            foreach (bool tickets in new[] { true, false })
            {
                using var server = OpenSslProcess.StartServer(p => $"s_server -tls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}{(tickets ? "" : " -no_ticket")}",
                    dir, Timeout, out int port);
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                var endpoint = new IPEndPoint(IPAddress.Loopback, port);
                var first = TestTls12.Connect(endpoint, c => c.UseSessionTickets = tickets);
                Assert.IsNotNull(first.SessionState, server.Output);
                first.Close();
                var second = TestTls12.Connect(endpoint, c => { c.UseSessionTickets = tickets; c.ResumptionSession = first.SessionState; });
                Assert.IsTrue(second.IsResumed, (tickets ? "ticket" : "session ID") + "\n" + server.Output);
            }
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void ClientAuthentication_AlpnAndSni_WithOpenSsl()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (serverKey, serverCert) = Pki.Leaf(new[] { "server.test" });
            var (clientKey, clientCert) = Pki.Leaf(commonName: "tls client", usage: KeyPurposeID.id_kp_clientAuth);
            string serverCertPath = OpenSsl.WritePem(dir, "server.pem", serverCert);
            string serverKeyPath = OpenSsl.WritePem(dir, "server-key.pem", serverKey.Private);
            string clientCertPath = OpenSsl.WritePem(dir, "client.pem", clientCert);
            string clientKeyPath = OpenSsl.WritePem(dir, "client-key.pem", clientKey.Private);
            string chain = Path.Combine(dir, "chain.pem");
            File.WriteAllText(chain, File.ReadAllText(OpenSsl.WritePem(dir, "int.pem", Pki.Intermediate.Cert)) + File.ReadAllText(OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert)));

            // OpenSSL server requiring a client certificate; our client with ALPN. (s_server's -servername switches to a
            // second context without ALPN, so SNI is covered by the other direction.)
            using (var server = OpenSslProcess.StartServer(p =>
                $"s_server -tls1_2 -accept 127.0.0.1:{p} -cert {serverCertPath} -key {serverKeyPath} -cert_chain {Path.Combine(dir, "int.pem")} -Verify 2 -CAfile {chain} -verify_return_error -alpn h2,http/1.1",
                dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                var client = TestTls12.Connect(new IPEndPoint(IPAddress.Loopback, port), c =>
                {
                    c.ClientCertificate = clientCert;
                    c.ClientCertificateKeyPair = clientKey;
                    c.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
                    c.ApplicationProtocols = new[] { "http/1.1" };
                    c.ServerName = "server.test";
                    c.ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer("server.test");
                });
                Assert.AreEqual("http/1.1", client.ApplicationProtocol);
                client.SendApplicationData(Encoding.UTF8.GetBytes("authenticated\n"));
                Assert.IsTrue(server.WaitForOutput("authenticated", Timeout), server.Output);
            }

            // OpenSSL client with a certificate, ALPN and SNI; our server requiring the certificate.
            var (key, cert) = Pki.Leaf(new[] { "server.test" });
            using var tlsServer = new Tls12Server(key, cert)
            {
                IntermediateCertificates = new[] { Pki.Intermediate.Cert }, RequireClientCertificate = true,
                ClientCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForClient(), ApplicationProtocols = new[] { "h2" },
            };
            var established = new TaskCompletionSource<Dtls12ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            tlsServer.HandshakeFinished += (_, c) => established.TrySetResult(c);
            tlsServer.Start(new IPEndPoint(IPAddress.Loopback, 0));
            using var openSslClient = new OpenSslProcess(
                $"s_client -tls1_2 -connect 127.0.0.1:{tlsServer.LocalEndpoint.Port} -cert {clientCertPath} -key {clientKeyPath} -cert_chain {Path.Combine(dir, "int.pem")} -alpn h2 -servername server.test -CAfile {chain} -verify_return_error",
                dir);
            Assert.IsTrue(established.Task.Wait(Timeout), openSslClient.Output);
            Assert.AreEqual(clientCert, established.Task.Result.ClientCertificate);
            Assert.AreEqual("server.test", established.Task.Result.ServerName);
            Assert.IsTrue(openSslClient.WaitForOutput("ALPN protocol: h2", Timeout), openSslClient.Output);
            Assert.IsTrue(openSslClient.WaitForOutput("Verify return code: 0 (ok)", Timeout), openSslClient.Output);
        }
    }
}
