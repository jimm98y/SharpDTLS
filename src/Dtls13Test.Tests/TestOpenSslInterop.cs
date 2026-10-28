using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.Protocol10;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol10.DTLS10;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Runs an OpenSSL command-line process and collects its output.
    /// </summary>
    internal sealed class OpenSslProcess : IDisposable
    {
        private readonly Process _process;
        private readonly StringBuilder _output = new();

        public OpenSslProcess(string arguments, string workingDirectory, string fileName = null)
        {
            _process = new Process
            {
                StartInfo = new ProcessStartInfo(fileName ?? OpenSsl.Path, arguments)
                {
                    WorkingDirectory = workingDirectory,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                },
            };
            _process.OutputDataReceived += (_, e) => { if (e.Data != null) lock (_output) _output.AppendLine(e.Data); };
            _process.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (_output) _output.AppendLine(e.Data); };
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        public string Output { get { lock (_output) return _output.ToString(); } }

        /// <summary>
        /// Starts a server on a free port and waits until it accepts. The probe in <see cref="OpenSsl.FreeUdpPort"/>
        /// can race with other binds during parallel runs, so a server that fails to bind is retried on a new port.
        /// </summary>
        public static OpenSslProcess StartServer(Func<int, string> arguments, string workingDirectory, TimeSpan timeout, out int port, string fileName = null)
        {
            for (int attempt = 1; ; attempt++)
            {
                port = OpenSsl.FreeUdpPort();
                var server = new OpenSslProcess(arguments(port), workingDirectory, fileName);
                if (server.WaitForOutput("ACCEPT", timeout) || attempt == 3 || !server.Output.Contains("in use"))
                    return server;
                server.Dispose();
            }
        }

        public bool WaitForOutput(string text, TimeSpan timeout)
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                if (Output.Contains(text))
                    return true;
                if (_process.HasExited)
                {
                    // The parameterless overload also waits for the async stdout/stderr readers to reach EOF,
                    // so the final lines (e.g. a bind error) are in Output before it is checked.
                    _process.WaitForExit();
                    return Output.Contains(text);
                }
                Thread.Sleep(20);
            }
            return false;
        }

        public void WriteLine(string line)
        {
            _process.StandardInput.Write(line + "\n");
            _process.StandardInput.Flush();
        }

        public void Dispose()
        {
            try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); } catch { }
            _process.Dispose();
        }
    }

    internal static class OpenSsl
    {
        private static readonly Lazy<string> _path = new(() =>
            new[] { "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl" }.FirstOrDefault(File.Exists));

        public static string Path => _path.Value;

        public static void RequireOpenSsl()
        {
            if (Path == null)
                Assert.Inconclusive("openssl is not installed");
        }

        // Ports for external processes come from a range below the OS ephemeral range (49152+ on macOS,
        // 32768+ on Linux), so sockets bound to port 0 elsewhere in the test run cannot take them between
        // the check and the external process binding.
        private static int _nextPort = 20000 + Environment.ProcessId % 5000;

        public static int FreeUdpPort()
        {
            while (true)
            {
                int port = 20000 + (Interlocked.Increment(ref _nextPort) - 20000) % 12000;
                try
                {
                    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
                    return port;
                }
                catch (SocketException)
                {
                    // in use, try the next one
                }
            }
        }

        public static string WritePem(string directory, string name, object value)
        {
            string path = System.IO.Path.Combine(directory, name);
            using var writer = new StreamWriter(path);
            new PemWriter(writer).WriteObject(value);
            return path;
        }

        public static string NewTempDirectory()
        {
            string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sharpdtls-interop-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestOpenSslInteropDtls12
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static (AsymmetricCipherKeyPair, X509Certificate) Credentials(bool ec)
            => ec ? SharpDTLS.Protocol13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate() : Dtls12CryptoUtils.GenerateSelfSignedCertificate();

        [DataRow("ECDHE-RSA-AES128-GCM-SHA256", false, "X25519")]
        [DataRow("ECDHE-RSA-AES256-GCM-SHA384", false, "P-256")]
        [DataRow("ECDHE-RSA-CHACHA20-POLY1305", false, "P-384")]
        [DataRow("ECDHE-ECDSA-AES128-GCM-SHA256", true, "X25519:P-256")]
        [DataRow("ECDHE-ECDSA-AES256-GCM-SHA384", true, "P-256")]
        [DataRow("ECDHE-ECDSA-CHACHA20-POLY1305", true, "P-384:P-256")]
        [TestMethod]
        public void SharpDtlsClient_To_OpenSslServer(string cipher, bool ecCertificate, string groups)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -cipher {cipher} -groups {groups} -msg", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(clientTransport);
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.ApplicationDataReceived += (_, data) => received.TrySetResult(Encoding.UTF8.GetString(data));

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);

            client.SendApplicationData(Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(server.WaitForOutput("hello-from-sharpdtls", Timeout), "s_server did not receive data:\n" + server.Output);

            server.WriteLine("hello-from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), "Client did not receive data:\n" + server.Output);
            StringAssert.Contains(received.Task.Result, "hello-from-openssl");
        }

        [DataRow("ECDHE-RSA-AES128-GCM-SHA256", false, "X25519")]
        [DataRow("ECDHE-RSA-AES256-GCM-SHA384", false, "P-256")]
        [DataRow("ECDHE-RSA-CHACHA20-POLY1305", false, "P-384")]
        [DataRow("ECDHE-ECDSA-AES128-GCM-SHA256", true, "X25519:P-256")]
        [DataRow("ECDHE-ECDSA-AES256-GCM-SHA384", true, "P-256")]
        [DataRow("ECDHE-ECDSA-CHACHA20-POLY1305", true, "P-384:P-256")]
        [TestMethod]
        public void OpenSslClient_To_SharpDtlsServer(string cipher, bool ecCertificate, string groups)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            int port = transport.LocalEndpoint.Port;
            var server = new Dtls12Server(transport, kp, cert);

            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<(EndPoint, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            server.ApplicationDataReceived += (_, e) => received.TrySetResult((e.RemoteEndPoint, Encoding.UTF8.GetString(e.Data)));

            using var client = new OpenSslProcess(
                $"s_client -dtls1_2 -connect 127.0.0.1:{port} -cipher {cipher} -groups {groups} -quiet", dir);

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);

            client.WriteLine("hello-from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), "Server did not receive data:\n" + client.Output);
            StringAssert.Contains(received.Task.Result.Item2, "hello-from-openssl");

            server.SendApplicationData(received.Task.Result.Item1, Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(client.WaitForOutput("hello-from-sharpdtls", Timeout), "s_client did not receive data:\n" + client.Output);
        }

        // CBC suites: OpenSSL negotiates encrypt_then_mac by default, so this also exercises RFC 7366.
        [DataRow("ECDHE-RSA-AES128-SHA256", false, true)]
        [DataRow("ECDHE-ECDSA-AES256-SHA384", true, true)]
        [DataRow("ECDHE-RSA-AES256-SHA", false, true)]
        [DataRow("ECDHE-RSA-AES128-SHA256", false, false)]
        [TestMethod]
        public void CbcSuites_BothDirections(string cipher, bool ecCertificate, bool encryptThenMac)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            string etm = encryptThenMac ? "" : " -no_etm";

            // SharpDTLS client -> OpenSSL server
            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -cipher {cipher}{etm}", dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport);
                var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
                client.Failed += (_, ex) => handshake.TrySetException(ex);
                client.BeginHandshake();
                Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);
                Assert.AreEqual(encryptThenMac, client.EncryptThenMacNegotiated);

                client.SendApplicationData(Encoding.UTF8.GetBytes("cbc-from-sharpdtls\n"));
                Assert.IsTrue(server.WaitForOutput("cbc-from-sharpdtls", Timeout), server.Output);
            }

            // OpenSSL client -> SharpDTLS server
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var sharpServer = new Dtls12Server(serverTransport, kp, cert);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            sharpServer.ApplicationDataReceived += (_, e) => received.TrySetResult(Encoding.UTF8.GetString(e.Data));
            using var openSslClient = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -cipher {cipher}{etm} -quiet", dir);
            openSslClient.WriteLine("cbc-from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), "Server did not receive data:\n" + openSslClient.Output);
            StringAssert.Contains(received.Task.Result, "cbc-from-openssl");
            Assert.AreEqual(encryptThenMac, sharpServer.Connections.Single().EncryptThenMacNegotiated);
        }

        [TestMethod]
        public void OpenSslAnyVersionClient_NegotiatesDtls12()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport) { MinimumVersion = DtlsVersion.Dtls10 };
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, _) => handshake.TrySetResult(true);

            using var client = new OpenSslProcess($"s_client -dtls -connect 127.0.0.1:{transport.LocalEndpoint.Port} -quiet", dir);
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);
            Assert.AreEqual(DtlsVersion.Dtls12, server.Connections.Single().NegotiatedVersion);
        }

        [DataRow("-dtls1_2", true)]
        [DataRow("-dtls1_2", false)]
        [DataRow("-dtls1", true)]
        [DataRow("-dtls1", false)]
        [TestMethod]
        public void OpenSslClient_ResumesSession_WithSharpDtlsServer(string versionFlag, bool tickets)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            string sessionFile = System.IO.Path.Combine(dir, "session.pem");
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport) { MinimumVersion = DtlsVersion.Dtls10 };
            var cache = new Dtls12SessionCache();
            server.SessionCache = cache;
            string connect = $"s_client {versionFlag} -cipher ECDHE-RSA-AES128-SHA@SECLEVEL=0 -connect 127.0.0.1:{transport.LocalEndpoint.Port}"
                + (tickets ? "" : " -no_ticket");

            using (var first = new OpenSslProcess($"{connect} -sess_out {sessionFile}", dir))
            {
                Assert.IsTrue(first.WaitForOutput("New, ", Timeout), "first handshake:\n" + first.Output);
                Assert.IsTrue(SpinWait.SpinUntil(() => System.IO.File.Exists(sessionFile) && new System.IO.FileInfo(sessionFile).Length > 0, Timeout));
                Assert.AreEqual(tickets, first.Output.Contains("TLS session ticket:"), "ticket issued:\n" + first.Output);
                Assert.AreEqual(tickets ? 0 : 1, cache.Count, "session ID sessions are cached, ticket sessions are not");
            }

            using var second = new OpenSslProcess($"{connect} -sess_in {sessionFile}", dir);
            Assert.IsTrue(second.WaitForOutput("Reused, ", Timeout), "OpenSSL did not resume:\n" + second.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsResumed && c.IsHandshakeComplete), Timeout));
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void SharpDtlsClient_ResumesSession_WithOpenSslServer(bool tickets)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(CertificateKeyType.Rsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", certificate);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", keyPair.Private);
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            Dtls12SessionState session;
            using (var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port)))
            {
                var client = Handshake(new Dtls12Client(transport) { UseSessionTickets = tickets }, server);
                Assert.IsFalse(client.IsResumed);
                session = client.SessionState;
                Assert.IsNotNull(session, "OpenSSL makes the session resumable");
                Assert.AreEqual(tickets, session.Ticket != null, "OpenSSL issues a ticket when the client supports them");
                client.Close();
            }
            Assert.IsTrue(server.WaitForOutput("DONE", Timeout), server.Output); // s_server finished the connection and accepts the next

            using (var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port)))
            {
                var client = Handshake(new Dtls12Client(transport) { ResumptionSession = session, UseSessionTickets = tickets }, server);
                Assert.IsTrue(client.IsResumed, "OpenSSL did not resume:\n" + server.Output);
                client.SendApplicationData(Encoding.UTF8.GetBytes("resumed\n"));
                Assert.IsTrue(server.WaitForOutput("resumed", Timeout), server.Output);
            }
        }

        private static Dtls12Client Handshake(Dtls12Client client, OpenSslProcess server)
        {
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "handshake did not complete:\n" + server.Output);
            return client;
        }

        [TestMethod]
        public void OpenSslFallbackClient_IsRejectedWithInappropriateFallback()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport) { MinimumVersion = DtlsVersion.Dtls10 };

            using var client = new OpenSslProcess(
                $"s_client -dtls1 -fallback_scsv -cipher DEFAULT@SECLEVEL=0 -connect 127.0.0.1:{transport.LocalEndpoint.Port} -quiet", dir);
            Assert.IsTrue(client.WaitForOutput("inappropriate fallback", Timeout), "expected inappropriate_fallback:\n" + client.Output);
            Assert.IsEmpty(server.Connections.Where(c => c.IsHandshakeComplete));
        }

        [TestMethod]
        public void SharpDtlsFallbackClient_To_OpenSslServer_IsRejected()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(CertificateKeyType.Rsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", certificate);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", keyPair.Private);
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -dtls -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -cipher DEFAULT@SECLEVEL=0", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new SharpDTLS.Protocol10.DTLS10.Dtls10Client(transport) { IsFallback = true };
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.Failed += (_, ex) => failed.TrySetResult(ex);
            client.HandshakeFinished += (_, _) => failed.TrySetResult(null);
            client.BeginHandshake();

            Assert.IsTrue(failed.Task.Wait(Timeout), "no result:\n" + server.Output);
            Assert.AreEqual(AlertDescription.InappropriateFallback, (failed.Task.Result as DtlsException)?.Alert, server.Output);
        }

        [TestMethod]
        public void SharpDtlsClient_WithClientCertificate_To_OpenSslServerRequiringIt()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (serverKp, serverCert) = Credentials(ec: false);
            var (clientKp, clientCert) = Credentials(ec: true);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", serverCert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", serverKp.Private);
            string caPath = OpenSsl.WritePem(dir, "client-ca.pem", clientCert);
            using var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -Verify 1 -CAfile {caPath} -verify_return_error", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(clientTransport)
            {
                ClientCertificate = clientCert,
                ClientCertificateKeyPair = clientKp,
            };
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);

            client.SendApplicationData(Encoding.UTF8.GetBytes("authenticated\n"));
            Assert.IsTrue(server.WaitForOutput("authenticated", Timeout), "s_server did not receive data:\n" + server.Output);
        }
    }

    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestOpenSslInteropDtls10
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static (AsymmetricCipherKeyPair, X509Certificate) Credentials(bool ec)
            => ec ? SharpDTLS.Protocol13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate() : Dtls10CryptoUtils.GenerateSelfSignedCertificate();

        // OpenSSL 3 only allows DTLS 1.0 (SHA-1 / MD5 based) at security level 0.
        [DataRow("ECDHE-RSA-AES128-SHA", false, "X25519")]
        [DataRow("ECDHE-RSA-AES256-SHA", false, "P-256")]
        [DataRow("ECDHE-ECDSA-AES128-SHA", true, "P-256")]
        [DataRow("ECDHE-ECDSA-AES256-SHA", true, "P-384:P-256")]
        [TestMethod]
        public void SharpDtlsClient_To_OpenSslServer(string cipher, bool ecCertificate, string groups)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -dtls1 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -cipher {cipher}@SECLEVEL=0 -groups {groups} -msg", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls10Client(clientTransport);
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.ApplicationDataReceived += (_, data) => received.TrySetResult(Encoding.UTF8.GetString(data));

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);

            client.SendApplicationData(Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(server.WaitForOutput("hello-from-sharpdtls", Timeout), "s_server did not receive data:\n" + server.Output);

            server.WriteLine("hello-from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), "Client did not receive data:\n" + server.Output);
            StringAssert.Contains(received.Task.Result, "hello-from-openssl");
        }

        [DataRow("ECDHE-RSA-AES128-SHA", false, "X25519")]
        [DataRow("ECDHE-RSA-AES256-SHA", false, "P-256")]
        [DataRow("ECDHE-ECDSA-AES128-SHA", true, "P-256")]
        [DataRow("ECDHE-ECDSA-AES256-SHA", true, "P-384:P-256")]
        [TestMethod]
        public void OpenSslClient_To_SharpDtlsServer(string cipher, bool ecCertificate, string groups)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            int port = transport.LocalEndpoint.Port;
            var server = new Dtls10Server(transport, kp, cert);

            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<(EndPoint, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            server.ApplicationDataReceived += (_, e) => received.TrySetResult((e.RemoteEndPoint, Encoding.UTF8.GetString(e.Data)));

            using var client = new OpenSslProcess(
                $"s_client -dtls1 -connect 127.0.0.1:{port} -cipher {cipher}@SECLEVEL=0 -groups {groups} -quiet", dir);

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);

            client.WriteLine("hello-from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), "Server did not receive data:\n" + client.Output);
            StringAssert.Contains(received.Task.Result.Item2, "hello-from-openssl");

            server.SendApplicationData(received.Task.Result.Item1, Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(client.WaitForOutput("hello-from-sharpdtls", Timeout), "s_client did not receive data:\n" + client.Output);
        }
    }
}
