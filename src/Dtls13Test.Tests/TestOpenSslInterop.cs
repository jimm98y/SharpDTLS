using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10;
using SharpDTLS.DTLS12;
using SharpSRTP.UDP;
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

        public bool WaitForOutput(string text, TimeSpan timeout)
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                if (Output.Contains(text))
                    return true;
                if (_process.HasExited)
                    return Output.Contains(text);
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

        public static int FreeUdpPort()
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)socket.LocalEndPoint).Port;
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
            => ec ? SharpDTLS.DTLS13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate() : Dtls12CryptoUtils.GenerateSelfSignedCertificate();

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
            int port = OpenSsl.FreeUdpPort();

            using var server = new OpenSslProcess(
                $"s_server -dtls1_2 -accept 127.0.0.1:{port} -cert {certPath} -key {keyPath} -cipher {cipher} -groups {groups} -msg", dir);
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
            int port = OpenSsl.FreeUdpPort();

            using var server = new OpenSslProcess(
                $"s_server -dtls1_2 -accept 127.0.0.1:{port} -cert {certPath} -key {keyPath} -Verify 1 -CAfile {caPath} -verify_return_error", dir);
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
            => ec ? SharpDTLS.DTLS13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate() : Dtls10CryptoUtils.GenerateSelfSignedCertificate();

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
            int port = OpenSsl.FreeUdpPort();

            using var server = new OpenSslProcess(
                $"s_server -dtls1 -accept 127.0.0.1:{port} -cert {certPath} -key {keyPath} -cipher {cipher}@SECLEVEL=0 -groups {groups} -msg", dir);
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
