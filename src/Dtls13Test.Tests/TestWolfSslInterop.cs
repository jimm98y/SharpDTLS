using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Builds the wolfSSL-based DTLS 1.3 peer (Interop/wolfdtls13.c) on first use.
    /// </summary>
    internal static class WolfSsl
    {
        private static readonly Lazy<string> _harness = new(Build);

        public static string Harness => _harness.Value;

        public static void RequireWolfSsl()
        {
            if (Harness == null)
                Assert.Inconclusive("wolfSSL (with DTLS 1.3) or a C compiler is not available");
        }

        private static string Build()
        {
            string config = new[] { "/opt/homebrew/bin/wolfssl-config", "/usr/local/bin/wolfssl-config", "/usr/bin/wolfssl-config" }.FirstOrDefault(File.Exists);
            string source = Path.Combine(AppContext.BaseDirectory, "Interop", "wolfdtls13.c");
            if (config == null || !File.Exists(source))
                return null;

            string flags = Run(config, "--cflags --libs").Trim();
            if (flags == null)
                return null;

            string output = Path.Combine(OpenSsl.NewTempDirectory(), "wolfdtls13");
            Run("/usr/bin/cc", $"-O1 -o {output} {source} {flags}");
            return File.Exists(output) ? output : null;
        }

        private static string Run(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName, arguments) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                using var p = Process.Start(psi);
                string stdout = p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0 ? stdout : null;
            }
            catch
            {
                return null;
            }
        }
    }

    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestWolfSslInteropDtls13
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static (AsymmetricCipherKeyPair, X509Certificate) Credentials(bool ec)
            => ec ? Dtls13CryptoUtils.GenerateSelfSignedEcCertificate() : Dtls13CryptoUtils.GenerateSelfSignedCertificate();

        private static readonly Dictionary<string, ushort> SuiteIds = new()
        {
            ["TLS13-AES128-GCM-SHA256"] = 0x1301,
            ["TLS13-AES256-GCM-SHA384"] = 0x1302,
            ["TLS13-CHACHA20-POLY1305-SHA256"] = 0x1303,
        };

        [DataRow("TLS13-AES128-GCM-SHA256", false, false)]
        [DataRow("TLS13-AES256-GCM-SHA384", true, false)]
        [DataRow("TLS13-CHACHA20-POLY1305-SHA256", true, true)]
        [DataRow("TLS13-AES128-GCM-SHA256", true, true)]
        [TestMethod]
        public void SharpDtlsClient_To_WolfSslServer(string cipher, bool helloRetry, bool ecCertificate)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            int port = OpenSsl.FreeUdpPort();

            using var server = new OpenSslProcess($"server {port} {certPath} {keyPath} -cipher {cipher}{(helloRetry ? " -hrr" : "")}", dir, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport);
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new List<string>();
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.ApplicationDataReceived += (_, data) => { lock (received) received.Add(Encoding.UTF8.GetString(data)); };

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);
            Assert.AreEqual(SuiteIds[cipher], client.Session.CipherSuite.Id);
            Assert.IsTrue(server.WaitForOutput("CONNECTED", Timeout), server.Output);

            client.SendApplicationData(Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:hello-from-sharpdtls", Timeout), "server did not receive data:\n" + server.Output);

            server.WriteLine("hello-from-wolfssl");
            Assert.IsTrue(WaitFor(() => Contains(received, "hello-from-wolfssl")), "client did not receive data:\n" + server.Output);

            // wolfSSL-initiated KeyUpdate, then data in the new epoch
            server.WriteLine("KEYUPDATE");
            Assert.IsTrue(server.WaitForOutput("KEYUPDATE SENT", Timeout), server.Output);
            server.WriteLine("after-server-keyupdate");
            Assert.IsTrue(WaitFor(() => Contains(received, "after-server-keyupdate")), "client did not receive data after KeyUpdate:\n" + server.Output);

            // our KeyUpdate (with update_requested), then data in both directions
            client.SendKeyUpdate(requestUpdate: true);
            Assert.IsTrue(WaitFor(() => client.Session.WriteKeys.Epoch > 3), "client KeyUpdate was not acknowledged:\n" + server.Output);
            client.SendApplicationData(Encoding.UTF8.GetBytes("after-client-keyupdate\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:after-client-keyupdate", Timeout), server.Output);
            server.WriteLine("final");
            Assert.IsTrue(WaitFor(() => Contains(received, "final")), "client did not receive data after both KeyUpdates:\n" + server.Output);
        }

        [DataRow("TLS13-AES128-GCM-SHA256", true, "x25519")]
        [DataRow("TLS13-AES256-GCM-SHA384", false, "x25519")]
        [DataRow("TLS13-CHACHA20-POLY1305-SHA256", true, "x25519")]
        [DataRow("TLS13-AES128-GCM-SHA256", false, "p256")]   // server must ask for an x25519 share
        [DataRow("TLS13-AES256-GCM-SHA384", true, "p256")]
        [TestMethod]
        public void WolfSslClient_To_SharpDtlsServer(string cipher, bool helloRetry, string group)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport) { ShouldSendHelloRetry = helloRetry };

            var handshake = new TaskCompletionSource<Dtls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new List<string>();
            server.HandshakeFinished += (_, e) => handshake.TrySetResult(((Dtls13ConnectionEventArgs)e).Connection);
            server.ApplicationDataReceived += (_, e) => { lock (received) received.Add(Encoding.UTF8.GetString(e.Data)); };

            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -cipher {cipher} -group {group}", dir, WolfSsl.Harness);

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);
            var connection = handshake.Task.Result;
            Assert.AreEqual(SuiteIds[cipher], connection.Session.CipherSuite.Id);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), client.Output);

            client.WriteLine("hello-from-wolfssl");
            Assert.IsTrue(WaitFor(() => Contains(received, "hello-from-wolfssl")), "server did not receive data:\n" + client.Output);

            connection.SendApplicationData(Encoding.UTF8.GetBytes("hello-from-sharpdtls\n"));
            Assert.IsTrue(client.WaitForOutput("RECV:hello-from-sharpdtls", Timeout), "client did not receive data:\n" + client.Output);

            client.WriteLine("KEYUPDATE");
            client.WriteLine("after-client-keyupdate");
            Assert.IsTrue(WaitFor(() => Contains(received, "after-client-keyupdate")), "server did not receive data after KeyUpdate:\n" + client.Output);

            connection.SendKeyUpdate(requestUpdate: true);
            Assert.IsTrue(WaitFor(() => connection.Session.WriteKeys.Epoch > 3), "server KeyUpdate was not acknowledged:\n" + client.Output);
            connection.SendApplicationData(Encoding.UTF8.GetBytes("after-server-keyupdate\n"));
            Assert.IsTrue(client.WaitForOutput("RECV:after-server-keyupdate", Timeout), client.Output);
        }

        [TestMethod]
        public void SharpDtlsClient_WithClientCertificate_To_WolfSslServerRequiringIt()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (serverKp, serverCert) = Credentials(ec: false);
            var (clientKp, clientCert) = Credentials(ec: true);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", serverCert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", serverKp.Private);
            string caPath = OpenSsl.WritePem(dir, "client-ca.pem", clientCert);
            int port = OpenSsl.FreeUdpPort();

            using var server = new OpenSslProcess($"server {port} {certPath} {keyPath} -hrr -verify {caPath}", dir, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { ClientCertificate = clientCert, ClientCertificateKeyPair = clientKp };
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);
            Assert.IsTrue(server.WaitForOutput("CONNECTED", Timeout), "server rejected the client certificate:\n" + server.Output);

            client.SendApplicationData(Encoding.UTF8.GetBytes("authenticated\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:authenticated", Timeout), server.Output);
        }

        [TestMethod]
        public void WolfSslClient_WithClientCertificate_To_SharpDtlsServerRequiringIt()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (clientKp, clientCert) = Credentials(ec: false);
            string certPath = OpenSsl.WritePem(dir, "client.pem", clientCert);
            string keyPath = OpenSsl.WritePem(dir, "client-key.pem", clientKp.Private);

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport) { RequireClientCertificate = true };
            var handshake = new TaskCompletionSource<Dtls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, e) => handshake.TrySetResult(((Dtls13ConnectionEventArgs)e).Connection);

            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -cert {certPath} -key {keyPath}", dir, WolfSsl.Harness);

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);
            Assert.AreEqual(clientCert, handshake.Task.Result.ClientCertificate);
        }

        private static bool Contains(List<string> list, string text)
        {
            lock (list) return list.Any(s => s.Contains(text));
        }

        private static bool WaitFor(Func<bool> condition)
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < Timeout)
            {
                if (condition()) return true;
                System.Threading.Thread.Sleep(20);
            }
            return condition();
        }
    }
}
