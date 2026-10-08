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
            ["TLS13-AES128-CCM-SHA256"] = 0x1304,
            ["TLS13-AES128-CCM-8-SHA256"] = 0x1305,
            ["TLS13-SHA256-SHA256"] = 0xC0B4,
            ["TLS13-SHA384-SHA384"] = 0xC0B5,
        };

        [DataRow("TLS13-AES128-GCM-SHA256", false, false)]
        [DataRow("TLS13-AES256-GCM-SHA384", true, false)]
        [DataRow("TLS13-CHACHA20-POLY1305-SHA256", true, true)]
        [DataRow("TLS13-AES128-GCM-SHA256", true, true)]
        [DataRow("TLS13-AES128-CCM-SHA256", true, false)]
        [DataRow("TLS13-AES128-CCM-8-SHA256", true, false)]
        [DataRow("TLS13-SHA256-SHA256", true, false)]
        [DataRow("TLS13-SHA384-SHA384", false, true)]
        [TestMethod]
        public void SharpDtlsClient_To_WolfSslServer(string cipher, bool helloRetry, bool ecCertificate)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ecCertificate);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -cipher {cipher}{(helloRetry ? " -hrr" : "")}", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { CipherSuites = new List<ushort> { SuiteIds[cipher] } };
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
        [DataRow("TLS13-AES128-CCM-SHA256", true, "x25519")]
        [DataRow("TLS13-AES128-CCM-8-SHA256", false, "p256")]
        [DataRow("TLS13-SHA256-SHA256", true, "x25519")]
        [DataRow("TLS13-SHA384-SHA384", true, "x25519")]
        [TestMethod]
        public void WolfSslClient_To_SharpDtlsServer(string cipher, bool helloRetry, string group)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport) { ShouldSendHelloRetry = helloRetry, CipherSuites = new List<ushort> { SuiteIds[cipher] } };

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

        [DataRow("TLS13-AES128-GCM-SHA256", true)]
        [DataRow("TLS13-AES256-GCM-SHA384", false)]
        [DataRow("TLS13-CHACHA20-POLY1305-SHA256", false)]
        [TestMethod]
        public void WolfSslClient_ResumesWithTicket_FromSharpDtlsServer(string cipher, bool helloRetry)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport) { ShouldSendHelloRetry = helloRetry, CipherSuites = new List<ushort> { SuiteIds[cipher] } };

            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -cipher {cipher} -resume", dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("RESUMED", Timeout), "second handshake did not complete:\n" + client.Output);
            Assert.DoesNotContain("NOT RESUMED", client.Output, "wolfSSL did not resume:\n" + client.Output);
            Assert.IsTrue(WaitFor(() => server.Connections.Any(c => c.IsResumed && c.IsHandshakeComplete)), "server did not resume:\n" + client.Output);

            client.WriteLine("after-resumption");
            var connection = server.Connections.First(c => c.IsResumed);
            var received = new List<string>();
            server.ApplicationDataReceived += (_, e) => { lock (received) received.Add(Encoding.UTF8.GetString(e.Data)); };
            Assert.IsTrue(WaitFor(() => Contains(received, "after-resumption")), client.Output);
        }

        [DataRow("TLS13-AES128-GCM-SHA256", true)]
        [DataRow("TLS13-AES256-GCM-SHA384", false)]
        [TestMethod]
        public void SharpDtlsClient_ResumesWithTicket_FromWolfSslServer(string cipher, bool helloRetry)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Credentials(ec: true);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -cipher {cipher} -resume{(helloRetry ? " -hrr" : "")}",
                dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "server did not start:\n" + server.Output);

            Dtls13SessionTicket ticket;
            using (var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port)))
            {
                var first = Handshake(new Dtls13Client(transport) { CipherSuites = new List<ushort> { SuiteIds[cipher] } }, server);
                Assert.IsTrue(WaitFor(() => first.SessionTicket != null), "wolfSSL issued no ticket:\n" + server.Output);
                ticket = first.SessionTicket;
                Assert.IsFalse(first.IsResumed);
                first.Close();
            }

            using (var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port)))
            {
                var second = Handshake(new Dtls13Client(transport) { CipherSuites = new List<ushort> { SuiteIds[cipher] }, ResumptionTicket = ticket }, server);
                Assert.IsTrue(second.IsResumed, "wolfSSL did not accept the ticket:\n" + server.Output);
                Assert.IsTrue(server.WaitForOutput("RESUMED", Timeout), server.Output);
                Assert.DoesNotContain("NOT RESUMED", server.Output);
                second.SendApplicationData(Encoding.UTF8.GetBytes("after-resumption\n"));
                Assert.IsTrue(server.WaitForOutput("RECV:after-resumption", Timeout), server.Output);
            }
        }

        private const string PskHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        private const string PskIdentity = "device-17";

        [DataRow("TLS13-AES128-GCM-SHA256", false, true)]
        [DataRow("TLS13-AES128-GCM-SHA256", true, false)]
        [DataRow("TLS13-AES256-GCM-SHA384", false, false)]
        [DataRow("TLS13-AES256-GCM-SHA384", true, true)]
        [TestMethod]
        public void WolfSslClient_WithExternalPsk_To_SharpDtlsServer(string cipher, bool pskOnly, bool helloRetry)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            ushort suite = SuiteIds[cipher];
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport)
            {
                ShouldSendHelloRetry = helloRetry,
                CipherSuites = new List<ushort> { suite },
                AllowPskOnlyKeyExchange = pskOnly,
                ExternalPskResolver = id => Encoding.ASCII.GetString(id) == PskIdentity
                    ? new Dtls13ExternalPsk(id, Convert.FromHexString(PskHex), suite) : null,
            };
            var received = new List<string>();
            server.ApplicationDataReceived += (_, e) => { lock (received) received.Add(Encoding.UTF8.GetString(e.Data)); };

            using var client = new OpenSslProcess(
                $"client {transport.LocalEndpoint.Port} -cipher {cipher} -psk {PskHex} -psk_identity {PskIdentity}{(pskOnly ? " -psk_only" : "")}",
                dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), "handshake did not complete:\n" + client.Output);
            Assert.IsTrue(WaitFor(() => server.Connections.Any(c => c.IsHandshakeComplete)), client.Output);
            var connection = server.Connections.Single();
            Assert.IsTrue(connection.IsExternalPsk, "the server authenticated with a certificate instead");
            Assert.AreEqual(pskOnly, connection.IsPskOnlyKeyExchange);

            client.WriteLine("over-psk");
            Assert.IsTrue(WaitFor(() => Contains(received, "over-psk")), client.Output);
            connection.SendApplicationData(Encoding.UTF8.GetBytes("back\n"));
            Assert.IsTrue(client.WaitForOutput("RECV:back", Timeout), client.Output);
        }

        [DataRow("TLS13-AES128-GCM-SHA256", false, true)]
        [DataRow("TLS13-AES128-GCM-SHA256", true, false)]
        [DataRow("TLS13-AES256-GCM-SHA384", true, true)]
        [TestMethod]
        public void SharpDtlsClient_WithExternalPsk_To_WolfSslServer(string cipher, bool pskOnly, bool helloRetry)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            ushort suite = SuiteIds[cipher];
            var (kp, cert) = Credentials(ec: true);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p =>
                $"server {p} {certPath} {keyPath} -cipher {cipher} -psk {PskHex} -psk_identity {PskIdentity}{(pskOnly ? " -psk_only" : "")}{(helloRetry ? " -hrr" : "")}",
                dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = Handshake(new Dtls13Client(transport)
            {
                CipherSuites = new List<ushort> { suite },
                ExternalPsk = new Dtls13ExternalPsk(Encoding.ASCII.GetBytes(PskIdentity), Convert.FromHexString(PskHex), suite),
                PskKeyExchangeModes = pskOnly ? new[] { PskKeyExchangeModesExtension.PskKe } : new[] { PskKeyExchangeModesExtension.PskDheKe },
            }, server);
            Assert.IsTrue(client.IsExternalPsk, "wolfSSL did not accept the PSK:\n" + server.Output);
            Assert.IsNull(client.ServerCertificate);

            client.SendApplicationData(Encoding.UTF8.GetBytes("over-psk\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:over-psk", Timeout), server.Output);
        }

        private static Dtls13Client Handshake(Dtls13Client client, OpenSslProcess peer)
        {
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "handshake did not complete:\n" + peer.Output);
            return client;
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
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -hrr -verify {caPath}", dir, Timeout, out int port, WolfSsl.Harness);
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
