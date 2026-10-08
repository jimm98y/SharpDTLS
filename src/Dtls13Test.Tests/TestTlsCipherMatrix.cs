using SharpDTLS;
using SharpDTLS.TLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Every implemented TLS 1.1/1.2 cipher suite against OpenSSL over TCP in both directions: TLS 1.2 where the suite
    /// is defined for it, otherwise TLS 1.1.
    /// </summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestTlsCipherMatrix
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        public static IEnumerable<object[]> ImplementedSuites => CipherSuites.All.Select(s => new object[] { s.Id, s.Name });

        /// <summary>The suites TLS 1.0 allows (no AEAD or SHA-256 MACs): its chained CBC IVs and the 1/n-1 split.</summary>
        public static IEnumerable<object[]> Tls10Suites => CipherSuites.All.Where(s => s.IsUsableWith(TlsVersion.Tls10)).Select(s => new object[] { s.Id, s.Name });

        private static (CipherSuiteInfo Suite, string OpenSslName, string VersionFlag, ushort Version) Prepare(ushort id, bool tls10 = false)
        {
            OpenSsl.RequireOpenSsl();
            var suite = CipherSuites.Get(id);
            if (suite.RequiresSrp)
                Assert.Inconclusive("OpenSSL 3.6 SRP is unusable from the command line");
            if (!TestOpenSslCipherMatrix._openSsl.Value.Names.TryGetValue(id, out string name))
                Assert.Inconclusive($"OpenSSL does not support {suite.Name}");
            if (tls10)
                return (suite, name, "-tls1", TlsVersion.Tls10);
            bool tls12 = suite.IsUsableWith(TlsVersion.Tls12);
            return (suite, name, tls12 ? "-tls1_2" : "-tls1_1", tls12 ? TlsVersion.Tls12 : TlsVersion.Tls11);
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void SharpTlsClient_To_OpenSslServer(ushort id, string name) => ClientToServer(id, name, tls10: false);

        [DynamicData(nameof(Tls10Suites))]
        [TestMethod]
        public void Tls10_SharpTlsClient_To_OpenSslServer(ushort id, string name) => ClientToServer(id, name, tls10: true);

        private static void ClientToServer(ushort id, string name, bool tls10)
        {
            var (suite, openSslName, versionFlag, version) = Prepare(id, tls10);
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(suite);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", certificate);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", keyPair.Private);
            string credentials = suite.ServerCertificateType == CertificateKeyType.None ? "-nocert" : $"-cert {certPath} -key {keyPath}";
            if (suite.RequiresPsk)
                credentials += $" -psk {Convert.ToHexString(TestCredentials.PskKey)} -psk_identity {Encoding.ASCII.GetString(TestCredentials.PskIdentity)} -psk_hint {Encoding.ASCII.GetString(TestCredentials.PskHint)}";

            using var server = OpenSslProcess.StartServer(p =>
                $"s_server {versionFlag} {TestOpenSslCipherMatrix._openSsl.Value.Providers} -accept 127.0.0.1:{p} {credentials} -cipher {openSslName}@SECLEVEL=0",
                dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            var client = TestTls12.Connect(new IPEndPoint(IPAddress.Loopback, port), c =>
            {
                c.MinimumVersion = version;
                c.MaximumVersion = version;
                c.CipherSuites = new List<ushort> { id };
                if (suite.RequiresPsk)
                {
                    c.PskIdentity = TestCredentials.PskIdentity;
                    c.PskKey = TestCredentials.PskKey;
                }
            });
            Assert.AreEqual(id, client.CipherSuite.Id);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, data) => received.TrySetResult(Encoding.UTF8.GetString(data));
            client.SendApplicationData(Encoding.UTF8.GetBytes("from-sharptls\n"));
            Assert.IsTrue(server.WaitForOutput("from-sharptls", Timeout), $"{name}: s_server did not receive data:\n" + server.Output);
            server.WriteLine("from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: client did not receive data:\n" + server.Output);
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void OpenSslClient_To_SharpTlsServer(ushort id, string name) => ServerFromClient(id, name, tls10: false);

        [DynamicData(nameof(Tls10Suites))]
        [TestMethod]
        public void Tls10_OpenSslClient_To_SharpTlsServer(ushort id, string name) => ServerFromClient(id, name, tls10: true);

        private static void ServerFromClient(ushort id, string name, bool tls10)
        {
            var (suite, openSslName, versionFlag, _) = Prepare(id, tls10);
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(suite);

            using var server = new Tls12Server(keyPair, certificate) { MinimumVersion = TlsVersion.Tls10, CipherSuites = new List<ushort> { id } };
            string psk = "";
            if (suite.RequiresPsk)
            {
                server.PskIdentityResolver = TestCredentials.ResolvePsk;
                server.PskIdentityHint = TestCredentials.PskHint;
                psk = $" -psk {Convert.ToHexString(TestCredentials.PskKey)} -psk_identity {Encoding.ASCII.GetString(TestCredentials.PskIdentity)}";
            }
            var received = new TaskCompletionSource<(SharpDTLS.DTLS12.Tls12ServerConnection, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => received.TrySetResult((e.Connection, Encoding.UTF8.GetString(e.Data)));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            using var client = new OpenSslProcess(
                $"s_client {versionFlag} {TestOpenSslCipherMatrix._openSsl.Value.Providers} -connect 127.0.0.1:{server.LocalEndpoint.Port} -cipher {openSslName}@SECLEVEL=0{psk} -quiet", dir);
            client.WriteLine("from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: server did not receive data:\n" + client.Output);
            Assert.AreEqual(id, received.Task.Result.Item1.CipherSuite.Id);
            received.Task.Result.Item1.SendApplicationData(Encoding.UTF8.GetBytes("from-sharptls\n"));
            Assert.IsTrue(client.WaitForOutput("from-sharptls", Timeout), $"{name}: s_client did not receive data:\n" + client.Output);
        }
    }
}
