using SharpDTLS;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Every implemented DTLS 1.0/1.2 cipher suite against OpenSSL in both directions, where OpenSSL
    /// (with its legacy provider) supports the suite.
    /// </summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestOpenSslCipherMatrix
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        internal static readonly Lazy<(Dictionary<ushort, string> Names, string Providers)> _openSsl = new(() =>
        {
            // The legacy provider adds SEED, IDEA and single DES; fall back to the default provider without it.
            foreach (string providers in new[] { "-provider legacy -provider default", "" })
            {
                var psi = new ProcessStartInfo(OpenSsl.Path, $"ciphers {providers} -V ALL:COMPLEMENTOFALL:@SECLEVEL=0")
                {
                    RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
                };
                using var p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0) continue;

                var names = new Dictionary<ushort, string>();
                foreach (Match m in Regex.Matches(output, @"0x([0-9A-F]{2}),0x([0-9A-F]{2}) - (\S+)"))
                    names[(ushort)((Convert.ToByte(m.Groups[1].Value, 16) << 8) | Convert.ToByte(m.Groups[2].Value, 16))] = m.Groups[3].Value;
                return (names, providers);
            }
            return (new Dictionary<ushort, string>(), "");
        });

        public static IEnumerable<object[]> ImplementedSuites
            => CipherSuites.All.Select(s => new object[] { s.Id, s.Name });

        private static (CipherSuiteInfo Suite, string OpenSslName, string VersionFlag, ushort Version) Prepare(ushort id)
        {
            OpenSsl.RequireOpenSsl();
            var suite = CipherSuites.Get(id);
            // BouncyCastle covers SRP instead (TestBouncyCastleInterop).
            if (suite.RequiresSrp)
                Assert.Inconclusive("OpenSSL 3.6 SRP is unusable from the command line: s_server stalls after the user lookup and s_client ignores -srppass");
            if (!_openSsl.Value.Names.TryGetValue(id, out string name))
                Assert.Inconclusive($"OpenSSL does not support {suite.Name}");
            bool dtls12 = suite.IsUsableWith(DtlsVersion.Dtls12);
            return (suite, name, dtls12 ? "-dtls1_2" : "-dtls1", dtls12 ? DtlsVersion.Dtls12 : DtlsVersion.Dtls10);
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void SharpDtlsClient_To_OpenSslServer(ushort id, string name)
        {
            var (suite, openSslName, versionFlag, version) = Prepare(id);
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(suite);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", certificate);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", keyPair.Private);
            string credentials = suite.ServerCertificateType == CertificateKeyType.None ? "-nocert" : $"-cert {certPath} -key {keyPath}";
            if (suite.RequiresPsk)
                credentials += $" -psk {Convert.ToHexString(TestCredentials.PskKey)} -psk_identity {Encoding.ASCII.GetString(TestCredentials.PskIdentity)} -psk_hint {Encoding.ASCII.GetString(TestCredentials.PskHint)}";

            using var server = OpenSslProcess.StartServer(p =>
                $"s_server {versionFlag} {_openSsl.Value.Providers} -accept 127.0.0.1:{p} {credentials} -cipher {openSslName}@SECLEVEL=0", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), "s_server did not start:\n" + server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(transport)
            {
                MinimumVersion = version,
                MaximumVersion = version,
                CipherSuites = new List<ushort> { id },
            };
            if (suite.RequiresPsk)
            {
                client.PskIdentity = TestCredentials.PskIdentity;
                client.PskKey = TestCredentials.PskKey;
            }
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.ApplicationDataReceived += (_, data) => received.TrySetResult(Encoding.UTF8.GetString(data));

            client.BeginHandshake();
            Assert.IsTrue(handshake.Task.Wait(Timeout), $"{name}: handshake did not complete:\n" + server.Output);
            Assert.AreEqual(id, client.CipherSuite.Id);

            client.SendApplicationData(Encoding.UTF8.GetBytes("from-sharpdtls\n"));
            Assert.IsTrue(server.WaitForOutput("from-sharpdtls", Timeout), $"{name}: s_server did not receive data:\n" + server.Output);
            server.WriteLine("from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: client did not receive data:\n" + server.Output);
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void OpenSslClient_To_SharpDtlsServer(ushort id, string name)
        {
            var (suite, openSslName, versionFlag, version) = Prepare(id);
            string dir = OpenSsl.NewTempDirectory();
            var (keyPair, certificate) = TestCredentials.For(suite);

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport, keyPair, certificate)
            {
                MinimumVersion = DtlsVersion.Dtls10,
                CipherSuites = new List<ushort> { id },
            };
            string psk = "";
            if (suite.RequiresPsk)
            {
                server.PskIdentityResolver = TestCredentials.ResolvePsk;
                server.PskIdentityHint = TestCredentials.PskHint;
                psk = $" -psk {Convert.ToHexString(TestCredentials.PskKey)} -psk_identity {Encoding.ASCII.GetString(TestCredentials.PskIdentity)}";
            }
            var received = new TaskCompletionSource<(EndPoint, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => received.TrySetResult((e.RemoteEndPoint, Encoding.UTF8.GetString(e.Data)));

            using var client = new OpenSslProcess(
                $"s_client {versionFlag} {_openSsl.Value.Providers} -connect 127.0.0.1:{transport.LocalEndpoint.Port} -cipher {openSslName}@SECLEVEL=0{psk} -quiet", dir);
            client.WriteLine("from-openssl");
            Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: server did not receive data:\n" + client.Output);
            Assert.AreEqual(id, server.Connections.Single().CipherSuite.Id);

            server.SendApplicationData(received.Task.Result.Item1, Encoding.UTF8.GetBytes("from-sharpdtls\n"));
            Assert.IsTrue(client.WaitForOutput("from-sharpdtls", Timeout), $"{name}: s_client did not receive data:\n" + client.Output);
        }
    }
}
