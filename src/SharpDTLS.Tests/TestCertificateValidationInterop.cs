using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>Certificate chains and host names checked by OpenSSL (DTLS 1.2) and wolfSSL (DTLS 1.3), and theirs by us.</summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestCertificateValidationInterop
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("Interop"));
        private static TestPki Pki => _pki.Value;

        private static (string Cert, string Key, string Chain, string Root) WriteCredentials(string dir)
        {
            var leaf = Pki.Leaf(new[] { "server.test" }, new[] { "127.0.0.1" });
            string cert = OpenSsl.WritePem(dir, "cert.pem", leaf.Cert);
            string key = OpenSsl.WritePem(dir, "key.pem", leaf.Key.Private);
            string intermediate = OpenSsl.WritePem(dir, "intermediate.pem", Pki.Intermediate.Cert);
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            string chain = Path.Combine(dir, "chain.pem");
            File.WriteAllText(chain, File.ReadAllText(cert) + File.ReadAllText(intermediate));
            return (cert, key, chain, root);
        }

        private static Exception Wait(Action begin, Action<Action> onSuccess, Action<Action<Exception>> onFailure, string peerOutput)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onSuccess(() => done.TrySetResult(null));
            onFailure(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed:\n" + peerOutput);
            return done.Task.Result;
        }

        [DataRow("server.test", null)]
        [DataRow("127.0.0.1", null)]
        [DataRow("evil.test", AlertDescription.BadCertificate)]
        [TestMethod]
        public void SharpDtlsClient_ValidatesOpenSslServerChain(string hostName, AlertDescription? expected)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var files = WriteCredentials(dir);
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {files.Cert} -key {files.Key} -cert_chain {Path.Combine(dir, "intermediate.pem")}",
                dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(transport) { ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer(hostName) };
            var error = Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), server.Output);
            Assert.AreEqual(expected, (error as DtlsException)?.Alert ?? (error == null ? null : AlertDescription.InternalError), error?.ToString());
        }

        [DataRow(true, "server.test", true)]
        [DataRow(false, "server.test", false)]  // without the intermediate OpenSSL cannot build the path
        [DataRow(true, "evil.test", false)]
        [TestMethod]
        public void OpenSslClient_ValidatesSharpDtlsServerChain(bool sendIntermediate, string hostName, bool accepted)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var leaf = Pki.Leaf(new[] { "server.test" });
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport, leaf.Key, leaf.Cert)
            {
                IntermediateCertificates = sendIntermediate ? new[] { Pki.Intermediate.Cert } : null,
            };

            using var client = new OpenSslProcess(
                $"s_client -dtls1_2 -connect 127.0.0.1:{transport.LocalEndpoint.Port} -CAfile {root} -verify_return_error -verify_hostname {hostName}", dir);
            if (accepted)
                Assert.IsTrue(client.WaitForOutput("Verify return code: 0 (ok)", Timeout), client.Output);
            else
                Assert.IsTrue(client.WaitForOutput("verify error", Timeout) || client.WaitForOutput("certificate verify failed", Timeout), client.Output);
        }

        [DataRow("server.test", null)]
        [DataRow("evil.test", AlertDescription.BadCertificate)]
        [TestMethod]
        public void SharpDtlsClient_ValidatesWolfSslServerChain(string hostName, AlertDescription? expected)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var files = WriteCredentials(dir);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {files.Chain} {files.Key}", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { ServerCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForServer(hostName) };
            var error = Wait(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), server.Output);
            Assert.AreEqual(expected, (error as DtlsException)?.Alert ?? (error == null ? null : AlertDescription.InternalError), error?.ToString());
        }

        [DataRow(true, "server.test", true)]
        [DataRow(false, "server.test", false)]
        [DataRow(true, "evil.test", false)]
        [TestMethod]
        public void WolfSslClient_ValidatesSharpDtlsServerChain(bool sendIntermediate, string hostName, bool accepted)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var leaf = Pki.Leaf(new[] { "server.test" });
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport, leaf.Key, leaf.Cert)
            {
                IntermediateCertificates = sendIntermediate ? new[] { Pki.Intermediate.Cert } : null,
            };

            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -verify {root} -host {hostName}", dir, WolfSsl.Harness);
            if (accepted)
                Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), client.Output);
            else
                Assert.IsTrue(client.WaitForOutput("ERROR connect", Timeout), client.Output);
        }
    }
}
