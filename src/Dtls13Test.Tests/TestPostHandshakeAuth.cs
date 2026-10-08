using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.3 post-handshake client authentication (RFC 8446 §4.6.2, RFC 9147 §5.8).</summary>
    [TestClass]
    public sealed class TestPostHandshakeAuth
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("PHA"));
        private static TestPki Pki => _pki.Value;

        private sealed class Setup
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public Dtls13ServerConnection Connection;
            public readonly List<string> ServerReceived = new();
            public readonly TaskCompletionSource<Exception> ServerFailed = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly TaskCompletionSource<Exception> ClientFailed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private static Setup Connect(bool allow = true, bool withCertificate = true, Func<X509Certificate, IReadOnlyList<byte[]>, bool> validator = null,
            Action<Dtls13Server, Dtls13Client> configure = null)
        {
            var s = new Setup();
            s.Server = new Dtls13Server(s.Pair.Server) { ClientCertificateValidator = validator ?? new CertificateValidator(new[] { Pki.Root.Cert }).ForClient() };
            s.Server.ApplicationDataReceived += (_, e) => { lock (s.ServerReceived) s.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            s.Client = new Dtls13Client(s.Pair.Client) { AllowPostHandshakeAuthentication = allow };
            if (withCertificate)
            {
                (s.Client.ClientCertificateKeyPair, s.Client.ClientCertificate) = Pki.Leaf(commonName: "pha client", usage: KeyPurposeID.id_kp_clientAuth);
                s.Client.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
            }
            configure?.Invoke(s.Server, s.Client);
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            s.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            s.Client.Failed += (_, ex) => { done.TrySetException(ex); s.ClientFailed.TrySetResult(ex); };
            s.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => s.Server.Connections.SingleOrDefault()?.IsHandshakeComplete == true, Timeout));
            s.Connection = s.Server.Connections.Single();
            s.Connection.Failed += (_, ex) => s.ServerFailed.TrySetResult(ex);
            return s;
        }

        private static bool Authenticate(Setup s, bool required = true)
        {
            var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler handler = (_, _) => completed.TrySetResult(true);
            s.Connection.PostHandshakeAuthenticationCompleted += handler;
            s.Connection.RequestClientCertificate(required);
            bool result = Task.WhenAny(completed.Task, s.ServerFailed.Task, s.ClientFailed.Task).Wait(Timeout) && completed.Task.IsCompleted;
            s.Connection.PostHandshakeAuthenticationCompleted -= handler;
            return result;
        }

        private static void AssertDataFlows(Setup s, string text)
        {
            s.Client.SendApplicationData(Encoding.UTF8.GetBytes(text));
            Assert.IsTrue(SpinWait.SpinUntil(() => { lock (s.ServerReceived) return s.ServerReceived.Contains(text); }, Timeout));
        }

        [TestMethod]
        public void ClientAnswersWithItsCertificate()
        {
            var s = Connect();
            Assert.IsTrue(s.Connection.AllowsPostHandshakeAuthentication);
            Assert.IsNull(s.Connection.ClientCertificate);
            Assert.IsTrue(Authenticate(s), s.ServerFailed.Task.IsCompleted ? s.ServerFailed.Task.Result.ToString() : "no answer");
            Assert.AreEqual(s.Client.ClientCertificate, s.Connection.ClientCertificate);
            AssertDataFlows(s, "after authentication");
        }

        [TestMethod]
        public void RequestsCanBeRepeated_ButNotOverlap()
        {
            var s = Connect(configure: (server, client) => { server.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50); client.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50); });
            Assert.IsTrue(Authenticate(s));

            // Hold the client's answer back so the request stays outstanding.
            s.Pair.ClientToServer = _ => Array.Empty<byte[]>();
            var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            s.Connection.PostHandshakeAuthenticationCompleted += (_, _) => completed.TrySetResult(true);
            s.Connection.RequestClientCertificate();
            Assert.ThrowsExactly<InvalidOperationException>(() => s.Connection.RequestClientCertificate());
            s.Pair.ClientToServer = d => new[] { d };
            Assert.IsTrue(completed.Task.Wait(Timeout), "the retransmitted answer did not complete the request");

            Assert.IsTrue(Authenticate(s));
            AssertDataFlows(s, "after three requests");
        }

        [TestMethod]
        public void WithoutCertificate_RequiredFails_OptionalCompletes()
        {
            var s = Connect(withCertificate: false);
            Assert.IsTrue(Authenticate(s, required: false));
            Assert.IsNull(s.Connection.ClientCertificate);
            AssertDataFlows(s, "still connected");

            Assert.IsFalse(Authenticate(s, required: true));
            Assert.AreEqual(AlertDescription.CertificateRequired, (s.ServerFailed.Task.Result as DtlsException)?.Alert);
        }

        [TestMethod]
        public void RejectedCertificate_IsBadCertificate()
        {
            var s = Connect(validator: (_, _) => false);
            Assert.IsFalse(Authenticate(s));
            Assert.AreEqual(AlertDescription.BadCertificate, (s.ServerFailed.Task.Result as DtlsException)?.Alert);
        }

        [TestMethod]
        public void ClientThatDidNotOffer_CannotBeAsked()
        {
            var s = Connect(allow: false);
            Assert.IsFalse(s.Connection.AllowsPostHandshakeAuthentication);
            Assert.ThrowsExactly<InvalidOperationException>(() => s.Connection.RequestClientCertificate());
        }

        [TestMethod]
        public void LostClientFlight_IsRetransmitted()
        {
            var s = Connect(configure: (server, client) => { server.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50); client.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50); });
            // Drop the client's first two datagrams after the handshake: the ACK of the request and the first Certificate.
            int dropped = 0;
            s.Pair.ClientToServer = d => Interlocked.Increment(ref dropped) <= 2 ? Array.Empty<byte[]>() : new[] { d };
            Assert.IsTrue(Authenticate(s), s.ServerFailed.Task.IsCompleted ? s.ServerFailed.Task.Result.ToString() : "no answer");
            Assert.IsNotNull(s.Connection.ClientCertificate);
        }

        [TestMethod]
        public void RawPublicKey_AndCompression()
        {
            var key = TestPki.NewKey();
            byte[] spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.Public).GetEncoded();
            var s = Connect(withCertificate: false, configure: (server, client) =>
            {
                server.ClientCertificateTypes = new[] { CertificateType.RawPublicKey };
                server.ClientRawPublicKeyValidator = k => k.AsSpan().SequenceEqual(spki);
                client.ClientCertificateTypes = new[] { CertificateType.RawPublicKey };
                client.ClientCertificateKeyPair = key;
            });
            Assert.IsTrue(Authenticate(s), s.ServerFailed.Task.IsCompleted ? s.ServerFailed.Task.Result.ToString() : "no answer");
            CollectionAssert.AreEqual(spki, s.Connection.ClientRawPublicKey);

            var c = Connect(configure: (_, client) => client.CertificateCompressionAlgorithms = new[] { CertificateCompression.Brotli });
            Assert.IsTrue(Authenticate(c));
            Assert.AreEqual(CertificateCompression.Brotli, c.Connection.CertificateCompressionAlgorithm);
        }

        // ── wolfSSL ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSslClient_AnswersSharpDtlsRequest()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Pki.Leaf(commonName: "wolf client", usage: KeyPurposeID.id_kp_clientAuth);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            System.IO.File.AppendAllText(certPath, System.IO.File.ReadAllText(OpenSsl.WritePem(dir, "intermediate.pem", Pki.Intermediate.Cert)));

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport) { ClientCertificateValidator = new CertificateValidator(new[] { Pki.Root.Cert }).ForClient() };
            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -pha -cert {certPath} -key {keyPath}", dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput("CONNECTED", Timeout), client.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            var connection = server.Connections.Single();
            Assert.IsTrue(connection.AllowsPostHandshakeAuthentication);

            var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.PostHandshakeAuthenticationCompleted += (_, _) => completed.TrySetResult(true);
            connection.RequestClientCertificate();
            Assert.IsTrue(completed.Task.Wait(Timeout), client.Output);
            Assert.AreEqual(cert, connection.ClientCertificate);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void SharpDtlsClient_AnswersWolfSslRequest()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (serverKey, serverCert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", serverCert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", serverKey.Private);
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -verify {root} -pha", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { AllowPostHandshakeAuthentication = true };
            (client.ClientCertificateKeyPair, client.ClientCertificate) = Pki.Leaf(commonName: "sharp client", usage: KeyPurposeID.id_kp_clientAuth);
            client.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var requested = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.PostHandshakeCertificateRequested += (_, _) => requested.TrySetResult(true);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), server.Output);
            Assert.IsTrue(server.WaitForOutput("CONNECTED", Timeout), server.Output);

            server.WriteLine("PEER");
            Assert.IsTrue(server.WaitForOutput("PEER:no", Timeout), server.Output);
            server.WriteLine("REQCERT");
            Assert.IsTrue(requested.Task.Wait(Timeout), server.Output);
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping\n"));
            Assert.IsTrue(server.WaitForOutput("RECV:ping", Timeout), server.Output);
            server.WriteLine("PEER");
            Assert.IsTrue(server.WaitForOutput("PEER:yes", Timeout), server.Output);
        }
    }
}
