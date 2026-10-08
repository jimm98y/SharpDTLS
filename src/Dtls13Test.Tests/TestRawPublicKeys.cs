using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Dtls13Test.Tests
{
    /// <summary>Raw public keys (RFC 7250) in both engines, for server and client authentication.</summary>
    [TestClass]
    public sealed class TestRawPublicKeys
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly CertificateType[] Rpk = { CertificateType.RawPublicKey };

        private static byte[] Spki(AsymmetricCipherKeyPair key) => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.Public).GetEncoded();

        private sealed class Options
        {
            public AsymmetricCipherKeyPair ServerKey = TestPki.NewKey();
            public X509Certificate ServerCertificate;
            public CertificateType[] ServerTypes = Rpk;
            public CertificateType[] ClientAcceptsServer = Rpk;
            public Func<byte[], bool> ServerKeyCheck;
            public bool RequireClientAuth;
            public CertificateType[] ServerAcceptsClient;
            public Func<byte[], bool> ClientKeyCheck;
            public CertificateType[] ClientTypes;
            public AsymmetricCipherKeyPair ClientKey;
        }

        private sealed record Outcome(Exception ClientError, Exception ServerError, DtlsConnectionBase Client, DtlsConnectionBase Server);

        private static Outcome Run(int version, Options o)
        {
            var pair = new ScriptedTransportPair();
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            var lateFailure = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            DtlsConnectionBase client;
            Func<DtlsConnectionBase> server;
            if (version == 12)
            {
                var s = new Dtls12Server(pair.Server, o.ServerKey, o.ServerCertificate)
                {
                    ServerCertificateTypes = o.ServerTypes, RequireClientCertificate = o.RequireClientAuth,
                    ClientCertificateTypes = o.ServerAcceptsClient, ClientRawPublicKeyValidator = o.ClientKeyCheck,
                };
                var c = new Dtls12Client(pair.Client)
                {
                    ServerCertificateTypes = o.ClientAcceptsServer, ServerRawPublicKeyValidator = o.ServerKeyCheck,
                    ClientCertificateTypes = o.ClientTypes, ClientCertificateKeyPair = o.ClientKey,
                };
                c.HandshakeFinished += (_, _) => done.TrySetResult(null);
                c.Failed += (_, ex) => { done.TrySetResult(ex); lateFailure.TrySetResult(ex); };
                c.BeginHandshake();
                (client, server) = (c, () => s.Connections.SingleOrDefault());
            }
            else
            {
                var s = new Dtls13Server(pair.Server, o.ServerKey, o.ServerCertificate)
                {
                    ServerCertificateTypes = o.ServerTypes, RequireClientCertificate = o.RequireClientAuth,
                    ClientCertificateTypes = o.ServerAcceptsClient, ClientRawPublicKeyValidator = o.ClientKeyCheck,
                };
                var c = new Dtls13Client(pair.Client)
                {
                    ServerCertificateTypes = o.ClientAcceptsServer, ServerRawPublicKeyValidator = o.ServerKeyCheck,
                    ClientCertificateTypes = o.ClientTypes, ClientCertificateKeyPair = o.ClientKey,
                };
                c.HandshakeFinished += (_, _) => done.TrySetResult(null);
                c.Failed += (_, ex) => { done.TrySetResult(ex); lateFailure.TrySetResult(ex); };
                c.BeginHandshake();
                (client, server) = (c, () => s.Connections.SingleOrDefault());
            }
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            // A DTLS 1.3 client is done after its Finished; the server can still reject its certificate afterwards.
            Assert.IsTrue(SpinWait.SpinUntil(() => done.Task.Result != null || lateFailure.Task.IsCompleted || server()?.IsHandshakeComplete == true, Timeout));
            var error = done.Task.Result ?? (lateFailure.Task.IsCompleted ? lateFailure.Task.Result : null);
            return new Outcome(error, null, client, server());
        }

        private static byte[] ServerKeyOf(DtlsConnectionBase client)
            => client is Dtls12Client c12 ? c12.ServerRawPublicKey : ((Dtls13Client)client).ServerRawPublicKey;

        private static CertificateType ServerTypeOf(DtlsConnectionBase client)
            => client is Dtls12Client c12 ? c12.ServerCertificateType : ((Dtls13Client)client).ServerCertificateType;

        private static byte[] ClientKeyOf(DtlsConnectionBase server)
            => server is Dtls12ServerConnection s12 ? s12.ClientRawPublicKey : ((Dtls13ServerConnection)server).ClientRawPublicKey;

        private static AlertDescription? Alert(Exception error) => (error as DtlsException)?.Alert;

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ServerWithoutCertificate_AuthenticatesWithItsKey(int version)
        {
            var o = new Options();
            o.ServerKeyCheck = spki => spki.AsSpan().SequenceEqual(Spki(o.ServerKey));
            var result = Run(version, o);
            Assert.IsNull(result.ClientError, result.ClientError?.ToString());
            Assert.AreEqual(CertificateType.RawPublicKey, ServerTypeOf(result.Client));
            CollectionAssert.AreEqual(Spki(o.ServerKey), ServerKeyOf(result.Client));
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void UnpinnedServerKey_IsBadCertificate(int version)
        {
            var result = Run(version, new Options { ServerKeyCheck = _ => false });
            Assert.AreEqual(AlertDescription.BadCertificate, Alert(result.ClientError), result.ClientError?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ServerPreference_DecidesTheType(int version)
        {
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            var both = new[] { CertificateType.RawPublicKey, CertificateType.X509 };
            var result = Run(version, new Options { ServerKey = key, ServerCertificate = cert, ServerTypes = new[] { CertificateType.X509, CertificateType.RawPublicKey }, ClientAcceptsServer = both });
            Assert.IsNull(result.ClientError, result.ClientError?.ToString());
            Assert.AreEqual(CertificateType.X509, ServerTypeOf(result.Client));

            result = Run(version, new Options { ServerKey = key, ServerCertificate = cert, ServerTypes = both, ClientAcceptsServer = both });
            Assert.AreEqual(CertificateType.RawPublicKey, ServerTypeOf(result.Client));
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void NoCommonType_IsUnsupportedCertificate(int version)
        {
            // The client takes only raw public keys; the server only has X.509.
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            var result = Run(version, new Options { ServerKey = key, ServerCertificate = cert, ServerTypes = null });
            Assert.AreEqual(AlertDescription.UnsupportedCertificate, Alert(result.ClientError), result.ClientError?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ClientRawPublicKey_AuthenticatesTheClient(int version)
        {
            var clientKey = TestPki.NewKey();
            var o = new Options
            {
                RequireClientAuth = true, ServerAcceptsClient = Rpk, ClientTypes = Rpk, ClientKey = clientKey,
                ClientKeyCheck = spki => spki.AsSpan().SequenceEqual(Spki(clientKey)),
            };
            var result = Run(version, o);
            Assert.IsNull(result.ClientError, result.ClientError?.ToString());
            CollectionAssert.AreEqual(Spki(clientKey), ClientKeyOf(result.Server));

            o.ClientKeyCheck = _ => false;
            result = Run(version, o);
            Assert.AreEqual(AlertDescription.BadCertificate, Alert(result.ClientError), result.ClientError?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ClientOnlyWithRawKey_ButServerWantsX509_IsUnsupportedCertificate(int version)
        {
            var result = Run(version, new Options { RequireClientAuth = true, ClientTypes = Rpk, ClientKey = TestPki.NewKey() });
            Assert.AreEqual(AlertDescription.UnsupportedCertificate, Alert(result.ClientError), result.ClientError?.ToString());
        }

        [TestMethod]
        public void Extension_RoundTripsAndSelectionsAreChecked()
        {
            var list = new CertificateTypeExtension(CertificateTypeExtension.ServerType, new[] { CertificateType.RawPublicKey, CertificateType.X509 });
            byte[] bytes = new byte[list.CalculateLength()];
            list.Write(0, bytes);
            CollectionAssert.AreEqual(new byte[] { 0, 20, 0, 3, 2, 2, 0 }, bytes);
            var parsed = new CertificateTypeExtension(CertificateTypeExtension.ServerType);
            parsed.Read(0, bytes);
            Assert.IsFalse(parsed.IsSelection);
            CollectionAssert.AreEqual(list.Types.ToList(), parsed.Types.ToList());

            var selection = new CertificateTypeExtension(CertificateTypeExtension.ServerType, CertificateType.RawPublicKey);
            Assert.AreEqual(CertificateType.RawPublicKey, RawPublicKeys.Accept(Rpk, selection, true));
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => RawPublicKeys.Accept(new[] { CertificateType.X509 }, selection, true)).Alert);
            Assert.AreEqual(AlertDescription.UnsupportedExtension, Assert.ThrowsExactly<DtlsException>(
                () => RawPublicKeys.Accept(null, selection, true)).Alert);
            Assert.AreEqual(AlertDescription.UnsupportedCertificate, Assert.ThrowsExactly<DtlsException>(
                () => RawPublicKeys.Accept(Rpk, null, true)).Alert);
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        private static Exception Handshake(Action<Action> onFinished, Action<Action<Exception>> onFailed, Action begin, string context)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onFinished(() => done.TrySetResult(null));
            onFailed(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed:\n" + context);
            return done.Task.Result;
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSsl_ServerRawPublicKey_BothDirections()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -enable_server_rpk",
                dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport) { ServerCertificateTypes = Rpk, ServerRawPublicKeyValidator = spki => spki.AsSpan().SequenceEqual(Spki(key)) };
                var error = Handshake(s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), client.BeginHandshake, server.Output);
                Assert.IsNull(error, error?.ToString());
                Assert.AreEqual(CertificateType.RawPublicKey, client.ServerCertificateType);
                CollectionAssert.AreEqual(Spki(key), client.ServerRawPublicKey);
            }

            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var serverKey = TestPki.NewKey();
            _ = new Dtls12Server(serverTransport, serverKey, null) { ServerCertificateTypes = Rpk };
            using var openSslClient = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -enable_server_rpk", dir);
            Assert.IsTrue(openSslClient.WaitForOutput("Server raw public key", Timeout), openSslClient.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSsl_ClientRawPublicKey_BothDirections()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            // OpenSSL server asking for a client raw public key, our client.
            var clientKey = TestPki.NewKey();
            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -enable_client_rpk -verify 1",
                dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport) { ClientCertificateTypes = Rpk, ClientCertificateKeyPair = clientKey };
                var error = Handshake(s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), client.BeginHandshake, server.Output);
                Assert.IsNull(error, error?.ToString());
                Assert.IsTrue(server.WaitForOutput("Client raw public key", Timeout), server.Output);
            }

            // OpenSSL client with a raw public key, our server.
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls12Server(serverTransport, key, cert) { RequireClientCertificate = true, ClientCertificateTypes = Rpk };
            using var openSslClient = new OpenSslProcess(
                $"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -enable_client_rpk -cert {certPath} -key {keyPath}", dir);
            Assert.IsTrue(SpinWait.SpinUntil(() => dtlsServer.Connections.Any(c => c.IsHandshakeComplete), Timeout), openSslClient.Output);
            CollectionAssert.AreEqual(Spki(key), dtlsServer.Connections.Single().ClientRawPublicKey);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSsl_RawPublicKeys_BothDirections()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var wolfKey = TestPki.NewKey();
            string wolfSpki = Path.Combine(dir, "wolf.der");
            File.WriteAllBytes(wolfSpki, Spki(wolfKey));
            string wolfKeyPath = OpenSsl.WritePem(dir, "wolf-key.pem", wolfKey.Private);
            var ourKey = TestPki.NewKey();
            string ourSpki = Path.Combine(dir, "ours.der");
            File.WriteAllBytes(ourSpki, Spki(ourKey));

            // wolfSSL server with a raw public key that wants ours; our client.
            using (var server = OpenSslProcess.StartServer(p => $"server {p} {wolfSpki} {wolfKeyPath} -rpk -rpk_pin {ourSpki}", dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls13Client(transport)
                {
                    ServerCertificateTypes = Rpk, ServerRawPublicKeyValidator = spki => spki.AsSpan().SequenceEqual(Spki(wolfKey)),
                    ClientCertificateTypes = Rpk, ClientCertificateKeyPair = ourKey,
                };
                var error = Handshake(s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), client.BeginHandshake, server.Output);
                Assert.IsNull(error, error + "\n" + server.Output);
                Assert.AreEqual(CertificateType.RawPublicKey, client.ServerCertificateType);
                Assert.IsTrue(server.WaitForOutput("CERTTYPE:2 2", Timeout), server.Output);
            }

            // wolfSSL client with a raw public key, pinning ours; our server.
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls13Server(serverTransport, ourKey, null)
            {
                ServerCertificateTypes = Rpk, RequireClientCertificate = true, ClientCertificateTypes = Rpk,
                ClientRawPublicKeyValidator = spki => spki.AsSpan().SequenceEqual(Spki(wolfKey)),
            };
            using var wolfClient = new OpenSslProcess($"client {serverTransport.LocalEndpoint.Port} -rpk -rpk_pin {ourSpki} -cert {wolfSpki} -key {wolfKeyPath}", dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CERTTYPE:2 2", Timeout), wolfClient.Output);
            Assert.IsTrue(SpinWait.SpinUntil(() => dtlsServer.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            CollectionAssert.AreEqual(Spki(wolfKey), dtlsServer.Connections.Single().ClientRawPublicKey);
        }
    }
}
