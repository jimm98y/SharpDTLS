using Org.BouncyCastle.Asn1.X509;
using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Choosing certificates from what the peer said: certificate_authorities and signature_algorithms_cert (RFC 8446
    /// §4.2.3-4), and the CA list of a DTLS 1.2 CertificateRequest.
    /// </summary>
    [TestClass]
    public sealed class TestCertificateSelection
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _a = new(() => new TestPki("Selection A"));
        private static readonly Lazy<TestPki> _b = new(() => new TestPki("Selection B"));
        private static TestPki A => _a.Value;
        private static TestPki B => _b.Value;

        private static ServerCredentials ServerCredentialsFrom(TestPki pki)
        {
            var (key, cert) = pki.Leaf(new[] { "server.test" });
            return new ServerCredentials(key, cert, new[] { pki.Intermediate.Cert });
        }

        private static CertificateCredentials ClientCredentialsFrom(TestPki pki)
        {
            var (key, cert) = pki.Leaf(commonName: "client", usage: KeyPurposeID.id_kp_clientAuth);
            return new CertificateCredentials(key, cert, new[] { pki.Intermediate.Cert });
        }

        private static Exception Handshake(DtlsConnectionBase client, Action<Action> onFinished, Action begin)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onFinished(() => done.TrySetResult(null));
            client.Failed += (_, ex) => done.TrySetResult(ex);
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        [TestMethod]
        public void Server_PicksTheChainForTheClientsCa()
        {
            var fromA = ServerCredentialsFrom(A);
            var fromB = ServerCredentialsFrom(B);
            foreach (var (trusted, expected) in new[] { (B, fromB), (A, fromA) })
            {
                var pair = new ScriptedTransportPair();
                CertificateSelectionContext seen = null;
                _ = new Dtls13Server(pair.Server)
                {
                    CredentialsSelector = context => { seen = context; return new[] { fromA, fromB }.First(context.IsIssuedByAcceptedAuthority); },
                };
                var client = new Dtls13Client(pair.Client)
                {
                    CertificateAuthorities = new[] { trusted.Root.Cert }, SignatureAlgorithmsCert = new ushort[] { 0x0403 },
                    ServerCertificateValidator = new CertificateValidator(new[] { trusted.Root.Cert }).ForServer("server.test"),
                };
                var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake);
                Assert.IsNull(error, error?.ToString());
                Assert.AreEqual(expected.Certificate, client.ServerCertificate);
                Assert.AreEqual(1, seen.CertificateAuthorities.Count);
                Assert.IsTrue(seen.CertificateAuthorities[0].Equivalent(trusted.Root.Cert.SubjectDN));
                CollectionAssert.AreEqual(new ushort[] { 0x0403 }, seen.SignatureAlgorithmsCert.ToArray());
                Assert.IsNotNull(seen.SignatureAlgorithms);
            }
        }

        [TestMethod]
        public void Dtls12Server_SeesSignatureSchemes_AndFallsBack()
        {
            var pair = new ScriptedTransportPair();
            CertificateSelectionContext seen = null;
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            _ = new Dtls12Server(pair.Server, key, cert) { CredentialsSelector = context => { seen = context; return null; } };
            var client = new Dtls12Client(pair.Client) { SignatureAlgorithmsCert = new ushort[] { 0x0403, 0x0804 }, ServerName = "server.test" };
            var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake);
            Assert.IsNull(error, error?.ToString());
            Assert.AreEqual(cert, client.ServerCertificate, "null falls back to the default certificate");
            Assert.AreEqual("server.test", seen.ServerName);
            CollectionAssert.AreEqual(new ushort[] { 0x0403, 0x0804 }, seen.SignatureAlgorithmsCert.ToArray());
            Assert.IsEmpty(seen.CertificateAuthorities);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Client_PicksTheCertificateForTheServersCa(int version)
        {
            var fromA = ClientCredentialsFrom(A);
            var fromB = ClientCredentialsFrom(B);
            var pair = new ScriptedTransportPair();
            CertificateSelectionContext seen = null;
            Func<CertificateSelectionContext, CertificateCredentials> selector = context => { seen = context; return new[] { fromA, fromB }.First(context.IsIssuedByAcceptedAuthority); };
            var validator = new CertificateValidator(new[] { B.Root.Cert }).ForClient();
            DtlsConnectionBase client;
            Func<Org.BouncyCastle.X509.X509Certificate> received;
            Exception error;
            if (version == 12)
            {
                var server = new Dtls12Server(pair.Server, TestCredentials.For(CertificateKeyType.Ecdsa).Item1, TestCredentials.For(CertificateKeyType.Ecdsa).Item2)
                {
                    RequireClientCertificate = true, ClientCertificateAuthorities = new[] { B.Root.Cert }, ClientCertificateValidator = validator,
                };
                var c = new Dtls12Client(pair.Client) { ClientCredentialsSelector = selector };
                error = Handshake(c, s => c.HandshakeFinished += (_, _) => s(), c.BeginHandshake);
                received = () => server.Connections.Single().ClientCertificate;
            }
            else
            {
                var server = new Dtls13Server(pair.Server)
                {
                    RequireClientCertificate = true, ClientCertificateAuthorities = new[] { B.Root.Cert }, ClientCertificateValidator = validator,
                };
                var c = new Dtls13Client(pair.Client) { ClientCredentialsSelector = selector };
                error = Handshake(c, s => c.HandshakeFinished += (_, _) => s(), c.BeginHandshake);
                received = () => server.Connections.Single().ClientCertificate;
            }
            Assert.IsNull(error, error?.ToString());
            Assert.IsTrue(SpinWait.SpinUntil(() => received() != null, Timeout));
            Assert.AreEqual(fromB.Certificate, received());
            Assert.IsTrue(seen.CertificateAuthorities.Single().Equivalent(B.Root.Cert.SubjectDN));
            Assert.IsNotNull(seen.SignatureAlgorithms);
        }

        [TestMethod]
        public void Extensions_RoundTripAndRejectEmptyLists()
        {
            var names = new[] { A.Root.Cert.SubjectDN.GetEncoded(), B.Intermediate.Cert.SubjectDN.GetEncoded() };
            var extension = new CertificateAuthoritiesExtension(names);
            byte[] bytes = new byte[extension.CalculateLength()];
            extension.Write(0, bytes);
            var parsed = new CertificateAuthoritiesExtension();
            Assert.AreEqual(bytes.Length, parsed.Read(0, bytes));
            Assert.HasCount(2, parsed.Names);
            CollectionAssert.AreEqual(names[1], parsed.Names[1]);

            Assert.AreEqual(AlertDescription.DecodeError, Assert.ThrowsExactly<DtlsException>(
                () => new CertificateAuthoritiesExtension().Read(0, new byte[] { 0, 47, 0, 2, 0, 0 })).Alert);
            Assert.AreEqual(AlertDescription.DecodeError, Assert.ThrowsExactly<DtlsException>(
                () => new SignatureAlgorithmsCertExtension().Read(0, new byte[] { 0, 50, 0, 2, 0, 0 })).Alert);
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSsl_CertificateRequestCaNames_BothDirections()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (serverKey, serverCert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", serverCert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", serverKey.Private);
            string rootB = OpenSsl.WritePem(dir, "rootB.pem", B.Root.Cert);
            string chainB = Path.Combine(dir, "chainB.pem");
            File.WriteAllText(chainB, File.ReadAllText(OpenSsl.WritePem(dir, "intermediateB.pem", B.Intermediate.Cert)) + File.ReadAllText(rootB));

            // OpenSSL server naming CA B; our client picks its B certificate.
            var fromA = ClientCredentialsFrom(A);
            var fromB = ClientCredentialsFrom(B);
            CertificateSelectionContext seen = null;
            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -Verify 2 -CAfile {chainB} -verify_return_error",
                dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport) { ClientCredentialsSelector = context => { seen = context; return new[] { fromA, fromB }.First(context.IsIssuedByAcceptedAuthority); } };
                var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake);
                Assert.IsNull(error, error + "\n" + server.Output);
                Assert.IsTrue(seen.CertificateAuthorities.Any(n => n.Equivalent(B.Root.Cert.SubjectDN)), string.Join("; ", seen.CertificateAuthorities));
            }

            // Our server naming CA B; OpenSSL's client lists it.
            var (clientKey, clientCert) = (fromB.KeyPair, fromB.Certificate);
            string clientCertPath = OpenSsl.WritePem(dir, "client.pem", clientCert);
            string clientKeyPath = OpenSsl.WritePem(dir, "client-key.pem", clientKey.Private);
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            _ = new Dtls12Server(serverTransport, serverKey, serverCert) { RequireClientCertificate = true, ClientCertificateAuthorities = new[] { B.Root.Cert } };
            using var openSslClient = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -cert {clientCertPath} -key {clientKeyPath}", dir);
            Assert.IsTrue(openSslClient.WaitForOutput("Acceptable client certificate CA names", Timeout), openSslClient.Output);
            Assert.IsTrue(openSslClient.WaitForOutput("Selection B Root CA", Timeout), openSslClient.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSsl_CertificateAuthorities_BothDirections()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            string rootA = OpenSsl.WritePem(dir, "rootA.pem", A.Root.Cert);
            string rootB = OpenSsl.WritePem(dir, "rootB.pem", B.Root.Cert);

            // wolfSSL server naming CA B in its CertificateRequest; our client names CA A in its ClientHello.
            var serverCredentials = ServerCredentialsFrom(A);
            string chainA = Path.Combine(dir, "chainA.pem");
            File.WriteAllText(chainA, File.ReadAllText(OpenSsl.WritePem(dir, "leafA.pem", serverCredentials.Certificate)) + File.ReadAllText(OpenSsl.WritePem(dir, "intA.pem", A.Intermediate.Cert)));
            string keyA = OpenSsl.WritePem(dir, "keyA.pem", serverCredentials.KeyPair.Private);
            var fromA = ClientCredentialsFrom(A);
            var fromB = ClientCredentialsFrom(B);
            CertificateSelectionContext seen = null;
            using (var server = OpenSslProcess.StartServer(p => $"server {p} {chainA} {keyA} -verify {rootB} -ca_names {rootB}", dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls13Client(transport)
                {
                    CertificateAuthorities = new[] { A.Root.Cert },
                    ClientCredentialsSelector = context => { seen = context; return new[] { fromA, fromB }.First(context.IsIssuedByAcceptedAuthority); },
                };
                var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake);
                Assert.IsNull(error, error + "\n" + server.Output);
                Assert.IsTrue(seen.CertificateAuthorities.Single().Equivalent(B.Root.Cert.SubjectDN));
                Assert.IsTrue(server.WaitForOutput("PEERCA:1", Timeout), server.Output);
            }

            // wolfSSL client naming CA B; our server picks its B chain.
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var fromServerA = ServerCredentialsFrom(A);
            var fromServerB = ServerCredentialsFrom(B);
            CertificateSelectionContext serverSeen = null;
            _ = new Dtls13Server(serverTransport)
            {
                CredentialsSelector = context => { serverSeen = context; return new[] { fromServerA, fromServerB }.First(context.IsIssuedByAcceptedAuthority); },
            };
            using var wolfClient = new OpenSslProcess($"client {serverTransport.LocalEndpoint.Port} -verify {rootB} -ca_names {rootB}", dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CONNECTED", Timeout), wolfClient.Output);
            Assert.IsTrue(serverSeen.CertificateAuthorities.Single().Equivalent(B.Root.Cert.SubjectDN));
        }
    }
}
