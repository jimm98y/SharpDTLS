using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
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
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Dtls13Test.Tests
{
    /// <summary>OCSP stapling (status_request, RFC 6066 §8 / RFC 8446 §4.4.2.1) and <see cref="OcspStapleValidator"/>.</summary>
    [TestClass]
    public sealed class TestOcspStapling
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("OCSP"));
        private static TestPki Pki => _pki.Value;

        private static readonly CertificateStatus Revoked = new RevokedStatus(DateTime.UtcNow.AddDays(-1), CrlReason.KeyCompromise);

        private static List<byte[]> Chain(X509Certificate leaf) => new() { leaf.GetEncoded(), Pki.Intermediate.Cert.GetEncoded() };

        private static void AssertRejected(AlertDescription expected, Action validate)
            => Assert.AreEqual(expected, Assert.ThrowsExactly<DtlsException>(validate).Alert);

        // ── The validator ────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void GoodResponse_IsAccepted()
        {
            var leaf = Pki.Leaf().Cert;
            new OcspStapleValidator().Validate(Pki.OcspResponse(leaf), Chain(leaf));
        }

        [TestMethod]
        public void RevokedCertificate_IsCertificateRevoked()
        {
            var leaf = Pki.Leaf().Cert;
            AssertRejected(AlertDescription.CertificateRevoked, () => new OcspStapleValidator().Validate(Pki.OcspResponse(leaf, Revoked), Chain(leaf)));
        }

        [TestMethod]
        public void UnknownStatus_StaleOrFutureResponse_AreRejected()
        {
            var leaf = Pki.Leaf().Cert;
            var validator = new OcspStapleValidator();
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => validator.Validate(Pki.OcspResponse(leaf, new UnknownStatus()), Chain(leaf)));
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => validator.Validate(
                Pki.OcspResponse(leaf, thisUpdate: DateTime.UtcNow.AddDays(-3), nextUpdate: DateTime.UtcNow.AddDays(-1)), Chain(leaf)));
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => validator.Validate(
                Pki.OcspResponse(leaf, thisUpdate: DateTime.UtcNow.AddDays(1), nextUpdate: DateTime.UtcNow.AddDays(2)), Chain(leaf)));
        }

        [TestMethod]
        public void ResponseForAnotherCertificate_IsRejected()
        {
            var leaf = Pki.Leaf().Cert;
            var other = Pki.Leaf().Cert;
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(Pki.OcspResponse(other), Chain(leaf)));
        }

        [TestMethod]
        public void ResponseNotSignedByTheIssuer_IsRejected()
        {
            var leaf = Pki.Leaf().Cert;
            // Signed by a key the issuer never certified, and by a certificate it issued without id-kp-OCSPSigning.
            var stranger = new TestPki("Stranger").Intermediate;
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(Pki.OcspResponse(leaf, responder: stranger), Chain(leaf)));
            var notAResponder = Pki.Leaf(usage: KeyPurposeID.id_kp_serverAuth);
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(Pki.OcspResponse(leaf, responder: notAResponder), Chain(leaf)));
        }

        [TestMethod]
        public void DelegatedResponder_IsAccepted()
        {
            var leaf = Pki.Leaf().Cert;
            var responder = Pki.Leaf(usage: KeyPurposeID.id_kp_OCSPSigning, commonName: "OCSP responder");
            new OcspStapleValidator().Validate(Pki.OcspResponse(leaf, responder: responder), Chain(leaf));
        }

        [TestMethod]
        public void IssuerOutsideTheChain_ComesFromTheConstructor()
        {
            var leaf = Pki.Leaf(fromRoot: true).Cert;
            byte[] response = Pki.OcspResponse(leaf, fromRoot: true);
            var chain = new List<byte[]> { leaf.GetEncoded() };
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(response, chain));
            new OcspStapleValidator(new[] { Pki.Root.Cert }).Validate(response, chain);
        }

        [TestMethod]
        public void MissingOrGarbage_Response()
        {
            var leaf = Pki.Leaf().Cert;
            new OcspStapleValidator().Validate(null, Chain(leaf));
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator { Required = true }.Validate(null, Chain(leaf)));
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(new byte[] { 0x30, 0x03, 0x0a, 0x01, 0x01 }, Chain(leaf)));
            AssertRejected(AlertDescription.BadCertificateStatusResponse, () => new OcspStapleValidator().Validate(new byte[] { 1, 2, 3 }, Chain(leaf)));
        }

        // ── Handshakes ───────────────────────────────────────────────────────────────────────

        private sealed record Result(Exception Error, byte[] Stapled);

        private static Result Run(int version, byte[] serverStaple, bool request, OcspStapleValidator validator,
            Func<string, ServerCredentials> selector = null, string serverName = null, (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair Key, X509Certificate Cert)? leaf = null)
        {
            var pair = new ScriptedTransportPair();
            var credentials = leaf ?? Pki.Leaf(new[] { "server.test" });
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<byte[]> stapled;
            if (version == 12)
            {
                _ = new Dtls12Server(pair.Server, credentials.Key, credentials.Cert)
                {
                    IntermediateCertificates = new[] { Pki.Intermediate.Cert }, OcspResponse = serverStaple, CertificateSelector = selector,
                };
                var client = new Dtls12Client(pair.Client) { RequestOcspStapling = request, ServerCertificateStatusValidator = validator?.ForServer(), ServerName = serverName };
                client.HandshakeFinished += (_, _) => done.TrySetResult(null);
                client.Failed += (_, ex) => done.TrySetResult(ex);
                client.BeginHandshake();
                stapled = () => client.OcspResponse;
            }
            else
            {
                _ = new Dtls13Server(pair.Server, credentials.Key, credentials.Cert)
                {
                    IntermediateCertificates = new[] { Pki.Intermediate.Cert }, OcspResponse = serverStaple, CertificateSelector = selector,
                };
                var client = new Dtls13Client(pair.Client) { RequestOcspStapling = request, ServerCertificateStatusValidator = validator?.ForServer(), ServerName = serverName };
                client.HandshakeFinished += (_, _) => done.TrySetResult(null);
                client.Failed += (_, ex) => done.TrySetResult(ex);
                client.BeginHandshake();
                stapled = () => client.OcspResponse;
            }
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return new Result(done.Task.Result, stapled());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Staple_IsDeliveredAndChecked(int version)
        {
            var leaf = Pki.Leaf(new[] { "server.test" });
            byte[] staple = Pki.OcspResponse(leaf.Cert);
            var result = Run(version, staple, request: true, new OcspStapleValidator { Required = true }, leaf: leaf);
            Assert.IsNull(result.Error, result.Error?.ToString());
            CollectionAssert.AreEqual(staple, result.Stapled);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void RevokedStaple_AbortsTheHandshake(int version)
        {
            var leaf = Pki.Leaf(new[] { "server.test" });
            var result = Run(version, Pki.OcspResponse(leaf.Cert, Revoked), request: true, new OcspStapleValidator(), leaf: leaf);
            Assert.AreEqual(AlertDescription.CertificateRevoked, (result.Error as DtlsException)?.Alert, result.Error?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void NoStaple_FailsOnlyWhenRequired(int version)
        {
            var result = Run(version, null, request: true, new OcspStapleValidator());
            Assert.IsNull(result.Error, result.Error?.ToString());
            Assert.IsNull(result.Stapled);
            result = Run(version, null, request: true, new OcspStapleValidator { Required = true });
            Assert.AreEqual(AlertDescription.BadCertificateStatusResponse, (result.Error as DtlsException)?.Alert, result.Error?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void NotRequested_NothingIsStapled(int version)
        {
            var leaf = Pki.Leaf(new[] { "server.test" });
            var result = Run(version, Pki.OcspResponse(leaf.Cert), request: false, null, leaf: leaf);
            Assert.IsNull(result.Error, result.Error?.ToString());
            Assert.IsNull(result.Stapled);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void SelectedCredentials_StapleTheirOwnResponse(int version)
        {
            var named = Pki.Leaf(new[] { "named.test" });
            byte[] namedStaple = Pki.OcspResponse(named.Cert);
            var credentials = new ServerCredentials(named.Key, named.Cert, new[] { Pki.Intermediate.Cert }) { OcspResponse = namedStaple };
            var defaultLeaf = Pki.Leaf(new[] { "server.test" });
            var result = Run(version, Pki.OcspResponse(defaultLeaf.Cert), request: true, new OcspStapleValidator { Required = true },
                name => name == "named.test" ? credentials : null, "named.test", defaultLeaf);
            Assert.IsNull(result.Error, result.Error?.ToString());
            CollectionAssert.AreEqual(namedStaple, result.Stapled);
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        private static (string Chain, string Key, string Root, string Good, string Revoked, X509Certificate Leaf) WriteFiles(string dir)
        {
            var leaf = Pki.Leaf(new[] { "server.test" });
            string cert = OpenSsl.WritePem(dir, "cert.pem", leaf.Cert);
            string intermediate = OpenSsl.WritePem(dir, "intermediate.pem", Pki.Intermediate.Cert);
            string chain = Path.Combine(dir, "chain.pem");
            File.WriteAllText(chain, File.ReadAllText(cert) + File.ReadAllText(intermediate));
            string good = Path.Combine(dir, "good.der");
            File.WriteAllBytes(good, Pki.OcspResponse(leaf.Cert));
            string revoked = Path.Combine(dir, "revoked.der");
            File.WriteAllBytes(revoked, Pki.OcspResponse(leaf.Cert, Revoked));
            return (chain, OpenSsl.WritePem(dir, "key.pem", leaf.Key.Private), OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert), good, revoked, leaf.Cert);
        }

        private static Exception Handshake(DtlsConnectionBase client, Action<Action> onFinished, Action begin, string context)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onFinished(() => done.TrySetResult(null));
            client.Failed += (_, ex) => done.TrySetResult(ex);
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed:\n" + context);
            return done.Task.Result;
        }

        [DataRow(false)]
        [DataRow(true)]
        [TestCategory("Interop")]
        [TestMethod]
        public void SharpDtlsClient_ChecksOpenSslStaple(bool revoked)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var files = WriteFiles(dir);
            using var server = OpenSslProcess.StartServer(p =>
                $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {Path.Combine(dir, "cert.pem")} -cert_chain {Path.Combine(dir, "intermediate.pem")} -key {files.Key} -status_file {(revoked ? files.Revoked : files.Good)}",
                dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(transport) { RequestOcspStapling = true, ServerCertificateStatusValidator = new OcspStapleValidator { Required = true }.ForServer() };
            var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake, server.Output);
            if (revoked)
            {
                Assert.AreEqual(AlertDescription.CertificateRevoked, (error as DtlsException)?.Alert, error?.ToString());
            }
            else
            {
                Assert.IsNull(error, error?.ToString());
                CollectionAssert.AreEqual(File.ReadAllBytes(files.Good), client.OcspResponse);
            }
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_ReceivesSharpDtlsStaple()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var leaf = Pki.Leaf(new[] { "server.test" });
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            _ = new Dtls12Server(transport, leaf.Key, leaf.Cert) { IntermediateCertificates = new[] { Pki.Intermediate.Cert }, OcspResponse = Pki.OcspResponse(leaf.Cert) };
            using var client = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{transport.LocalEndpoint.Port} -status", dir);
            Assert.IsTrue(client.WaitForOutput("Cert Status: good", Timeout), client.Output);
            Assert.IsTrue(client.WaitForOutput("OCSP Response Status: successful", Timeout), client.Output);
        }

        [DataRow(false)]
        [DataRow(true)]
        [TestCategory("Interop")]
        [TestMethod]
        public void SharpDtlsClient_ChecksWolfSslStaple(bool revoked)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var files = WriteFiles(dir);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {files.Chain} {files.Key} -ocsp_resp {(revoked ? files.Revoked : files.Good)}",
                dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { RequestOcspStapling = true, ServerCertificateStatusValidator = new OcspStapleValidator { Required = true }.ForServer() };
            var error = Handshake(client, s => client.HandshakeFinished += (_, _) => s(), client.BeginHandshake, server.Output);
            if (revoked)
            {
                Assert.AreEqual(AlertDescription.CertificateRevoked, (error as DtlsException)?.Alert, error?.ToString());
            }
            else
            {
                Assert.IsNull(error, error?.ToString());
                CollectionAssert.AreEqual(File.ReadAllBytes(files.Good), client.OcspResponse);
            }
        }

        [DataRow(false)]
        [DataRow(true)]
        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSslClient_ChecksSharpDtlsStaple(bool revoked)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var leaf = Pki.Leaf(new[] { "server.test" });
            string root = OpenSsl.WritePem(dir, "root.pem", Pki.Root.Cert);
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            _ = new Dtls13Server(transport, leaf.Key, leaf.Cert)
            {
                IntermediateCertificates = new[] { Pki.Intermediate.Cert }, OcspResponse = Pki.OcspResponse(leaf.Cert, revoked ? Revoked : null),
            };
            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -verify {root} -ocsp", dir, WolfSsl.Harness);
            Assert.IsTrue(client.WaitForOutput(revoked ? "ERROR connect" : "CONNECTED", Timeout), client.Output);
            if (revoked)
                StringAssert.Contains(client.Output, "revoked", StringComparison.OrdinalIgnoreCase);
        }
    }
}
