using Org.BouncyCastle.Asn1.X509;
using SharpDTLS;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>Peer certificate validation with <see cref="CertificateValidator"/> and intermediate chains.</summary>
    [TestClass]
    public sealed class TestCertificateValidation
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki());
        private static TestPki Pki => _pki.Value;

        private static CertificateValidator Validator() => new(new[] { Pki.Root.Cert });

        private static List<byte[]> Chain(Org.BouncyCastle.X509.X509Certificate leaf, bool withIntermediate = true)
            => withIntermediate ? new List<byte[]> { leaf.GetEncoded(), Pki.Intermediate.Cert.GetEncoded() } : new List<byte[]> { leaf.GetEncoded() };

        private static void AssertRejected(AlertDescription expected, Action validate)
            => Assert.AreEqual(expected, Assert.ThrowsExactly<DtlsException>(validate).Alert);

        private const string ServerAuth = "1.3.6.1.5.5.7.3.1";

        [TestMethod]
        public void ValidChain_WithIntermediate_Matches()
        {
            var leaf = Pki.Leaf(new[] { "server.test" }, new[] { "127.0.0.1" }).Cert;
            Validator().Validate(Chain(leaf), ServerAuth, "server.test");
            Validator().Validate(Chain(leaf), ServerAuth, "127.0.0.1");
            Validator().Validate(Chain(leaf), ServerAuth, null);
        }

        [TestMethod]
        public void Wildcard_MatchesOneLabel()
        {
            var leaf = Pki.Leaf(new[] { "*.example.test" }).Cert;
            Validator().Validate(Chain(leaf), ServerAuth, "a.example.test");
            AssertRejected(AlertDescription.BadCertificate, () => Validator().Validate(Chain(leaf), ServerAuth, "a.b.example.test"));
            AssertRejected(AlertDescription.BadCertificate, () => Validator().Validate(Chain(leaf), ServerAuth, "example.test"));
        }

        [TestMethod]
        public void HostNameMismatch_IsBadCertificate()
        {
            var leaf = Pki.Leaf(new[] { "server.test" }).Cert;
            AssertRejected(AlertDescription.BadCertificate, () => Validator().Validate(Chain(leaf), ServerAuth, "other.test"));
            AssertRejected(AlertDescription.BadCertificate, () => Validator().Validate(Chain(leaf), ServerAuth, "10.0.0.1"));
        }

        [TestMethod]
        public void HostNameValidator_ReplacesTheNameCheckButNotTheChain()
        {
            var leaf = Pki.Leaf(new[] { "server.test" }).Cert;
            string seen = null;
            var validator = new CertificateValidator(new[] { Pki.Root.Cert })
            {
                HostNameValidator = (certificate, hostName) => { seen = hostName; return hostName == "pinned.example"; },
            };
            validator.Validate(Chain(leaf), ServerAuth, "pinned.example");
            Assert.AreEqual("pinned.example", seen);
            AssertRejected(AlertDescription.BadCertificate, () => validator.Validate(Chain(leaf), ServerAuth, "server.test"));
            AssertRejected(AlertDescription.UnknownCa, () => validator.Validate(Chain(leaf, withIntermediate: false), ServerAuth, "pinned.example"));
        }

        [TestMethod]
        public void CommonNameOnly_NeedsTheFallback()
        {
            var leaf = Pki.Leaf(commonName: "legacy.test").Cert;
            AssertRejected(AlertDescription.BadCertificate, () => Validator().Validate(Chain(leaf), ServerAuth, "legacy.test"));
            new CertificateValidator(new[] { Pki.Root.Cert }) { AllowCommonNameFallback = true }.Validate(Chain(leaf), ServerAuth, "legacy.test");
        }

        [TestMethod]
        public void MissingIntermediateOrForeignRoot_IsUnknownCa()
        {
            var leaf = Pki.Leaf(new[] { "server.test" }).Cert;
            AssertRejected(AlertDescription.UnknownCa, () => Validator().Validate(Chain(leaf, withIntermediate: false), ServerAuth, "server.test"));

            var other = new TestPki("Other");
            AssertRejected(AlertDescription.UnknownCa, () => new CertificateValidator(new[] { other.Root.Cert }).Validate(Chain(leaf), ServerAuth, "server.test"));
        }

        [TestMethod]
        public void ExpiredOrNotYetValid_IsCertificateExpired()
        {
            var expired = Pki.Leaf(new[] { "server.test" }, notBefore: DateTime.UtcNow.AddDays(-10), notAfter: DateTime.UtcNow.AddDays(-1)).Cert;
            AssertRejected(AlertDescription.CertificateExpired, () => Validator().Validate(Chain(expired), ServerAuth, "server.test"));

            var future = Pki.Leaf(new[] { "server.test" }, notBefore: DateTime.UtcNow.AddDays(1), notAfter: DateTime.UtcNow.AddDays(10)).Cert;
            AssertRejected(AlertDescription.CertificateExpired, () => Validator().Validate(Chain(future), ServerAuth, "server.test"));
        }

        [TestMethod]
        public void WrongExtendedKeyUsage_IsUnsupportedCertificate()
        {
            var clientOnly = Pki.Leaf(new[] { "server.test" }, usage: KeyPurposeID.id_kp_clientAuth).Cert;
            AssertRejected(AlertDescription.UnsupportedCertificate, () => Validator().Validate(Chain(clientOnly), ServerAuth, "server.test"));
            Validator().ForClient()(clientOnly, Chain(clientOnly));
        }

        [TestMethod]
        public void GeneratedEcCertificates_UseNamedCurves()
        {
            // RFC 5480 §2.1.1: explicit curve parameters are not allowed, and platform validators reject them.
            foreach (var certificate in new[]
            {
                Dtls12CryptoUtils.GenerateSelfSignedEcCertificate().certificate,
                Dtls13CryptoUtils.GenerateSelfSignedEcCertificate().certificate,
            })
                Assert.IsTrue(Org.BouncyCastle.Asn1.X9.X962Parameters.GetInstance(certificate.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Parameters).IsNamedCurve);

            var protectionKey = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)PwdCredential.GenerateProtectionKeyPair().Public;
            Assert.IsInstanceOfType<Org.BouncyCastle.Crypto.Parameters.ECNamedDomainParameters>(protectionKey.Parameters);
        }

        // ── Handshakes ───────────────────────────────────────────────────────────────────────

        private static Exception Handshake12(bool sendIntermediate, string hostName, bool clientAuth = false)
        {
            var pair = new ScriptedTransportPair();
            var server = Pki.Leaf(new[] { "server.test" });
            var client = Pki.Leaf(usage: KeyPurposeID.id_kp_clientAuth, commonName: "client");
            var dtlsServer = new Dtls12Server(pair.Server, server.Key, server.Cert)
            {
                IntermediateCertificates = sendIntermediate ? new[] { Pki.Intermediate.Cert } : null,
                RequireClientCertificate = clientAuth,
                ClientCertificateValidator = clientAuth ? Validator().ForClient() : null,
            };
            var dtlsClient = new Dtls12Client(pair.Client) { ServerCertificateValidator = Validator().ForServer(hostName) };
            if (clientAuth)
            {
                dtlsClient.ClientCertificate = client.Cert;
                dtlsClient.ClientCertificateKeyPair = client.Key;
                dtlsClient.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
            }
            return Run(dtlsClient.BeginHandshake, h => dtlsClient.HandshakeFinished += (_, _) => h(null), f => dtlsClient.Failed += (_, ex) => f(ex));
        }

        private static Exception Handshake13(bool sendIntermediate, string hostName, bool clientAuth = false)
        {
            var pair = new ScriptedTransportPair();
            var server = Pki.Leaf(new[] { "server.test" });
            var client = Pki.Leaf(usage: KeyPurposeID.id_kp_clientAuth, commonName: "client");
            var dtlsServer = new Dtls13Server(pair.Server, server.Key, server.Cert)
            {
                IntermediateCertificates = sendIntermediate ? new[] { Pki.Intermediate.Cert } : null,
                RequireClientCertificate = clientAuth,
                ClientCertificateValidator = clientAuth ? Validator().ForClient() : null,
            };
            var dtlsClient = new Dtls13Client(pair.Client) { ServerCertificateValidator = Validator().ForServer(hostName) };
            if (clientAuth)
            {
                dtlsClient.ClientCertificate = client.Cert;
                dtlsClient.ClientCertificateKeyPair = client.Key;
                dtlsClient.ClientIntermediateCertificates = new[] { Pki.Intermediate.Cert };
            }
            Exception serverError = null;
            var result = Run(dtlsClient.BeginHandshake, h => dtlsClient.HandshakeFinished += (_, _) => h(null), f => dtlsClient.Failed += (_, ex) => f(ex));
            return result ?? serverError;
        }

        private static Exception Run(Action begin, Action<Action<Exception>> onSuccess, Action<Action<Exception>> onFailure)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onSuccess(ex => done.TrySetResult(null));
            onFailure(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Handshake_WithChainAndHostName_Succeeds(int version)
        {
            Exception error = version == 12 ? Handshake12(true, "server.test") : Handshake13(true, "server.test");
            Assert.IsNull(error, error?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Handshake_WithoutIntermediate_FailsWithUnknownCa(int version)
        {
            Exception error = version == 12 ? Handshake12(false, "server.test") : Handshake13(false, "server.test");
            Assert.AreEqual(AlertDescription.UnknownCa, (error as DtlsException)?.Alert, error?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Handshake_WrongHostName_FailsWithBadCertificate(int version)
        {
            Exception error = version == 12 ? Handshake12(true, "evil.test") : Handshake13(true, "evil.test");
            Assert.AreEqual(AlertDescription.BadCertificate, (error as DtlsException)?.Alert, error?.ToString());
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void Handshake_ClientChainValidatedByTheServer(int version)
        {
            Exception error = version == 12 ? Handshake12(true, "server.test", clientAuth: true) : Handshake13(true, "server.test", clientAuth: true);
            Assert.IsNull(error, error?.ToString());
        }
    }
}
