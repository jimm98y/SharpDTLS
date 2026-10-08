using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>Test credentials for every server certificate type, generated once.</summary>
    internal static class TestCredentials
    {
        // Fresh copies on every access: BouncyCastle zeroizes PSK buffers after use, and tests run in parallel.
        public static byte[] PskIdentity => Encoding.ASCII.GetBytes("Client_identity");
        public static byte[] PskKey => Convert.FromHexString("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
        public static byte[] PskHint => Encoding.ASCII.GetBytes("sharpdtls-hint");

        public static byte[] ResolvePsk(byte[] identity) => identity.AsSpan().SequenceEqual(PskIdentity) ? PskKey : null;

        // RFC 5054 Appendix B test user, on the 2048-bit group.
        public static byte[] SrpIdentity => Encoding.ASCII.GetBytes("alice");
        public static byte[] SrpPassword => Encoding.ASCII.GetBytes("password123");
        private static readonly Lazy<SrpVerifier> _srpVerifier = new(() => SrpVerifier.Create(SrpIdentity, SrpPassword));

        public static SrpVerifier ResolveSrp(byte[] identity) => identity.AsSpan().SequenceEqual(SrpIdentity) ? _srpVerifier.Value : null;

        // RFC 8492 Appendix A test user.
        public const string PwdUsername = "fred";
        public const string PwdPassword = "barney";
        private static readonly Lazy<PwdCredential> _pwdCredential = new(() => PwdCredential.Create(PwdUsername, PwdPassword));

        public static PwdCredential ResolvePwd(string username) => username == PwdUsername ? _pwdCredential.Value : null;

        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _rsa = new(() => Dtls12CryptoUtils.GenerateSelfSignedCertificate());
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ecdsa = new(() => SharpDTLS.DTLS13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate());
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dsa = new(GenerateDsa);
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dhRsa = new(() => GenerateDh(_rsa.Value.Item1.Private, "SHA256WITHRSA"));
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dhDss = new(() => GenerateDh(_dsa.Value.Item1.Private, "SHA256WITHDSA"));
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ecdhRsa = new(() => GenerateEcdh(_rsa.Value.Item1.Private, "SHA256WITHRSA"));

        // Fixed (EC)DH client certificates: distinct keys on the server's group or curve (RFC 5246 §7.4.6, RFC 8422 §3).
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dhRsaClient = new(() => GenerateDh(_rsa.Value.Item1.Private, "SHA256WITHRSA"));
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dhDssClient = new(() => GenerateDh(_dsa.Value.Item1.Private, "SHA256WITHDSA"));
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ecdhRsaClient = new(() => GenerateEcdh(_rsa.Value.Item1.Private, "SHA256WITHRSA"));
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ecdhEcdsaClient = new(() => GenerateEcdh(_ecdsa.Value.Item1.Private, "SHA256WITHECDSA"));

        /// <summary>Fixed (EC)DH client credentials for a static key agreement suite; (null, null) otherwise.</summary>
        public static (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate) FixedClientFor(CipherSuiteInfo suite) => suite.KeyExchange switch
        {
            KeyExchangeAlgorithm.DH_RSA => _dhRsaClient.Value,
            KeyExchangeAlgorithm.DH_DSS => _dhDssClient.Value,
            KeyExchangeAlgorithm.ECDH_RSA => _ecdhRsaClient.Value,
            KeyExchangeAlgorithm.ECDH_ECDSA => _ecdhEcdsaClient.Value,
            _ => (null, null),
        };

        /// <summary>Server credentials for <paramref name="suite"/>, including static (EC)DH certificates.</summary>
        public static (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate) For(CipherSuiteInfo suite) => suite.KeyExchange switch
        {
            KeyExchangeAlgorithm.DH_RSA => _dhRsa.Value,
            KeyExchangeAlgorithm.DH_DSS => _dhDss.Value,
            KeyExchangeAlgorithm.ECDH_RSA => _ecdhRsa.Value,
            KeyExchangeAlgorithm.ECDH_ECDSA => _ecdsa.Value,
            _ => For(suite.ServerCertificateType),
        };

        private static X509Certificate Certify(AsymmetricKeyParameter subjectKey, AsymmetricKeyParameter issuerKey, string algorithm, string name)
        {
            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(Environment.TickCount64));
            certGenerator.SetIssuerDN(new X509Name("CN=SharpDTLS Test CA"));
            certGenerator.SetSubjectDN(new X509Name("CN=" + name));
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            certGenerator.SetPublicKey(subjectKey);
            return certGenerator.Generate(new Asn1SignatureFactory(algorithm, issuerKey, new SecureRandom()));
        }

        private static (AsymmetricCipherKeyPair, X509Certificate) GenerateDh(AsymmetricKeyParameter issuerKey, string algorithm)
        {
            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(new SecureRandom(), FfdheGroups.Parameters(FfdheGroups.Ffdhe2048)));
            var keyPair = generator.GenerateKeyPair();
            var certificate = Certify(keyPair.Public, issuerKey, algorithm, "SharpDTLS static DH");

            // Use the parameters as decoded from the certificate (as loading the key from PKCS#8 would):
            // BouncyCastle requires identical DHParameters on both keys of an agreement.
            var publicKey = (DHPublicKeyParameters)certificate.GetPublicKey();
            var privateKey = new DHPrivateKeyParameters(((DHPrivateKeyParameters)keyPair.Private).X, publicKey.Parameters);
            return (new AsymmetricCipherKeyPair(publicKey, privateKey), certificate);
        }

        private static (AsymmetricCipherKeyPair, X509Certificate) GenerateEcdh(AsymmetricKeyParameter issuerKey, string algorithm)
        {
            var ec = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-256");
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(new ECDomainParameters(ec.Curve, ec.G, ec.N, ec.H), new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();
            return (keyPair, Certify(keyPair.Public, issuerKey, algorithm, "SharpDTLS static ECDH"));
        }

        public static (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate) For(CertificateKeyType type) => type switch
        {
            CertificateKeyType.Ecdsa => _ecdsa.Value,
            CertificateKeyType.Dsa => _dsa.Value,
            _ => _rsa.Value,
        };

        private static (AsymmetricCipherKeyPair, X509Certificate) GenerateDsa()
        {
            var parametersGenerator = new DsaParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            parametersGenerator.Init(new DsaParameterGenerationParameters(2048, 256, 80, new SecureRandom()));
            var generator = new DsaKeyPairGenerator();
            generator.Init(new DsaKeyGenerationParameters(new SecureRandom(), parametersGenerator.GenerateParameters()));
            var keyPair = generator.GenerateKeyPair();

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetIssuerDN(new X509Name("CN=SharpDTLS DSA"));
            certGenerator.SetSubjectDN(new X509Name("CN=SharpDTLS DSA"));
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            certGenerator.SetPublicKey(keyPair.Public);
            return (keyPair, certGenerator.Generate(new Asn1SignatureFactory("SHA256WITHDSA", keyPair.Private, new SecureRandom())));
        }
    }

    /// <summary>A full handshake and data exchange for every implemented DTLS 1.0/1.2 cipher suite.</summary>
    [TestClass]
    public sealed class TestCipherSuiteMatrix
    {
        public static IEnumerable<object[]> ImplementedSuites
            => CipherSuites.All.Select(s => new object[] { s.Id, s.Name });

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void Handshake_AndData(ushort id, string name)
        {
            var suite = CipherSuites.Get(id);
            ushort version = suite.IsUsableWith(DtlsVersion.Dtls12) ? DtlsVersion.Dtls12 : DtlsVersion.Dtls10;
            var (keyPair, certificate) = TestCredentials.For(suite);

            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server, keyPair, certificate) { MinimumVersion = DtlsVersion.Dtls10, CipherSuites = new List<ushort> { id } };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = version, MaximumVersion = version, CipherSuites = new List<ushort> { id }, MinimumDhPrimeBits = 2048 };
            if (suite.IsStaticKeyAgreement)
            {
                server.RequireClientCertificate = true;
                (client.ClientCertificateKeyPair, client.ClientCertificate) = TestCredentials.FixedClientFor(suite);
            }
            if (suite.RequiresSrp)
            {
                server.SrpVerifierProvider = TestCredentials.ResolveSrp;
                (client.SrpIdentity, client.SrpPassword) = (TestCredentials.SrpIdentity, TestCredentials.SrpPassword);
            }
            if (suite.RequiresPwd)
            {
                server.PwdCredentialProvider = TestCredentials.ResolvePwd;
                (client.PwdUsername, client.PwdPassword) = (TestCredentials.PwdUsername, TestCredentials.PwdPassword);
            }
            byte[] seenHint = null;
            if (suite.RequiresPsk)
            {
                server.PskIdentityResolver = TestCredentials.ResolvePsk;
                server.PskIdentityHint = TestCredentials.PskHint;
                client.PskProvider = hint => { seenHint = hint; return (TestCredentials.PskIdentity, TestCredentials.PskKey); };
            }

            var received = new List<string>();
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => received.Add(Encoding.UTF8.GetString(e.Data));
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);

            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(TimeSpan.FromSeconds(10)), $"{name}: handshake did not complete");
            Assert.AreEqual(id, client.CipherSuite.Id);
            Assert.AreEqual(version, client.NegotiatedVersion);
            if (suite.RequiresPsk)
                CollectionAssert.AreEqual(TestCredentials.PskHint, seenHint, "the server's identity hint reaches the client");
            if (suite.IsStaticKeyAgreement)
                Assert.AreEqual(client.ClientCertificate, server.Connections.Single().ClientCertificate, "fixed (EC)DH client authentication");

            for (int i = 0; i < 20; i++)
                client.SendApplicationData(Encoding.UTF8.GetBytes($"{name}-{i}"));
            Assert.HasCount(20, received);
        }

        [TestMethod]
        public void Registry_CoversIanaAndReportsImplementation()
        {
            Assert.HasCount(356, CipherSuites.Registry);
            Assert.AreEqual(328, CipherSuites.Registry.Count(s => s.DtlsOk));
            Assert.IsTrue(CipherSuites.All.All(s => s.DtlsOk), "stream-cipher (non DTLS-OK) suites must never be implemented");
            Assert.IsFalse(CipherSuites.DefaultFor(DtlsVersion.Dtls10, DtlsVersion.Dtls12).Any(id => CipherSuites.Get(id).Security == CipherSuiteSecurity.Weak));
            Assert.IsFalse(CipherSuites.DefaultFor(DtlsVersion.Dtls10, DtlsVersion.Dtls12).Any(id => CipherSuites.Get(id).RequiresSrp), "SRP suites need credentials");
            Assert.IsTrue(CipherSuites.DefaultFor(DtlsVersion.Dtls10, DtlsVersion.Dtls12, includeSrp: true).Any(id => CipherSuites.Get(id).RequiresSrp));
        }
    }
}
