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
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _rsa = new(() => Dtls12CryptoUtils.GenerateSelfSignedCertificate());
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ecdsa = new(() => SharpDTLS.DTLS13.Dtls13CryptoUtils.GenerateSelfSignedEcCertificate());
        private static readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _dsa = new(GenerateDsa);

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
            var (keyPair, certificate) = TestCredentials.For(suite.ServerCertificateType);

            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server, keyPair, certificate) { MinimumVersion = DtlsVersion.Dtls10, CipherSuites = new List<ushort> { id } };
            var client = new Dtls12Client(pair.Client) { MinimumVersion = version, MaximumVersion = version, CipherSuites = new List<ushort> { id } };

            var received = new List<string>();
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => received.Add(Encoding.UTF8.GetString(e.Data));
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);

            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(TimeSpan.FromSeconds(10)), $"{name}: handshake did not complete");
            Assert.AreEqual(id, client.CipherSuite.Id);
            Assert.AreEqual(version, client.NegotiatedVersion);

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
        }
    }
}
