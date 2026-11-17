using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    [TestClass]
    public sealed class TestCertificateBuilder
    {
        [TestMethod]
        public void CreateSelfSigned_NamesTheHostInTheSubjectAndTheAltName()
        {
            var credentials = CertificateBuilder.CreateSelfSigned(" example.test ", ECCurve.NamedCurves.nistP256);
            Assert.AreEqual("CN=example.test", credentials.Certificate.Subject);
            Assert.AreEqual(credentials.Certificate.Subject, credentials.Certificate.Issuer);
            Assert.AreEqual("example.test", credentials.Certificate.GetNameInfo(X509NameType.DnsFromAlternativeName, false));
            Assert.AreEqual("1.2.840.10045.2.1", credentials.Certificate.PublicKey.Oid.Value); // id-ecPublicKey

            var p384 = CertificateBuilder.CreateSelfSigned("example.test", ECCurve.NamedCurves.nistP384);
            Assert.AreEqual(384, p384.Certificate.GetECDsaPublicKey().KeySize);
            Assert.AreEqual("1.2.840.10045.4.3.3", p384.Certificate.SignatureAlgorithm.Value); // ecdsa-with-SHA384
            Assert.ThrowsExactly<ArgumentException>(() => CertificateBuilder.CreateSelfSigned("example.test", ECCurve.CreateFromValue("1.2.3.4")));

            var rsa = CertificateBuilder.CreateSelfSigned(rsaKeySize: 1024);
            Assert.AreEqual("CN=SharpDTLS Server", rsa.Certificate.Subject);
            Assert.AreEqual(1024, rsa.Certificate.GetRSAPublicKey().KeySize);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => CertificateBuilder.CreateSelfSigned(rsaKeySize: 512));
        }

        [TestMethod]
        public void ExportPkcs8PrivateKey_OfPkcs8AndOfTheCertificatesOwnKey()
        {
            // of PKCS#8: the same key again, as credentials of the certificate without its key take it
            var built = CertificateBuilder.CreateSelfSigned("example.test", ECCurve.NamedCurves.nistP256);
            byte[] pkcs8 = built.ExportPkcs8PrivateKey();
            var again = new CertificateCredentials(built.Certificate, pkcs8);
            CollectionAssert.AreEqual(pkcs8, again.ExportPkcs8PrivateKey());

            // of the certificate's own key, exportable
            var certificate = TestDotNetCredentials.SelfSigned(ecdsa: false);
            byte[] exported = new CertificateCredentials(certificate).ExportPkcs8PrivateKey();
#if NET
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(exported, out _);
            CollectionAssert.AreEqual(certificate.GetRSAPublicKey().ExportParameters(false).Modulus, rsa.ExportParameters(false).Modulus);
#else
            Assert.IsGreaterThan(0, exported.Length);
#endif
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task CreateSelfSigned_AuthenticatesServerAndClient(bool ecdsa)
        {
            var server = ecdsa ? CertificateBuilder.CreateSelfSigned("server.test", ECCurve.NamedCurves.nistP384) : CertificateBuilder.CreateSelfSigned("server.test", 1024);
            var client = ecdsa ? CertificateBuilder.CreateSelfSigned("client.test", ECCurve.NamedCurves.nistP256) : CertificateBuilder.CreateSelfSigned("client.test", 1024);
            X509Certificate2 seenByClient = null, seenByServer = null;
            using var tls = new TlsServer(server)
            {
                RequireClientCertificate = true,
                ClientCertificateValidator = (certificate, chain) => (seenByServer = certificate) != null,
            };
            await TestDotNetCredentials.Connect(tls, c =>
            {
                c.ServerCertificateValidator = (certificate, chain) => (seenByClient = certificate) != null;
                c.ClientCredentials = client;
            });
            Assert.IsTrue(System.Threading.SpinWait.SpinUntil(() => seenByServer != null, TestTimeouts.InProcess));
            Assert.AreEqual(server.Certificate.Thumbprint, seenByClient.Thumbprint);
            Assert.AreEqual(client.Certificate.Thumbprint, seenByServer.Thumbprint);
        }
    }
}
