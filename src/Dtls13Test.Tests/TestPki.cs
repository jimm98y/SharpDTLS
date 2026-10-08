using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Threading;

namespace Dtls13Test.Tests
{
    /// <summary>A test PKI: root CA → intermediate CA → end-entity certificates (P-256, SHA-256).</summary>
    internal sealed class TestPki
    {
        private static long _serial = DateTime.UtcNow.Ticks;

        public (AsymmetricCipherKeyPair Key, X509Certificate Cert) Root { get; }
        public (AsymmetricCipherKeyPair Key, X509Certificate Cert) Intermediate { get; }

        public TestPki(string name = "SharpDTLS Test")
        {
            var rootKey = NewKey();
            Root = (rootKey, Issue(rootKey.Public, $"CN={name} Root CA", rootKey.Private, $"CN={name} Root CA", rootKey.Public, ca: true));
            var intermediateKey = NewKey();
            Intermediate = (intermediateKey, Issue(intermediateKey.Public, $"CN={name} Intermediate CA", rootKey.Private, Root.Cert.SubjectDN.ToString(), rootKey.Public, ca: true));
        }

        public static AsymmetricCipherKeyPair NewKey()
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
            return generator.GenerateKeyPair();
        }

        /// <summary>An end-entity certificate issued by the intermediate CA.</summary>
        public (AsymmetricCipherKeyPair Key, X509Certificate Cert) Leaf(string[] dnsNames = null, string[] ipAddresses = null,
            KeyPurposeID usage = null, DateTime? notBefore = null, DateTime? notAfter = null, string commonName = "leaf")
        {
            var key = NewKey();
            var cert = Issue(key.Public, $"CN={commonName}", Intermediate.Key.Private, Intermediate.Cert.SubjectDN.ToString(), Intermediate.Key.Public,
                ca: false, dnsNames, ipAddresses, usage ?? KeyPurposeID.id_kp_serverAuth, notBefore, notAfter);
            return (key, cert);
        }

        private static X509Certificate Issue(AsymmetricKeyParameter subjectKey, string subject, AsymmetricKeyParameter issuerKey, string issuer,
            AsymmetricKeyParameter issuerPublicKey, bool ca, string[] dnsNames = null, string[] ipAddresses = null, KeyPurposeID usage = null,
            DateTime? notBefore = null, DateTime? notAfter = null)
        {
            var g = new X509V3CertificateGenerator();
            g.SetSerialNumber(BigInteger.ValueOf(Interlocked.Increment(ref _serial)));
            g.SetIssuerDN(new X509Name(issuer));
            g.SetSubjectDN(new X509Name(subject));
            g.SetNotBefore(notBefore ?? DateTime.UtcNow.AddDays(-1));
            g.SetNotAfter(notAfter ?? DateTime.UtcNow.AddYears(1));
            g.SetPublicKey(subjectKey);
            g.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
            g.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(ca ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature));
            g.AddExtension(X509Extensions.SubjectKeyIdentifier, false, X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectKey));
            g.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerPublicKey));
            if (!ca)
            {
                g.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usage));
                var names = new System.Collections.Generic.List<GeneralName>();
                foreach (string dns in dnsNames ?? Array.Empty<string>())
                    names.Add(new GeneralName(GeneralName.DnsName, dns));
                foreach (string ip in ipAddresses ?? Array.Empty<string>())
                    names.Add(new GeneralName(GeneralName.IPAddress, ip));
                if (names.Count > 0)
                    g.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(names.ToArray()));
            }
            return g.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", issuerKey, new SecureRandom()));
        }
    }
}
