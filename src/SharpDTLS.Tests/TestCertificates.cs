using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS.Tests
{
    /// <summary>The tests' BouncyCastle certificates, as the public API takes them.</summary>
    internal static class TestCertificates
    {
        public static X509Certificate2 Net(this BcX509Certificate certificate) => Certificates.ToNet(certificate);

        public static X509Certificate2[] Net(this IEnumerable<BcX509Certificate> certificates) => certificates.Select(Net).ToArray();

        public static bool Equivalent(this X500DistinguishedName name, X509Name other) => X509Name.GetInstance(name.RawData).Equivalent(other);
    }
}
