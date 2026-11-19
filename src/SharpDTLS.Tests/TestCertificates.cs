using Org.BouncyCastle.Crypto;
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

        /// <summary>An engine's certificate as BouncyCastle's, to compare with the tests' (equal of the same DER).</summary>
        public static BcX509Certificate Bc(this X509Certificate2 certificate) => Certificates.ToBc(certificate);

        public static X509Certificate2[] Net(this IEnumerable<BcX509Certificate> certificates) => certificates.Select(Net).ToArray();

        public static bool Equivalent(this X500DistinguishedName name, X509Name other) => X509Name.GetInstance(name.RawData).Equivalent(other);

        /// <summary>A server's credentials of a BouncyCastle key pair and certificate (null and null for a PSK-only server).</summary>
        public static TransportCertificate Server(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate) => TransportCertificate.OfServer(keyPair, certificate);

        public static TransportCertificate Server((AsymmetricCipherKeyPair Key, BcX509Certificate Cert) pair) => Server(pair.Key, pair.Cert);

        /// <summary>A client's credentials of a BouncyCastle key pair, its certificate (null for a raw public key) and intermediates.</summary>
        public static TransportCertificate Credentials(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediates = null)
            => TransportCertificate.Of(keyPair, certificate, intermediates);

        public static TransportCertificate Credentials((AsymmetricCipherKeyPair Key, BcX509Certificate Cert) pair, IList<BcX509Certificate> intermediates = null)
            => Credentials(pair.Key, pair.Cert, intermediates);

        /// <summary>The .NET certificates of BouncyCastle's, or null.</summary>
        public static X509Certificate2[] NetOrNull(this IEnumerable<BcX509Certificate> certificates) => certificates?.Select(Net).ToArray();
    }
}
