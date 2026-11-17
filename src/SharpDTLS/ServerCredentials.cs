using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    /// <summary>A certificate, its private key and its intermediate CA certificates.</summary>
    public class CertificateCredentials
    {
        /// <summary>A certificate with its own private key (<see cref="X509Certificate2.HasPrivateKey"/>).</summary>
        public CertificateCredentials(X509Certificate2 certificate, IList<X509Certificate2> intermediateCertificates = null)
            : this(certificate ?? throw new ArgumentNullException(nameof(certificate)), null, null, intermediateCertificates)
        {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("The certificate has no private key; pass the key as PKCS#8.", nameof(certificate));
        }

        /// <summary>
        /// A certificate and its private key as PKCS#8 DER, for keys .NET has no type for (Ed25519, Ed448, DH).
        /// <paramref name="certificate"/> may be null to authenticate with the raw public key alone (RFC 7250).
        /// </summary>
        public CertificateCredentials(X509Certificate2 certificate, byte[] pkcs8PrivateKey, IList<X509Certificate2> intermediateCertificates = null)
            : this(certificate, pkcs8PrivateKey ?? throw new ArgumentNullException(nameof(pkcs8PrivateKey)), null, intermediateCertificates)
        {
        }

        private protected CertificateCredentials(X509Certificate2 certificate, byte[] pkcs8PrivateKey, AsymmetricCipherKeyPair keyPair, IList<X509Certificate2> intermediateCertificates)
        {
            Certificate = certificate;
            IntermediateCertificates = intermediateCertificates ?? Array.Empty<X509Certificate2>();
            if (keyPair != null)
            {
                KeyPair = keyPair;
                BcPrivateKey = keyPair.Private;
                PublicKey = TlsPublicKey.Of(keyPair.Public);
                return;
            }
            if (pkcs8PrivateKey != null)
            {
                try
                {
                    BcPrivateKey = PrivateKeyFactory.CreateKey(pkcs8PrivateKey);
                }
                catch (Exception ex)
                {
                    throw new ArgumentException("The private key is not PKCS#8.", nameof(pkcs8PrivateKey), ex);
                }
                HasPkcs8PrivateKey = true;
            }
            PublicKey = certificate != null ? TlsPublicKey.Of(certificate) : TlsPublicKey.Of(PublicKeyOf(BcPrivateKey));
        }

        /// <summary>Credentials of BouncyCastle's key pair and certificate (null for a raw public key), as the engines and tests take them.</summary>
        internal CertificateCredentials(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            : this(Certificates.ToNet(certificate), null, keyPair ?? throw new ArgumentNullException(nameof(keyPair)), intermediateCertificates?.Select(Certificates.ToNet).ToList())
        {
        }

        internal static CertificateCredentials Of(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            => keyPair == null ? null : new CertificateCredentials(keyPair, certificate, intermediateCertificates);

        /// <summary>A server's own key pair and certificate: a certificate needs its key pair, and neither is of a PSK-only server.</summary>
        internal static CertificateCredentials OfServer(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate)
            => certificate != null && keyPair == null ? throw new ArgumentException("A certificate needs its key pair.") : Of(keyPair, certificate);

        public X509Certificate2 Certificate { get; }
        public IList<X509Certificate2> IntermediateCertificates { get; }

        /// <summary>The certificate as BouncyCastle's, for the tests.</summary>
        internal BcX509Certificate BcCertificate => Certificates.ToBc(Certificate);

        /// <summary>BouncyCastle's key pair the credentials were made of, or null.</summary>
        internal AsymmetricCipherKeyPair KeyPair { get; }

        /// <summary>The public key of the private key: the certificate's, or the raw public key's.</summary>
        internal TlsPublicKey PublicKey { get; }

        /// <summary>The private key as BouncyCastle's: of PKCS#8, or exported of the certificate when first needed.</summary>
        internal AsymmetricKeyParameter BcPrivateKey;

        /// <summary>The key was given as PKCS#8, not as the certificate's own.</summary>
        internal bool HasPkcs8PrivateKey { get; }

        /// <summary>The DER of the intermediates, as sent after the certificate.</summary>
        internal IEnumerable<byte[]> IntermediateChain => IntermediateCertificates.Select(c => c.RawData);

        private static AsymmetricKeyParameter PublicKeyOf(AsymmetricKeyParameter privateKey) => privateKey switch
        {
            RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
            ECPrivateKeyParameters ec => ec.PublicKeyParamSet != null
                ? new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D).Normalize(), ec.PublicKeyParamSet)
                : new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
            Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
            Ed448PrivateKeyParameters ed => ed.GeneratePublicKey(),
            _ => throw new ArgumentException("A raw public key of this key type needs its certificate."),
        };
    }

    /// <summary>A server certificate, its private key, its intermediate CA certificates and an optional OCSP staple.</summary>
    public sealed class ServerCredentials : CertificateCredentials
    {
        /// <summary>A certificate with its own private key (<see cref="X509Certificate2.HasPrivateKey"/>).</summary>
        public ServerCredentials(X509Certificate2 certificate, IList<X509Certificate2> intermediateCertificates = null)
            : base(certificate, intermediateCertificates)
        {
        }

        /// <summary>
        /// A certificate and its private key as PKCS#8 DER, for keys .NET has no type for (Ed25519, Ed448, DH).
        /// <paramref name="certificate"/> may be null to authenticate with the raw public key alone (RFC 7250).
        /// </summary>
        public ServerCredentials(X509Certificate2 certificate, byte[] pkcs8PrivateKey, IList<X509Certificate2> intermediateCertificates = null)
            : base(certificate, pkcs8PrivateKey, intermediateCertificates)
        {
        }

        internal ServerCredentials(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            : base(Certificates.ToNet(certificate), null, keyPair, intermediateCertificates?.Select(Certificates.ToNet).ToList())
        {
        }

        /// <summary>
        /// A DER OCSP response for <see cref="Certificate"/> to staple for clients that ask (RFC 6066 §8); null for none.
        /// Replace it before it expires.
        /// </summary>
        public byte[] OcspResponse { get; set; }
    }
}
