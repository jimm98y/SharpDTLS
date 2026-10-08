using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>A certificate, its private key and its intermediate CA certificates.</summary>
    public class CertificateCredentials
    {
        public CertificateCredentials(AsymmetricCipherKeyPair keyPair, X509Certificate certificate, IList<X509Certificate> intermediateCertificates = null)
        {
            KeyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            IntermediateCertificates = intermediateCertificates ?? Array.Empty<X509Certificate>();
        }

        public AsymmetricCipherKeyPair KeyPair { get; }
        public X509Certificate Certificate { get; }
        public IList<X509Certificate> IntermediateCertificates { get; }
    }

    /// <summary>A server certificate, its private key, its intermediate CA certificates and an optional OCSP staple.</summary>
    public sealed class ServerCredentials : CertificateCredentials
    {
        public ServerCredentials(AsymmetricCipherKeyPair keyPair, X509Certificate certificate, IList<X509Certificate> intermediateCertificates = null)
            : base(keyPair, certificate, intermediateCertificates)
        {
        }

        /// <summary>
        /// A DER OCSP response for <see cref="Certificate"/> to staple for clients that ask (RFC 6066 §8); null for none.
        /// Replace it before it expires.
        /// </summary>
        public byte[] OcspResponse { get; set; }
    }
}
