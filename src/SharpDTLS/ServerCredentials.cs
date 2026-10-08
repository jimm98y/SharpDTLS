using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>A server certificate, its private key and its intermediate CA certificates.</summary>
    public sealed class ServerCredentials
    {
        public ServerCredentials(AsymmetricCipherKeyPair keyPair, X509Certificate certificate, IList<X509Certificate> intermediateCertificates = null)
        {
            KeyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            IntermediateCertificates = intermediateCertificates ?? Array.Empty<X509Certificate>();
        }

        public AsymmetricCipherKeyPair KeyPair { get; }
        public X509Certificate Certificate { get; }
        public IList<X509Certificate> IntermediateCertificates { get; }

        /// <summary>
        /// A DER OCSP response for <see cref="Certificate"/> to staple for clients that ask (RFC 6066 §8); null for none.
        /// Replace it before it expires.
        /// </summary>
        public byte[] OcspResponse { get; set; }
    }
}
