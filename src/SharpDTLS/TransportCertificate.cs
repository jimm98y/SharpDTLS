using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SharpDTLS
{
    /// <summary>
    /// A certificate, its private key and its intermediate CA certificates: what a server or a client authenticates
    /// with, a server's with an optional OCSP staple.
    /// </summary>
    public sealed partial class TransportCertificate
    {
        /// <summary>A certificate with its own private key (<see cref="X509Certificate2.HasPrivateKey"/>).</summary>
        public TransportCertificate(X509Certificate2 certificate, IList<X509Certificate2> intermediateCertificates = null)
            : this(certificate ?? throw new ArgumentNullException(nameof(certificate)), intermediateCertificates, null)
        {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("The certificate has no private key; pass the key as PKCS#8.", nameof(certificate));
        }

        /// <summary>
        /// A certificate and its private key as PKCS#8 DER, for keys .NET has no type for (Ed25519, Ed448, DH).
        /// <paramref name="certificate"/> may be null to authenticate with the raw public key alone (RFC 7250).
        /// </summary>
        public TransportCertificate(X509Certificate2 certificate, byte[] pkcs8PrivateKey, IList<X509Certificate2> intermediateCertificates = null)
            : this(certificate, intermediateCertificates, pkcs8PrivateKey ?? throw new ArgumentNullException(nameof(pkcs8PrivateKey)))
        {
        }

        private TransportCertificate(X509Certificate2 certificate, IList<X509Certificate2> intermediateCertificates, byte[] pkcs8PrivateKey)
        {
            Certificate = certificate;
            IntermediateCertificates = intermediateCertificates ?? Array.Empty<X509Certificate2>();
            if (pkcs8PrivateKey != null)
            {
                ReadPkcs8(pkcs8PrivateKey);
                HasPkcs8PrivateKey = true;
            }
            PublicKey = certificate != null ? TlsPublicKey.Of(certificate) : pkcs8PrivateKey != null ? PublicKeyOfPrivateKey() : null;
        }

        public X509Certificate2 Certificate { get; }
        public IList<X509Certificate2> IntermediateCertificates { get; }

        /// <summary>The public key of the private key: the certificate's, or the raw public key's.</summary>
        internal TlsPublicKey PublicKey { get; private set; }

        /// <summary>The key was given as PKCS#8, not as the certificate's own.</summary>
        internal bool HasPkcs8PrivateKey { get; }

        /// <summary>The DER of the intermediates, as sent after the certificate.</summary>
        internal IEnumerable<byte[]> IntermediateChain => IntermediateCertificates.Select(c => c.RawData);

        /// <summary>
        /// A DER OCSP response for <see cref="Certificate"/> to staple for clients that ask, when it is a server's (RFC 6066 §8); null for none.
        /// Replace it before it expires.
        /// </summary>
        public byte[] OcspResponse { get; set; }
    }
}
