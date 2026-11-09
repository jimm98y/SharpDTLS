using System;
using System.Collections.Generic;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    /// <summary>
    /// Validates a peer's certificate chain. <see cref="CertificateValidator"/> is the default implementation, with the
    /// platform's path validation; implement this to validate some other way, such as by pinning, and plug it into a
    /// ServerCertificateValidator or ClientCertificateValidator with
    /// <see cref="CertificateValidatorExtensions.ForServer"/> or <see cref="CertificateValidatorExtensions.ForClient"/>.
    /// </summary>
    public interface ICertificateValidator
    {
        /// <summary>
        /// Validates <paramref name="chain"/> (DER, end entity first, as received) and throws a <see cref="DtlsException"/>
        /// with the alert to send when it is not acceptable; any other exception aborts the handshake as well.
        /// </summary>
        /// <param name="chain">The peer's certificates, DER encoded, end entity first.</param>
        /// <param name="usage">
        /// The extended key usage the peer's role needs: <see cref="CertificateValidator.ServerAuthentication"/> or
        /// <see cref="CertificateValidator.ClientAuthentication"/>.
        /// </param>
        /// <param name="hostName">The name the server certificate must match (a DNS name or IP address); null to skip the check.</param>
        void Validate(IReadOnlyList<byte[]> chain, string usage, string hostName);
    }

    /// <summary>Turns an <see cref="ICertificateValidator"/> into a ServerCertificateValidator or ClientCertificateValidator.</summary>
    public static class CertificateValidatorExtensions
    {
        /// <summary>
        /// A server certificate validator: the chain must be valid for serverAuth and match <paramref name="hostName"/>
        /// (a DNS name or IP address; null skips the name check).
        /// </summary>
        public static Func<BcX509Certificate, IReadOnlyList<byte[]>, bool> ForServer(this ICertificateValidator validator, string hostName)
        {
            if (validator == null)
                throw new ArgumentNullException(nameof(validator));
            return (certificate, chain) => { validator.Validate(chain, CertificateValidator.ServerAuthentication, hostName); return true; };
        }

        /// <summary>A client certificate validator: the chain must be valid for clientAuth.</summary>
        public static Func<BcX509Certificate, IReadOnlyList<byte[]>, bool> ForClient(this ICertificateValidator validator)
        {
            if (validator == null)
                throw new ArgumentNullException(nameof(validator));
            return (certificate, chain) => { validator.Validate(chain, CertificateValidator.ClientAuthentication, null); return true; };
        }
    }
}
