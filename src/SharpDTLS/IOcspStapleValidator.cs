using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// Checks the OCSP response a server stapled for its certificate. <see cref="OcspStapleValidator"/> is the default
    /// implementation (RFC 6960); implement this to check it some other way, and plug it into a client's
    /// ServerCertificateStatusValidator with <see cref="OcspStapleValidatorExtensions.ForServer"/>.
    /// </summary>
    public interface IOcspStapleValidator
    {
        /// <summary>
        /// Checks <paramref name="ocspResponse"/> for the end entity of <paramref name="chain"/> and throws a
        /// <see cref="DtlsException"/> with the alert to send when it is not acceptable; any other exception aborts the
        /// handshake as well.
        /// </summary>
        /// <param name="ocspResponse">The DER encoded OCSPResponse the server stapled; null when it stapled none.</param>
        /// <param name="chain">The server's certificates, DER encoded, end entity first, as received.</param>
        void Validate(byte[] ocspResponse, IReadOnlyList<byte[]> chain);
    }

    /// <summary>Turns an <see cref="IOcspStapleValidator"/> into a ServerCertificateStatusValidator.</summary>
    public static class OcspStapleValidatorExtensions
    {
        /// <summary>A ServerCertificateStatusValidator: (OCSP response or null, the server's chain as received).</summary>
        public static Func<byte[], IReadOnlyList<byte[]>, bool> ForServer(this IOcspStapleValidator validator)
        {
            if (validator == null)
                throw new ArgumentNullException(nameof(validator));
            return (response, chain) => { validator.Validate(response, chain); return true; };
        }
    }
}
