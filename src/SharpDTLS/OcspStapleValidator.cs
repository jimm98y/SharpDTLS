// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// The default <see cref="IOcspStapleValidator"/>: checks a stapled OCSP response (RFC 6960) for the server
    /// certificate: a successful response signed by the certificate's issuer or by a responder the issuer delegated to
    /// (id-kp-OCSPSigning), with a "good" status for the certificate that is current. Plug
    /// <see cref="OcspStapleValidatorExtensions.ForServer"/> into a client's ServerCertificateStatusValidator next to a
    /// certificate validator: it checks the response, not the chain. Failures are bad_certificate_status_response, or
    /// certificate_revoked for a revoked certificate.
    /// </summary>
    public sealed class OcspStapleValidator : IOcspStapleValidator
    {
        private readonly List<X509Certificate> _issuers;

        /// <param name="issuers">
        /// Possible issuers of the server certificate besides the ones the server sends, e.g. the root CA when it
        /// issued the certificate directly.
        /// </param>
        public OcspStapleValidator(IEnumerable<X509Certificate> issuers = null) => _issuers = issuers?.ToList() ?? new List<X509Certificate>();

        /// <summary>Fail when the server staples no response (otherwise a missing staple is accepted).</summary>
        public bool Required { get; set; }

        /// <summary>Tolerated clock difference for thisUpdate and nextUpdate.</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>The time the response must be current at; null for now.</summary>
        public DateTime? VerificationTime { get; set; }

        /// <summary>
        /// Checks <paramref name="ocspResponse"/> (null when the server stapled none) for the end entity of
        /// <paramref name="chain"/> and throws a <see cref="DtlsException"/> with the matching alert when it is not acceptable.
        /// </summary>
        public void Validate(byte[] ocspResponse, IReadOnlyList<byte[]> chain)
        {
            if (ocspResponse == null)
            {
                if (Required)
                    throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The server stapled no OCSP response.");
                return;
            }
            if (chain == null || chain.Count == 0)
                throw new DtlsException(AlertDescription.BadCertificate, "No certificate.");

            var parser = new X509CertificateParser();
            var leaf = parser.ReadCertificate(chain[0]);
            var candidates = chain.Skip(1).Select(c => parser.ReadCertificate(c)).Concat(_issuers).ToList();
            var issuer = candidates.FirstOrDefault(c => c.SubjectDN.Equivalent(leaf.IssuerDN) && SignedBy(leaf, c))
                ?? throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The certificate's issuer is unknown, so its OCSP response cannot be checked.");

            BasicOcspResp basic;
            try
            {
                var response = new OcspResp(ocspResponse);
                if (response.Status != OcspRespStatus.Successful)
                    throw new DtlsException(AlertDescription.BadCertificateStatusResponse, $"OCSP response status {response.Status}.");
                basic = response.GetResponseObject() as BasicOcspResp
                    ?? throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "Not a basic OCSP response.");
            }
            catch (Exception ex) when (ex is not DtlsException)
            {
                throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The OCSP response could not be parsed.", ex);
            }

            DateTime now = VerificationTime ?? DateTime.UtcNow;
            if (!SignedByIssuerOrDelegate(basic, issuer, now))
                throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The OCSP response is not signed by the issuer or its responder.");

            var single = basic.Responses.FirstOrDefault(r => r.GetCertID().SerialNumber.Equals(leaf.SerialNumber) && r.GetCertID().MatchesIssuer(issuer))
                ?? throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The OCSP response is for another certificate.");
            if (single.ThisUpdate > now + ClockSkew || (single.NextUpdate.HasValue && single.NextUpdate.Value < now - ClockSkew))
                throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The OCSP response is not current.");

            switch (single.GetCertStatus())
            {
                case null: // good
                    return;
                case RevokedStatus revoked:
                    throw new DtlsException(AlertDescription.CertificateRevoked, $"The certificate was revoked on {revoked.RevocationTime:u}.");
                default:
                    throw new DtlsException(AlertDescription.BadCertificateStatusResponse, "The responder does not know the certificate.");
            }
        }

        private static bool SignedBy(X509Certificate certificate, X509Certificate issuer)
        {
            try
            {
                certificate.Verify(issuer.GetPublicKey());
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // RFC 6960 §4.2.2.2: the issuer itself, or a certificate it issued for id-kp-OCSPSigning.
        private static bool SignedByIssuerOrDelegate(BasicOcspResp basic, X509Certificate issuer, DateTime now)
        {
            if (Verifies(basic, issuer))
                return true;
            foreach (var responder in basic.GetCerts() ?? Array.Empty<X509Certificate>())
            {
                if (!SignedBy(responder, issuer) || !responder.IsValid(now))
                    continue;
                var usages = responder.GetExtendedKeyUsage();
                if (usages != null && usages.Contains(KeyPurposeID.id_kp_OCSPSigning) && Verifies(basic, responder))
                    return true;
            }
            return false;
        }

        private static bool Verifies(BasicOcspResp basic, X509Certificate signer)
        {
            try
            {
                return basic.Verify(signer.GetPublicKey());
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
