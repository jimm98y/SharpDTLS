using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    /// <summary>
    /// Validates peer certificate chains with the platform's path validation (<see cref="X509Chain"/>): signatures,
    /// validity periods, basic constraints, key usage for the peer's role (serverAuth or clientAuth) and, for
    /// servers, the host name (RFC 6125). Plug it into a ServerCertificateValidator or ClientCertificateValidator
    /// with <see cref="ForServer"/> or <see cref="ForClient"/>. Failures abort the handshake with
    /// certificate_expired, unknown_ca or bad_certificate.
    /// </summary>
    public sealed class CertificateValidator
    {
        private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
        private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

        private readonly X509Certificate2Collection _trustedRoots;

        /// <summary>
        /// Trusts only <paramref name="trustedRoots"/>; with null, the operating system's trust store.
        /// </summary>
        public CertificateValidator(IEnumerable<BcX509Certificate> trustedRoots = null)
        {
            if (trustedRoots != null)
            {
                _trustedRoots = new X509Certificate2Collection();
                foreach (var root in trustedRoots)
                    _trustedRoots.Add(X509CertificateLoader.LoadCertificate(root.GetEncoded()));
            }
        }

        /// <summary>Revocation checking (CRL/OCSP downloads); off by default, as are AIA certificate downloads.</summary>
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.NoCheck;

        /// <summary>Also accept a host name in the subject Common Name when the certificate has no matching SAN.</summary>
        public bool AllowCommonNameFallback { get; set; }

        /// <summary>The time the chain must be valid at; null for now.</summary>
        public DateTime? VerificationTime { get; set; }

        /// <summary>
        /// A server certificate validator: the chain must lead to a trusted root, allow serverAuth and match
        /// <paramref name="hostName"/> (a DNS name or IP address; null skips the name check).
        /// </summary>
        public Func<BcX509Certificate, IReadOnlyList<byte[]>, bool> ForServer(string hostName)
            => (certificate, chain) => { Validate(chain, ServerAuth, hostName); return true; };

        /// <summary>A client certificate validator: the chain must lead to a trusted root and allow clientAuth.</summary>
        public Func<BcX509Certificate, IReadOnlyList<byte[]>, bool> ForClient()
            => (certificate, chain) => { Validate(chain, ClientAuth, null); return true; };

        /// <summary>
        /// Validates <paramref name="chain"/> (DER, end entity first, as received) and throws a
        /// <see cref="DtlsException"/> with the matching alert when it is not acceptable.
        /// </summary>
        public void Validate(IReadOnlyList<byte[]> chain, string usage, string hostName)
        {
            if (chain == null || chain.Count == 0)
                throw new DtlsException(AlertDescription.BadCertificate, "No certificate.");

            using var leaf = Load(chain[0]);
            using var x509Chain = new X509Chain();
            var policy = x509Chain.ChainPolicy;
            policy.RevocationMode = RevocationMode;
            policy.DisableCertificateDownloads = true;
            policy.VerificationTime = VerificationTime ?? DateTime.Now;
            policy.ApplicationPolicy.Add(new Oid(usage));
            foreach (byte[] intermediate in chain.Skip(1))
                policy.ExtraStore.Add(Load(intermediate));
            if (_trustedRoots != null)
            {
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.AddRange(_trustedRoots);
            }

            if (!x509Chain.Build(leaf))
            {
                var problems = x509Chain.ChainStatus.Select(s => s.Status).Aggregate(X509ChainStatusFlags.NoError, (a, b) => a | b);
                string detail = string.Join("; ", x509Chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct());
                throw new DtlsException(Alert(problems), $"Certificate chain is not valid: {problems}. {detail}");
            }

            if (hostName != null && !leaf.MatchesHostname(hostName, allowWildcards: true, allowCommonName: AllowCommonNameFallback))
                throw new DtlsException(AlertDescription.BadCertificate, $"Certificate does not match {hostName}.");
        }

        private static AlertDescription Alert(X509ChainStatusFlags problems)
        {
            if ((problems & (X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested)) != 0)
                return AlertDescription.CertificateExpired;
            if ((problems & X509ChainStatusFlags.Revoked) != 0)
                return AlertDescription.CertificateRevoked;
            if ((problems & (X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain)) != 0)
                return AlertDescription.UnknownCa;
            if ((problems & X509ChainStatusFlags.NotValidForUsage) != 0)
                return AlertDescription.UnsupportedCertificate;
            return AlertDescription.BadCertificate;
        }

        private static X509Certificate2 Load(byte[] der)
        {
            try
            {
                return X509CertificateLoader.LoadCertificate(der);
            }
            catch (CryptographicException ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "Certificate could not be parsed.", ex);
            }
        }
    }
}
