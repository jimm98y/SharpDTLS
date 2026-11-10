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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    /// <summary>
    /// The default <see cref="ICertificateValidator"/>: validates peer certificate chains with the platform's path
    /// validation (<see cref="X509Chain"/>): signatures, validity periods, basic constraints, key usage for the peer's
    /// role (serverAuth or clientAuth) and, for servers, the host name (RFC 6125). Plug it into a
    /// ServerCertificateValidator or ClientCertificateValidator with
    /// <see cref="CertificateValidatorExtensions.ForServer"/> or <see cref="CertificateValidatorExtensions.ForClient"/>.
    /// Failures abort the handshake with certificate_expired, unknown_ca or bad_certificate.
    /// </summary>
    public sealed class CertificateValidator : ICertificateValidator
    {
        /// <summary>The serverAuth extended key usage (RFC 5280 §4.2.1.12): the usage a server's chain is validated for.</summary>
        public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

        /// <summary>The clientAuth extended key usage (RFC 5280 §4.2.1.12): the usage a client's chain is validated for.</summary>
        public const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

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
                    _trustedRoots.Add(Load(root.GetEncoded()));
            }
        }

        /// <summary>Revocation checking (CRL/OCSP downloads); off by default, as are AIA certificate downloads.</summary>
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.NoCheck;

        /// <summary>Also accept a host name in the subject Common Name when the certificate has no matching SAN.</summary>
        public bool AllowCommonNameFallback { get; set; }

        /// <summary>The time the chain must be valid at; null for now.</summary>
        public DateTime? VerificationTime { get; set; }

        /// <summary>
        /// Replaces the built-in host name check (RFC 6125: subject alternative names, wildcards, optionally the Common
        /// Name): gets the server certificate and the expected host name, and returns whether they match. The chain is
        /// validated as usual either way.
        /// </summary>
        public Func<BcX509Certificate, string, bool> HostNameValidator { get; set; }

        /// <summary>
        /// Validates <paramref name="chain"/> (DER, end entity first, as received): it must lead to a trusted root and
        /// allow <paramref name="usage"/>, and the end entity must match <paramref name="hostName"/> unless it is null.
        /// Throws a <see cref="DtlsException"/> with the matching alert when it is not acceptable.
        /// </summary>
        public void Validate(IReadOnlyList<byte[]> chain, string usage, string hostName)
        {
            if (chain == null || chain.Count == 0)
                throw new DtlsException(AlertDescription.BadCertificate, "No certificate.");

            using var leaf = Load(chain[0]);
            using var x509Chain = new X509Chain();
            var policy = x509Chain.ChainPolicy;
            policy.RevocationMode = RevocationMode;
#if NETCOREAPP
            policy.DisableCertificateDownloads = true;
#endif
            policy.VerificationTime = VerificationTime ?? DateTime.Now;
            policy.ApplicationPolicy.Add(new Oid(usage));
            foreach (byte[] intermediate in chain.Skip(1))
                policy.ExtraStore.Add(Load(intermediate));
            if (_trustedRoots != null)
            {
#if !NETCOREAPP
                // No custom root trust here: build with the roots as extra certificates, then require one of them at the top.
                policy.ExtraStore.AddRange(_trustedRoots);
                policy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
#else
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.AddRange(_trustedRoots);
#endif
            }

            if (!BuildChain(x509Chain, leaf, out var problems))
            {
                string detail = string.Join("; ", x509Chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct());
                throw new DtlsException(Alert(problems), $"Certificate chain is not valid: {problems}. {detail}");
            }

            if (hostName != null && !MatchesHostName(leaf, chain[0], hostName))
                throw new DtlsException(AlertDescription.BadCertificate, $"Certificate does not match {hostName}.");
        }

        private bool BuildChain(X509Chain x509Chain, X509Certificate2 leaf, out X509ChainStatusFlags problems)
        {
            bool built = x509Chain.Build(leaf);
            problems = x509Chain.ChainStatus.Select(s => s.Status).Aggregate(X509ChainStatusFlags.NoError, (a, b) => a | b);
#if !NETCOREAPP
            if (_trustedRoots != null)
            {
                // Allowed unknown authority: the chain must still end at one of our roots, and nothing else may be wrong.
                var top = x509Chain.ChainElements[x509Chain.ChainElements.Count - 1].Certificate;
                bool trusted = _trustedRoots.Cast<X509Certificate2>().Any(r => r.RawData.AsSpan().SequenceEqual(top.RawData));
                problems &= ~X509ChainStatusFlags.UntrustedRoot;
                if (!trusted)
                    problems |= X509ChainStatusFlags.UntrustedRoot;
                return problems == X509ChainStatusFlags.NoError;
            }
#endif
            return built;
        }

        private bool MatchesHostName(X509Certificate2 leaf, byte[] der, string hostName)
        {
            if (HostNameValidator != null)
                return HostNameValidator(new BcX509Certificate(der), hostName);
#if !NETCOREAPP
            return HostNameMatcher.Matches(der, hostName, AllowCommonNameFallback);
#else
            return leaf.MatchesHostname(hostName, allowWildcards: true, allowCommonName: AllowCommonNameFallback);
#endif
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
#if NET9_0_OR_GREATER
                return X509CertificateLoader.LoadCertificate(der);
#else
                return new X509Certificate2(der);
#endif
            }
            catch (CryptographicException ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "Certificate could not be parsed.", ex);
            }
        }
    }
}
