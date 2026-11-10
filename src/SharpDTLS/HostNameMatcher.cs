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

#if !NETCOREAPP
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Linq;
using System.Net;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    /// <summary>
    /// Host name verification (RFC 6125) for netstandard2.0, which lacks <c>X509Certificate2.MatchesHostname</c>: DNS
    /// names and IP addresses in the subject alternative names, a wildcard only as the whole leftmost label, and the
    /// Common Name only when allowed and the certificate has no subject alternative names.
    /// </summary>
    internal static class HostNameMatcher
    {
        public static bool Matches(byte[] certificate, string hostName, bool allowCommonName)
        {
            var cert = new BcX509Certificate(certificate);
            var extension = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            bool isAddress = IPAddress.TryParse(hostName, out var address);
            string name = hostName.TrimEnd('.');

            if (extension != null)
            {
                foreach (var generalName in GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(extension)).GetNames())
                {
                    if (isAddress && generalName.TagNo == GeneralName.IPAddress
                        && Asn1OctetString.GetInstance(generalName.Name).GetOctets().AsSpan().SequenceEqual(address.GetAddressBytes()))
                        return true;
                    if (!isAddress && generalName.TagNo == GeneralName.DnsName && DnsNameMatches(DerIA5String.GetInstance(generalName.Name).GetString(), name))
                        return true;
                }
                return false;
            }

            if (!allowCommonName || isAddress)
                return false;
            var commonNames = cert.SubjectDN.GetValueList(X509Name.CN);
            return commonNames.Count > 0 && DnsNameMatches(commonNames[commonNames.Count - 1], name);
        }

        private static bool DnsNameMatches(string pattern, string hostName)
        {
            pattern = pattern.TrimEnd('.');
            if (!pattern.StartsWith("*.", StringComparison.Ordinal))
                return string.Equals(pattern, hostName, StringComparison.OrdinalIgnoreCase);

            // "*.example.com" matches exactly one label in place of the asterisk.
            int dot = hostName.IndexOf('.');
            return dot > 0 && pattern.Skip(1).Count(c => c == '.') >= 2
                && string.Equals(pattern.Substring(1), hostName.Substring(dot), StringComparison.OrdinalIgnoreCase);
        }
    }
}
#endif
