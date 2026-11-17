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
using System.Security.Cryptography;

namespace SharpDTLS
{
    /// <summary>
    /// Certificates and their keys made by the library, of every framework. Each is a server's credentials, and a
    /// client's <see cref="TlsClientBase.ClientCredentials"/> too.
    /// </summary>
    public static class CertificateBuilder
    {
        /// <summary>A new self-signed RSA certificate and its key: for tests, demos and peers that pin it.</summary>
        /// <param name="hostName">The subject's CN and the subjectAltName DNS name; null for "CN=SharpDTLS Server" and none.</param>
        /// <param name="rsaKeySize">The modulus size, at least 1024: generating 2048 bits takes a while.</param>
        public static ServerCredentials CreateSelfSigned(string hostName = null, int rsaKeySize = 2048)
        {
            if (rsaKeySize < 1024)
                throw new ArgumentOutOfRangeException(nameof(rsaKeySize));
            var (keyPair, certificate) = SelfSigned.Rsa(HostName(hostName), rsaKeySize);
            return new ServerCredentials(keyPair, certificate);
        }

        /// <summary>
        /// A new self-signed ECDSA certificate and its key on <paramref name="curve"/>, a named curve such as
        /// <see cref="ECCurve.NamedCurves.nistP256"/>; signed with SHA-256, SHA-384 or SHA-512 by the curve's size.
        /// </summary>
        /// <param name="hostName">The subject's CN and the subjectAltName DNS name; null for "CN=SharpDTLS Server" and none.</param>
        /// <param name="curve">The key's curve. TLS 1.3 signs with P-256, P-384 and P-521 (and brainpool where offered).</param>
        public static ServerCredentials CreateSelfSigned(string hostName, ECCurve curve)
        {
            if (!curve.IsNamed)
                throw new ArgumentException("Only named curves are supported.", nameof(curve));
            var (keyPair, certificate) = SelfSigned.Ec(HostName(hostName), Certificates.CurveOid(curve));
            return new ServerCredentials(keyPair, certificate);
        }

        private static string HostName(string hostName) => string.IsNullOrWhiteSpace(hostName) ? null : hostName.Trim();
    }
}
