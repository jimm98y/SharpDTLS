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


using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace SharpDTLS
{
    /// <summary>Certificates between the public API's <see cref="X509Certificate2"/> and BouncyCastle's, inside.</summary>
    internal static class Certificates
    {
        /// <summary>The DER SubjectPublicKeyInfo of a BouncyCastle public key.</summary>
        public static byte[] Spki(Org.BouncyCastle.Crypto.AsymmetricKeyParameter key)
            => Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetEncoded();

        public static X509Certificate ToBc(X509Certificate2 certificate)
            => certificate == null ? null : new X509CertificateParser().ReadCertificate(certificate.RawData)
                ?? throw new ArgumentException("The certificate could not be parsed.", nameof(certificate));

        public static List<X509Certificate> ToBc(IEnumerable<X509Certificate2> certificates) => certificates?.Select(ToBc).ToList();

        public static X509Certificate2 ToNet(X509Certificate certificate) => certificate == null ? null : Load(certificate.GetEncoded());

        /// <summary>The OID of a named curve; Windows names some only (nistP256, ECDSA_P256...).</summary>
        public static DerObjectIdentifier CurveOid(ECCurve curve)
        {
            string oid = curve.Oid?.Value;
            if (string.IsNullOrEmpty(oid))
            {
                oid = curve.Oid?.FriendlyName switch
                {
                    "nistP256" or "ECDSA_P256" or "ECDH_P256" or "secp256r1" => "1.2.840.10045.3.1.7",
                    "nistP384" or "ECDSA_P384" or "ECDH_P384" or "secp384r1" => "1.3.132.0.34",
                    "nistP521" or "ECDSA_P521" or "ECDH_P521" or "secp521r1" => "1.3.132.0.35",
                    _ => throw new CryptographicException("Only named curves are supported."),
                };
            }
            return new DerObjectIdentifier(oid);
        }

        /// <summary>A DER certificate; one that cannot be parsed is a bad_certificate.</summary>
        public static X509Certificate2 Load(byte[] der)
        {
            try
            {
#if NET9_0_OR_GREATER
                return System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(der);
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
