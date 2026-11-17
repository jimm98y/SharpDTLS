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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace SharpDTLS
{
    internal enum TlsKeyKind
    {
        Other,
        Rsa,
        Ec,
        Dsa,
        Dh,
        Ed25519,
        Ed448,
    }

    /// <summary>
    /// A public key as the handshake decides with it: its kind and curve, and its DER SubjectPublicKeyInfo, which the
    /// <see cref="ITlsCrypto"/> verifies and encrypts with. Of a certificate, a raw public key or credentials.
    /// </summary>
    internal sealed class TlsPublicKey
    {
        private AsymmetricKeyParameter _bc;

        private TlsPublicKey(byte[] subjectPublicKeyInfo, TlsKeyKind kind, string curveOid, AsymmetricKeyParameter bc)
        {
            Spki = subjectPublicKeyInfo;
            Kind = kind;
            CurveOid = curveOid;
            _bc = bc;
        }

        /// <summary>The DER SubjectPublicKeyInfo.</summary>
        public byte[] Spki { get; }

        public TlsKeyKind Kind { get; }

        /// <summary>The named curve of an EC key, or null.</summary>
        public string CurveOid { get; }

        /// <summary>The field size of an EC key in bits: of the named curve, or of explicit parameters.</summary>
        public int CurveBits => CurveOid switch
        {
            "1.2.840.10045.3.1.7" => 256,
            "1.3.132.0.34" => 384,
            "1.3.132.0.35" => 521,
            _ => Kind == TlsKeyKind.Ec && Bc is ECKeyParameters ec ? ec.Parameters.Curve.FieldSize : 0,
        };

        /// <summary>The key as BouncyCastle's, for the static (EC)DH arithmetic, which is BouncyCastle's.</summary>
        internal AsymmetricKeyParameter Bc => _bc ??= PublicKeyFactory.CreateKey(Spki);

        /// <summary>Of a DER SubjectPublicKeyInfo; throws for one that does not parse.</summary>
        public static TlsPublicKey FromSpki(byte[] subjectPublicKeyInfo, AsymmetricKeyParameter bc = null)
        {
            var info = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(subjectPublicKeyInfo));
            var kind = info.Algorithm.Algorithm.Id switch
            {
                "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10" => TlsKeyKind.Rsa,
                "1.2.840.10045.2.1" => TlsKeyKind.Ec,
                "1.2.840.10040.4.1" => TlsKeyKind.Dsa,
                "1.2.840.10046.2.1" or "1.2.840.113549.1.3.1" => TlsKeyKind.Dh,
                "1.3.101.112" => TlsKeyKind.Ed25519,
                "1.3.101.113" => TlsKeyKind.Ed448,
                _ => TlsKeyKind.Other,
            };
            string curve = kind == TlsKeyKind.Ec && info.Algorithm.Parameters is DerObjectIdentifier oid ? oid.Id : null;
            return new TlsPublicKey(subjectPublicKeyInfo, kind, curve, bc);
        }

        /// <summary>The key of a certificate.</summary>
        public static TlsPublicKey Of(X509Certificate2 certificate)
            => FromSpki(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certificate.RawData)).SubjectPublicKeyInfo.GetEncoded());

        /// <summary>Of BouncyCastle's public key (credentials of a key pair).</summary>
        public static TlsPublicKey Of(AsymmetricKeyParameter publicKey) => FromSpki(Certificates.Spki(publicKey), publicKey);
    }
}
