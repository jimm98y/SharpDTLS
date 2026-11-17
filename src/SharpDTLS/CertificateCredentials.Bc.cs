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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpDTLS
{
    // BouncyCastle's side of the credentials: their PKCS#8 key as BouncyCastle's, and credentials of BouncyCastle's key
    // pairs, as the default self-signed certificate and the tests make them.
    public partial class CertificateCredentials
    {
        /// <summary>Credentials of BouncyCastle's key pair and certificate (null for a raw public key), as the engines and tests take them.</summary>
        internal CertificateCredentials(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            : this(Certificates.ToNet(certificate), intermediateCertificates?.Select(Certificates.ToNet).ToList(), null)
        {
            KeyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
            BcPrivateKey = keyPair.Private;
            PublicKey = TlsPublicKey.Of(keyPair.Public);
        }

        internal static CertificateCredentials Of(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            => keyPair == null ? null : new CertificateCredentials(keyPair, certificate, intermediateCertificates);

        /// <summary>A server's own key pair and certificate: a certificate needs its key pair, and neither is of a PSK-only server.</summary>
        internal static CertificateCredentials OfServer(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate)
            => certificate != null && keyPair == null ? throw new ArgumentException("A certificate needs its key pair.") : Of(keyPair, certificate);

        /// <summary>
        /// The private key as PKCS#8 DER: the one given as PKCS#8, or the certificate's own, which must then be exportable
        /// (a <see cref="System.Security.Cryptography.CryptographicException"/> otherwise). For libraries that hand the key on.
        /// </summary>
        public byte[] ExportPkcs8PrivateKey() => PrivateKeyInfoFactory.CreatePrivateKeyInfo(BouncyCastleTlsCrypto.PrivateKey(this)).GetEncoded();

        /// <summary>The certificate as BouncyCastle's, for the tests.</summary>
        internal BcX509Certificate BcCertificate => Certificates.ToBc(Certificate);

        /// <summary>BouncyCastle's key pair the credentials were made of, or null.</summary>
        internal AsymmetricCipherKeyPair KeyPair { get; private set; }

        /// <summary>The private key as BouncyCastle's: of PKCS#8, or exported of the certificate when first needed.</summary>
        internal AsymmetricKeyParameter BcPrivateKey;

        private void ReadPkcs8(byte[] pkcs8PrivateKey)
        {
            try
            {
                BcPrivateKey = PrivateKeyFactory.CreateKey(pkcs8PrivateKey);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("The private key is not PKCS#8.", "pkcs8PrivateKey", ex);
            }
        }

        // the public key of a raw public key's credentials (no certificate)
        private TlsPublicKey PublicKeyOfPrivateKey() => TlsPublicKey.Of(PublicKeyOf(BcPrivateKey));

        private static AsymmetricKeyParameter PublicKeyOf(AsymmetricKeyParameter privateKey) => privateKey switch
        {
            RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
            ECPrivateKeyParameters ec => ec.PublicKeyParamSet != null
                ? new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D).Normalize(), ec.PublicKeyParamSet)
                : new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
            Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
            Ed448PrivateKeyParameters ed => ed.GeneratePublicKey(),
            _ => throw new ArgumentException("A raw public key of this key type needs its certificate."),
        };
    }

    public sealed partial class ServerCredentials
    {
        internal ServerCredentials(AsymmetricCipherKeyPair keyPair, BcX509Certificate certificate, IList<BcX509Certificate> intermediateCertificates = null)
            : base(keyPair, certificate, intermediateCertificates)
        {
        }
    }
}
