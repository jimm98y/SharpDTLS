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
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SharpDTLS.Protocol13;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace SharpDTLS
{
    /// <summary>The default <see cref="ITlsCrypto"/>: the private key is BouncyCastle's.</summary>
    public class BouncyCastleTlsCrypto : ITlsCrypto
    {
        /// <summary>The instance used when none is set.</summary>
        public static BouncyCastleTlsCrypto Default { get; } = new BouncyCastleTlsCrypto();

        public virtual byte[] Sign(CertificateCredentials credentials, ushort scheme, byte[] content)
        {
            var key = PrivateKey(credentials);
            return BcSignatures.Sign(scheme, key, content);
        }

        public virtual byte[] DecryptPreMasterSecret(CertificateCredentials credentials, byte[] encrypted)
        {
            // of a padding or length failure, 48 random bytes in constant time
            var rsa = new Pkcs1Encoding(new RsaBlindedEngine(), 48);
            rsa.Init(false, PrivateKey(credentials));
            try
            {
                return rsa.ProcessBlock(encrypted, 0, encrypted.Length);
            }
            catch (System.Exception ex) when (ex is InvalidCipherTextException || ex is DataLengthException)
            {
                throw new CryptographicException("RSA decryption failed.", ex);
            }
        }

        public virtual byte[] Agree(CertificateCredentials credentials, byte[] peerPublicKey) => PrivateKey(credentials) switch
        {
            DHPrivateKeyParameters dh => DhUtilities.Agree(dh.Parameters, dh.X, new BigInteger(1, peerPublicKey)),
            ECPrivateKeyParameters ec => StaticEcdh.Agree(ec, peerPublicKey),
            _ => throw new CryptographicException("The key is not a key agreement key."),
        };

        public virtual ITlsAead CreateAead(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key) => BcPrimitives.Aead(algorithm, key);

        public virtual ITlsBlockCipher CreateBlockCipher(TlsBlockCipherAlgorithm algorithm, ReadOnlySpan<byte> key) => BcPrimitives.BlockCipher(algorithm, key);

        public virtual ITlsHash CreateHash(TlsHashAlgorithm hash) => new BcHash(BcPrimitives.Digest(hash));

        public virtual ITlsHash CreateHmac(TlsHashAlgorithm hash, ReadOnlySpan<byte> key) => new BcHash(BcPrimitives.Digest(hash), key);

        public virtual ITlsKeyShare CreateKeyShare(ushort group) => Dtls13Groups.IsSupported(group) ? BcKeyShares.Create(group) : null;

        public virtual byte[] Encapsulate(ushort group, byte[] encapsulationKey, out byte[] sharedSecret)
            => BcKeyShares.Encapsulate(group, encapsulationKey, out sharedSecret);

        public virtual ITlsKeyShare CreateDhKeyShare(byte[] prime, byte[] generator) => BcKeyShares.Dh(prime, generator);

        public virtual ITlsKeyShare CreateKeyShareOnDomainOf(byte[] subjectPublicKeyInfo) => BcKeyShares.OnDomainOf(subjectPublicKeyInfo);

        public virtual bool Verify(ushort scheme, byte[] subjectPublicKeyInfo, byte[] content, byte[] signature)
        {
            return BcSignatures.Verify(scheme, PublicKeyFactory.CreateKey(subjectPublicKeyInfo), content, signature);
        }

        public virtual byte[] EncryptPreMasterSecret(byte[] subjectPublicKeyInfo, byte[] preMasterSecret)
        {
            var rsa = new Pkcs1Encoding(new RsaBlindedEngine());
            rsa.Init(true, new ParametersWithRandom(PublicKeyFactory.CreateKey(subjectPublicKeyInfo), new SecureRandom()));
            return rsa.ProcessBlock(preMasterSecret, 0, preMasterSecret.Length);
        }

        /// <summary>The BouncyCastle private key of <paramref name="credentials"/>: of PKCS#8, or exported of the certificate once.</summary>
        internal static AsymmetricKeyParameter PrivateKey(CertificateCredentials credentials)
            => credentials.BcPrivateKey ??= Export(credentials.Certificate);

        // The certificate's own key, which must be exportable.
        private static AsymmetricKeyParameter Export(X509Certificate2 certificate)
        {
#if NETCOREAPP
            using AsymmetricAlgorithm key = (AsymmetricAlgorithm)certificate.GetRSAPrivateKey() ?? (AsymmetricAlgorithm)certificate.GetECDsaPrivateKey()
                ?? certificate.GetDSAPrivateKey() ?? throw new CryptographicException("The certificate's key is not RSA, ECDSA or DSA.");
            try
            {
                return PrivateKeyFactory.CreateKey(key.ExportPkcs8PrivateKey());
            }
            catch (CryptographicException)
            {
                // exportable, but not as plaintext (a Windows CNG key): encrypted under a password of this call alone
                string password = System.Convert.ToBase64String(Dtls13CryptoUtils.GenerateRandom(16));
                byte[] encrypted = key.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 1));
                return PrivateKeyFactory.DecryptKey(password.ToCharArray(), encrypted);
            }
#else
            using (var rsa = certificate.GetRSAPrivateKey())
            {
                if (rsa != null)
                {
                    var p = rsa.ExportParameters(true);
                    return new RsaPrivateCrtKeyParameters(new BigInteger(1, p.Modulus), new BigInteger(1, p.Exponent), new BigInteger(1, p.D),
                        new BigInteger(1, p.P), new BigInteger(1, p.Q), new BigInteger(1, p.DP), new BigInteger(1, p.DQ), new BigInteger(1, p.InverseQ));
                }
            }
            using (var ecdsa = certificate.GetECDsaPrivateKey())
            {
                if (ecdsa != null)
                {
                    var p = ecdsa.ExportParameters(true);
                    return new ECPrivateKeyParameters("EC", new BigInteger(1, p.D), Certificates.CurveOid(p.Curve));
                }
            }
            if (certificate.PrivateKey is DSA dsa)
            {
                var p = dsa.ExportParameters(true);
                return new DsaPrivateKeyParameters(new BigInteger(1, p.X),
                    new DsaParameters(new BigInteger(1, p.P), new BigInteger(1, p.Q), new BigInteger(1, p.G)));
            }
            throw new CryptographicException("The certificate's key is not RSA, ECDSA or DSA.");
#endif
        }
    }
}
