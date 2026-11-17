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
using SharpDTLS.Protocol10;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace SharpDTLS
{
    /// <summary>
    /// The cryptography of a connection: the operations of the local private key, whatever holds it (BouncyCastle, .NET,
    /// an HSM), and the primitives of record protection. Set it as <see cref="TlsClientBase.Crypto"/> or
    /// <see cref="TlsServerBase.Crypto"/>; derive from <see cref="BouncyCastleTlsCrypto"/> to keep what is not overridden.
    /// </summary>
    public interface ITlsCrypto
    {
        /// <summary>
        /// Signs <paramref name="content"/> with the key of <paramref name="credentials"/>. <paramref name="scheme"/> is a
        /// <see cref="SignatureSchemes"/> value the key fits, <see cref="SignatureSchemes.RsaPkcs1Md5Sha1"/> included; ECDSA
        /// signatures are DER encoded.
        /// </summary>
        byte[] Sign(CertificateCredentials credentials, ushort scheme, byte[] content);

        /// <summary>
        /// RSA key transport (RFC 5246 §7.4.7.1): the 48-byte premaster secret in <paramref name="encrypted"/>, PKCS#1 v1.5.
        /// Bad padding should not be told apart from good padding by time: return random bytes, or throw a
        /// <see cref="CryptographicException"/>, which the caller treats the same way.
        /// </summary>
        byte[] DecryptPreMasterSecret(CertificateCredentials credentials, byte[] encrypted);

        /// <summary>
        /// Static (EC)DH of the key of <paramref name="credentials"/> with the peer's public value: an uncompressed EC point,
        /// or a DH public value as unsigned big-endian bytes. Returns the shared secret as TLS uses it (RFC 8422 §5.10, RFC 5246 §8.1.2).
        /// </summary>
        byte[] Agree(CertificateCredentials credentials, byte[] peerPublicKey);

        /// <summary>The AEAD of one record protection key, used for every record of that key.</summary>
        ITlsAead CreateAead(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key);

        /// <summary>The block cipher of one CBC record key, or of the DTLS 1.3 record number key.</summary>
        ITlsBlockCipher CreateBlockCipher(TlsBlockCipherAlgorithm algorithm, ReadOnlySpan<byte> key);

        ITlsHash CreateHash(TlsHashAlgorithm hash);

        ITlsHash CreateHmac(TlsHashAlgorithm hash, ReadOnlySpan<byte> key);
    }

    /// <summary>The default <see cref="ITlsCrypto"/>: the private key is BouncyCastle's.</summary>
    public class BouncyCastleTlsCrypto : ITlsCrypto
    {
        /// <summary>The instance used when none is set.</summary>
        public static BouncyCastleTlsCrypto Default { get; } = new BouncyCastleTlsCrypto();

        public virtual byte[] Sign(CertificateCredentials credentials, ushort scheme, byte[] content)
        {
            var key = PrivateKey(credentials);
            return scheme switch
            {
                SignatureSchemes.RsaPkcs1Md5Sha1 => Tls10Signatures.Sign(key, content),
                SignatureSchemes.Ed25519 or SignatureSchemes.Ed448 => Dtls13Signatures.Sign(scheme, key, content),
                _ => Dtls12Signatures.Sign(scheme, key, content),
            };
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

        /// <summary>The BouncyCastle private key of <paramref name="credentials"/>: of PKCS#8, or exported of the certificate once.</summary>
        private static AsymmetricKeyParameter PrivateKey(CertificateCredentials credentials)
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

    /// <summary>
    /// An <see cref="ITlsCrypto"/> that signs and decrypts with the certificate's own <see cref="RSA"/> or <see cref="ECDsa"/>,
    /// so its key need not be exportable (the Windows certificate store, smart cards, HSMs). What .NET has no key for
    /// (PKCS#8 keys, Ed25519, Ed448, DSA, DH, static ECDH) and the MD5 || SHA-1 RSA signature of TLS 1.0/1.1 are left to
    /// <see cref="BouncyCastleTlsCrypto"/>. RSA key transport is the platform's PKCS#1 v1.5 decryption, whose failures may
    /// take longer than successes; prefer the ECDHE and DHE cipher suites, as the defaults do.
    /// On .NET 8 and later, records are protected by .NET's AES-GCM, AES-CCM and ChaCha20-Poly1305 where the platform has
    /// them, which allocate nothing per record, and hashed by .NET's hashes and HMACs.
    /// </summary>
    public class NetTlsCrypto : BouncyCastleTlsCrypto
    {
        public override byte[] Sign(CertificateCredentials credentials, ushort scheme, byte[] content)
        {
            if (!OwnKey(credentials))
                return base.Sign(credentials, scheme, content);
            HashAlgorithmName hash = (scheme >> 8, scheme & 0xFF) switch
            {
                (2, _) => HashAlgorithmName.SHA1,
                (4, _) or (8, 4) => HashAlgorithmName.SHA256,
                (5, _) or (8, 5) => HashAlgorithmName.SHA384,
                (6, _) or (8, 6) => HashAlgorithmName.SHA512,
                _ => default,
            };
            bool pss = scheme is SignatureSchemes.RsaPssRsaeSha256 or SignatureSchemes.RsaPssRsaeSha384 or SignatureSchemes.RsaPssRsaeSha512;
            if (hash.Name != null && (pss || (scheme & 0xFF) == 1))
            {
                using var rsa = credentials.Certificate.GetRSAPrivateKey();
                if (rsa != null)
                    return rsa.SignData(content, hash, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }
            else if (hash.Name != null && (scheme & 0xFF) == 3)
            {
                using var ecdsa = credentials.Certificate.GetECDsaPrivateKey();
                if (ecdsa != null)
                {
                    // IEEE P1363 r || s, as TLS has it: a DER SEQUENCE of the two INTEGERs
                    byte[] rs = ecdsa.SignData(content, hash);
                    int half = rs.Length / 2;
                    return new Org.BouncyCastle.Asn1.DerSequence(
                        new Org.BouncyCastle.Asn1.DerInteger(new BigInteger(1, rs, 0, half)),
                        new Org.BouncyCastle.Asn1.DerInteger(new BigInteger(1, rs, half, half))).GetEncoded();
                }
            }
            return base.Sign(credentials, scheme, content);
        }

        public override byte[] DecryptPreMasterSecret(CertificateCredentials credentials, byte[] encrypted)
        {
            using var rsa = OwnKey(credentials) ? credentials.Certificate.GetRSAPrivateKey() : null;
            if (rsa == null)
                return base.DecryptPreMasterSecret(credentials, encrypted);
            try
            {
                return rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
            }
            catch (System.Exception ex) when (ex is not CryptographicException)
            {
                throw new CryptographicException("RSA decryption failed.", ex);
            }
        }

        // .NET Framework and .NET Standard have no AEAD and no span hashes: BouncyCastle's there
        public override ITlsAead CreateAead(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
#if NETCOREAPP
            => (ITlsAead)NetAead.Create(algorithm, key) ?? base.CreateAead(algorithm, key);
#else
            => base.CreateAead(algorithm, key);
#endif

        public override ITlsHash CreateHash(TlsHashAlgorithm hash)
#if NETCOREAPP
            => new NetHash(hash, default, hmac: false);
#else
            => base.CreateHash(hash);
#endif

        public override ITlsHash CreateHmac(TlsHashAlgorithm hash, ReadOnlySpan<byte> key)
#if NETCOREAPP
            => new NetHash(hash, key, hmac: true);
#else
            => base.CreateHmac(hash, key);
#endif

        // The certificate holds the key, and BouncyCastle has none of it: of PKCS#8, or of the engines' key pairs.
        private static bool OwnKey(CertificateCredentials credentials)
            => credentials.Certificate != null && credentials.Certificate.HasPrivateKey && !credentials.HasPkcs8PrivateKey && credentials.KeyPair == null;
    }
}
