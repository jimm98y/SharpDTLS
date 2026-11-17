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
using SharpDTLS.Protocol10;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System.Security.Cryptography;

namespace SharpDTLS
{
    /// <summary>
    /// The operations of a local private key: whatever holds the key (BouncyCastle, .NET, an HSM) implements them.
    /// Set it as <see cref="TlsClientBase.Crypto"/> or <see cref="TlsServerBase.Crypto"/>.
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
            DHPrivateKeyParameters dh => DhUtilities.Agree(dh.Parameters, dh.X, new Org.BouncyCastle.Math.BigInteger(1, peerPublicKey)),
            ECPrivateKeyParameters ec => StaticEcdh.Agree(ec, peerPublicKey),
            _ => throw new CryptographicException("The key is not a key agreement key."),
        };

        /// <summary>The BouncyCastle private key of <paramref name="credentials"/>.</summary>
        private static AsymmetricKeyParameter PrivateKey(CertificateCredentials credentials) => credentials.KeyPair.Private;
    }
}
