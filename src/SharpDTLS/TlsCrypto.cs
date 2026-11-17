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

        /// <summary>
        /// An ephemeral key of the named group <paramref name="group"/> (RFC 8446 §4.2.7: an elliptic curve, x25519, x448,
        /// ffdhe or ML-KEM); null when this provider has none for it.
        /// </summary>
        ITlsKeyShare CreateKeyShare(ushort group);

        /// <summary>
        /// ML-KEM encapsulation to the peer's <paramref name="encapsulationKey"/>: returns the ciphertext. Throws a
        /// <see cref="CryptographicException"/> for an invalid key.
        /// </summary>
        byte[] Encapsulate(ushort group, byte[] encapsulationKey, out byte[] sharedSecret);

        /// <summary>
        /// TLS 1.2's DHE on the server's explicit parameters (big-endian unsigned): the key share's public value and its
        /// secret are without leading zeros (RFC 5246 §8.1.2); it refuses a peer value outside 1 &lt; Y &lt; p - 1.
        /// </summary>
        ITlsKeyShare CreateDhKeyShare(byte[] prime, byte[] generator);

        /// <summary>
        /// An ephemeral key on the curve or DH group of the peer's static key (DER SubjectPublicKeyInfo): the client side of
        /// static ECDH and DH (RFC 8422 §2.1, RFC 5246 §7.4.7.2).
        /// </summary>
        ITlsKeyShare CreateKeyShareOnDomainOf(byte[] subjectPublicKeyInfo);

        /// <summary>
        /// Verifies the peer's <paramref name="signature"/> of <paramref name="content"/> with its public key, a DER
        /// SubjectPublicKeyInfo. <paramref name="scheme"/> fits the key (the protocol checks that first); ECDSA signatures
        /// are DER encoded.
        /// </summary>
        bool Verify(ushort scheme, byte[] subjectPublicKeyInfo, byte[] content, byte[] signature);

        /// <summary>RSA key transport (RFC 5246 §7.4.7.1): the premaster secret encrypted to the server's RSA key, PKCS#1 v1.5.</summary>
        byte[] EncryptPreMasterSecret(byte[] subjectPublicKeyInfo, byte[] preMasterSecret);
    }
}
