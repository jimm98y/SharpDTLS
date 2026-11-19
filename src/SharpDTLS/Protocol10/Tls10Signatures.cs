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

namespace SharpDTLS.Protocol10
{
    /// <summary>
    /// TLS 1.0/1.1 digital signatures, as used by DTLS 1.0 (RFC 4346 §4.7, RFC 4492 §5.4):
    /// RSA signs MD5(data) || SHA1(data) with PKCS#1 v1.5 padding and no DigestInfo; DSA and ECDSA use SHA-1.
    /// There is no SignatureAndHashAlgorithm field on the wire.
    /// </summary>
    internal static class Tls10Signatures
    {

        public static bool Verify(TlsPublicKey publicKey, byte[] content, byte[] signature, ITlsCrypto crypto = null)
            => (crypto ?? BouncyCastleTlsCrypto.Default).Verify(FixedScheme(publicKey), publicKey.Spki, content, signature);

        /// <summary>The fixed signature of TLS 1.0/1.1 and DTLS 1.0, by the key's type.</summary>
        public static ushort FixedScheme(TlsPublicKey key) => key.Kind switch
        {
            TlsKeyKind.Rsa => SignatureSchemes.RsaPkcs1Md5Sha1,
            TlsKeyKind.Ec => SignatureSchemes.EcdsaSha1,
            TlsKeyKind.Dsa => SignatureSchemes.DsaSha1,
            _ => throw new DtlsException(AlertDescription.UnsupportedCertificate, "Unsupported key type for TLS 1.0 signatures."),
        };



    }
}
