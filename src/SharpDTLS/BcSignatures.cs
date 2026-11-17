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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace SharpDTLS
{
    /// <summary>
    /// BouncyCastle's signatures of every <see cref="SignatureSchemes"/> value, for <see cref="BouncyCastleTlsCrypto"/>: the
    /// protocols choose the scheme, this signs and verifies with it.
    /// </summary>
    internal static class BcSignatures
    {
        public static byte[] Sign(ushort scheme, AsymmetricKeyParameter privateKey, byte[] content)
        {
            ISigner signer = CreateSigner(scheme);
            signer.Init(true, privateKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(ushort scheme, AsymmetricKeyParameter publicKey, byte[] content, byte[] signature)
        {
            ISigner signer = CreateSigner(scheme);
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.VerifySignature(signature);
        }

        private static ISigner CreateSigner(ushort scheme) => scheme switch
        {
            // TLS 1.0/1.1 (RFC 4346 §4.7): MD5 || SHA-1 with PKCS#1 v1.5 padding and no DigestInfo
            SignatureSchemes.RsaPkcs1Md5Sha1 => new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), new CombinedHash()),
            SignatureSchemes.RsaPkcs1Sha1 => SignerUtilities.GetSigner("SHA1WITHRSA"),
            SignatureSchemes.EcdsaSha1 => SignerUtilities.GetSigner("SHA1WITHECDSA"),
            SignatureSchemes.DsaSha1 => SignerUtilities.GetSigner("SHA1WITHDSA"),
            SignatureSchemes.DsaSha256 => SignerUtilities.GetSigner("SHA256WITHDSA"),
            SignatureSchemes.DsaSha384 => SignerUtilities.GetSigner("SHA384WITHDSA"),
            SignatureSchemes.DsaSha512 => SignerUtilities.GetSigner("SHA512WITHDSA"),
            SignatureSchemes.RsaPkcs1Sha256 => SignerUtilities.GetSigner("SHA256WITHRSA"),
            SignatureSchemes.RsaPkcs1Sha384 => SignerUtilities.GetSigner("SHA384WITHRSA"),
            SignatureSchemes.RsaPkcs1Sha512 => SignerUtilities.GetSigner("SHA512WITHRSA"),
            SignatureSchemes.EcdsaSecp256r1Sha256 => SignerUtilities.GetSigner("SHA256WITHECDSA"),
            SignatureSchemes.EcdsaSecp384r1Sha384 => SignerUtilities.GetSigner("SHA384WITHECDSA"),
            SignatureSchemes.EcdsaSecp521r1Sha512 => SignerUtilities.GetSigner("SHA512WITHECDSA"),
            SignatureSchemes.RsaPssRsaeSha256 => SignerUtilities.GetSigner("SHA256WITHRSAANDMGF1"),
            SignatureSchemes.RsaPssRsaeSha384 => SignerUtilities.GetSigner("SHA384WITHRSAANDMGF1"),
            SignatureSchemes.RsaPssRsaeSha512 => SignerUtilities.GetSigner("SHA512WITHRSAANDMGF1"),
            SignatureSchemes.Ed25519 => SignerUtilities.GetSigner("Ed25519"),
            SignatureSchemes.Ed448 => SignerUtilities.GetSigner("Ed448"),
            _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unsupported signature scheme 0x{scheme:X4}"),
        };

        /// <summary>MD5 || SHA1 as a single 36-byte digest.</summary>
        private sealed class CombinedHash : IDigest
        {
            private readonly MD5Digest _md5 = new();
            private readonly Sha1Digest _sha1 = new();

            public string AlgorithmName => "MD5andSHA1";
            public int GetDigestSize() => 36;
            public int GetByteLength() => 64;

            public void Update(byte input) { _md5.Update(input); _sha1.Update(input); }
            public void BlockUpdate(byte[] input, int inOff, int inLen) { _md5.BlockUpdate(input, inOff, inLen); _sha1.BlockUpdate(input, inOff, inLen); }
#if NETCOREAPP
            public void BlockUpdate(System.ReadOnlySpan<byte> input) { _md5.BlockUpdate(input); _sha1.BlockUpdate(input); }
#endif

            public int DoFinal(byte[] output, int outOff)
            {
                _md5.DoFinal(output, outOff);
                _sha1.DoFinal(output, outOff + 16);
                return 36;
            }

#if NETCOREAPP
            public int DoFinal(System.Span<byte> output)
            {
                _md5.DoFinal(output);
                _sha1.DoFinal(output.Slice(16));
                return 36;
            }
#endif

            public void Reset() { _md5.Reset(); _sha1.Reset(); }
        }
    }
}
