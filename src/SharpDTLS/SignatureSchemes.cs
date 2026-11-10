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

namespace SharpDTLS
{
    /// <summary>
    /// Signature schemes (RFC 8446 §4.2.3; TLS 1.2 hash/signature pairs, RFC 5246 §7.4.1.4.1, share the code points).
    /// In TLS/DTLS 1.2 the ECDSA schemes are not bound to a curve.
    /// </summary>
    public static class SignatureSchemes
    {
        public const ushort RsaPkcs1Sha1 = 0x0201;
        public const ushort DsaSha1 = 0x0202;
        public const ushort EcdsaSha1 = 0x0203;
        public const ushort RsaPkcs1Sha256 = 0x0401;
        public const ushort DsaSha256 = 0x0402;
        public const ushort EcdsaSecp256r1Sha256 = 0x0403;
        public const ushort RsaPkcs1Sha384 = 0x0501;
        public const ushort DsaSha384 = 0x0502;
        public const ushort EcdsaSecp384r1Sha384 = 0x0503;
        public const ushort RsaPkcs1Sha512 = 0x0601;
        public const ushort DsaSha512 = 0x0602;
        public const ushort EcdsaSecp521r1Sha512 = 0x0603;
        public const ushort RsaPssRsaeSha256 = 0x0804;
        public const ushort RsaPssRsaeSha384 = 0x0805;
        public const ushort RsaPssRsaeSha512 = 0x0806;
        public const ushort Ed25519 = 0x0807;
        public const ushort Ed448 = 0x0808;
    }
}
