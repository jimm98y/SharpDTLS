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
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// TLS 1.3 signature schemes usable in CertificateVerify (RFC 8446 §4.2.3, §4.4.3).
    /// </summary>
    internal static class Dtls13Signatures
    {
        public const ushort EcdsaSecp256r1Sha256 = 0x0403;
        public const ushort EcdsaSecp384r1Sha384 = 0x0503;
        public const ushort EcdsaSecp521r1Sha512 = 0x0603;
        public const ushort RsaPssRsaeSha256     = 0x0804;
        public const ushort RsaPssRsaeSha384     = 0x0805;
        public const ushort RsaPssRsaeSha512     = 0x0806;
        public const ushort Ed25519              = 0x0807;
        public const ushort Ed448                = 0x0808;

        /// <summary>Schemes this implementation can produce and verify, in preference order.</summary>
        public static readonly ushort[] Supported =
        {
            EcdsaSecp256r1Sha256, EcdsaSecp384r1Sha384, EcdsaSecp521r1Sha512,
            RsaPssRsaeSha256, RsaPssRsaeSha384, RsaPssRsaeSha512,
            Ed25519, Ed448,
        };

        private static readonly byte[] ServerContext = Encoding.ASCII.GetBytes(new string(' ', 64) + "TLS 1.3, server CertificateVerify\0");
        private static readonly byte[] ClientContext = Encoding.ASCII.GetBytes(new string(' ', 64) + "TLS 1.3, client CertificateVerify\0");

        public static byte[] BuildSignedContent(bool server, byte[] transcriptHash)
        {
            byte[] context = server ? ServerContext : ClientContext;
            byte[] content = new byte[context.Length + transcriptHash.Length];
            Buffer.BlockCopy(context, 0, content, 0, context.Length);
            Buffer.BlockCopy(transcriptHash, 0, content, context.Length, transcriptHash.Length);
            return content;
        }

        /// <summary>Picks the first scheme from <see cref="Supported"/> that fits the key and that the peer offered.</summary>
        public static ushort? SelectScheme(TlsPublicKey privateKey, IEnumerable<ushort> peerSchemes)
        {
            var offered = new HashSet<ushort>(peerSchemes ?? Enumerable.Empty<ushort>());
            foreach (ushort scheme in Supported)
            {
                if (offered.Contains(scheme) && IsCompatible(scheme, privateKey))
                    return scheme;
            }
            return null;
        }

        public static bool IsCompatible(ushort scheme, TlsPublicKey key)
        {
            switch (scheme)
            {
                case EcdsaSecp256r1Sha256: return key.Kind == TlsKeyKind.Ec && key.CurveBits == 256;
                case EcdsaSecp384r1Sha384: return key.Kind == TlsKeyKind.Ec && key.CurveBits == 384;
                case EcdsaSecp521r1Sha512: return key.Kind == TlsKeyKind.Ec && key.CurveBits == 521;
                case RsaPssRsaeSha256:
                case RsaPssRsaeSha384:
                case RsaPssRsaeSha512:     return key.Kind == TlsKeyKind.Rsa;
                case Ed25519:              return key.Kind == TlsKeyKind.Ed25519;
                case Ed448:                return key.Kind == TlsKeyKind.Ed448;
                default:                   return false;
            }
        }


        public static bool Verify(ushort scheme, TlsPublicKey publicKey, byte[] content, byte[] signature, ITlsCrypto crypto = null)
            => IsCompatible(scheme, publicKey) && (crypto ?? BouncyCastleTlsCrypto.Default).Verify(scheme, publicKey.Spki, content, signature);


    }
}
