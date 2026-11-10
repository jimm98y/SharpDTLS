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
using Org.BouncyCastle.Security;
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
        public static ushort? SelectScheme(AsymmetricKeyParameter privateKey, IEnumerable<ushort> peerSchemes)
        {
            var offered = new HashSet<ushort>(peerSchemes ?? Enumerable.Empty<ushort>());
            foreach (ushort scheme in Supported)
            {
                if (offered.Contains(scheme) && IsCompatible(scheme, privateKey))
                    return scheme;
            }
            return null;
        }

        public static bool IsCompatible(ushort scheme, AsymmetricKeyParameter key)
        {
            switch (scheme)
            {
                case EcdsaSecp256r1Sha256: return key is ECKeyParameters ec && ec.Parameters.Curve.FieldSize == 256;
                case EcdsaSecp384r1Sha384: return key is ECKeyParameters ec2 && ec2.Parameters.Curve.FieldSize == 384;
                case EcdsaSecp521r1Sha512: return key is ECKeyParameters ec3 && ec3.Parameters.Curve.FieldSize == 521;
                case RsaPssRsaeSha256:
                case RsaPssRsaeSha384:
                case RsaPssRsaeSha512:     return key is RsaKeyParameters;
                case Ed25519:              return key is Ed25519PrivateKeyParameters || key is Ed25519PublicKeyParameters;
                case Ed448:                return key is Ed448PrivateKeyParameters || key is Ed448PublicKeyParameters;
                default:                   return false;
            }
        }

        public static byte[] Sign(ushort scheme, AsymmetricKeyParameter privateKey, byte[] content)
        {
            ISigner signer = CreateSigner(scheme);
            signer.Init(true, privateKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(ushort scheme, AsymmetricKeyParameter publicKey, byte[] content, byte[] signature)
        {
            if (!IsCompatible(scheme, publicKey))
                return false;

            ISigner signer = CreateSigner(scheme);
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.VerifySignature(signature);
        }

        private static ISigner CreateSigner(ushort scheme) => scheme switch
        {
            EcdsaSecp256r1Sha256 => SignerUtilities.GetSigner("SHA256WITHECDSA"),
            EcdsaSecp384r1Sha384 => SignerUtilities.GetSigner("SHA384WITHECDSA"),
            EcdsaSecp521r1Sha512 => SignerUtilities.GetSigner("SHA512WITHECDSA"),
            RsaPssRsaeSha256     => SignerUtilities.GetSigner("SHA256WITHRSAANDMGF1"),
            RsaPssRsaeSha384     => SignerUtilities.GetSigner("SHA384WITHRSAANDMGF1"),
            RsaPssRsaeSha512     => SignerUtilities.GetSigner("SHA512WITHRSAANDMGF1"),
            Ed25519              => SignerUtilities.GetSigner("Ed25519"),
            Ed448                => SignerUtilities.GetSigner("Ed448"),
            _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unsupported signature scheme 0x{scheme:X4}")
        };
    }
}
