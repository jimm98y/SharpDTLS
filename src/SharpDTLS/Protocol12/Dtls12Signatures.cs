using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// TLS 1.2 SignatureAndHashAlgorithm handling (RFC 5246 §7.4.1.4.1, RFC 8446 §4.2.3 code points).
    /// The scheme is written as (hash &lt;&lt; 8) | signature.
    /// </summary>
    internal static class Dtls12Signatures
    {
        public const ushort RsaPkcs1Sha256 = 0x0401;
        public const ushort RsaPkcs1Sha384 = 0x0501;
        public const ushort RsaPkcs1Sha512 = 0x0601;
        public const ushort EcdsaSha256    = 0x0403;
        public const ushort EcdsaSha384    = 0x0503;
        public const ushort EcdsaSha512    = 0x0603;
        public const ushort RsaPssRsaeSha256 = 0x0804;
        public const ushort RsaPssRsaeSha384 = 0x0805;
        public const ushort RsaPssRsaeSha512 = 0x0806;
        public const ushort RsaPkcs1Sha1   = 0x0201;
        public const ushort EcdsaSha1      = 0x0203;
        public const ushort DsaSha1        = 0x0202;
        public const ushort DsaSha256      = 0x0402;
        public const ushort DsaSha384      = 0x0502;
        public const ushort DsaSha512      = 0x0602;

        /// <summary>Schemes this implementation can produce and verify, in preference order.</summary>
        public static readonly ushort[] Supported =
        {
            EcdsaSha256, EcdsaSha384, EcdsaSha512,
            RsaPssRsaeSha256, RsaPssRsaeSha384, RsaPssRsaeSha512,
            RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512,
            DsaSha256, DsaSha384, DsaSha512,
            // SHA-1 based schemes, for older peers only
            EcdsaSha1, RsaPkcs1Sha1, DsaSha1,
        };

        private static readonly ushort[] WithoutDsa = Supported.Where(s => (s & 0xFF) != 0x02).ToArray();

        /// <summary>
        /// The schemes to offer in signature_algorithms: <see cref="Supported"/> without DSA, which RFC 9846 §4.3.3
        /// forbids offering, unless <paramref name="dsa"/> because DSA cipher suites were enabled explicitly.
        /// </summary>
        public static ushort[] Offered(bool dsa) => dsa ? Supported : WithoutDsa;

        public static ushort Scheme(byte hashAlgorithm, byte signatureAlgorithm) => (ushort)((hashAlgorithm << 8) | signatureAlgorithm);

        /// <summary>
        /// Picks the first supported scheme that fits the key and that the peer offered. When the peer sent no
        /// signature_algorithms extension, RFC 5246 §7.4.1.4.1 defaults apply (SHA-1); SHA-256 is used instead
        /// since all DTLS 1.2 peers in practice accept it.
        /// </summary>
        public static ushort? SelectScheme(AsymmetricKeyParameter privateKey, IEnumerable<ushort> peerSchemes)
        {
            var offered = peerSchemes?.ToHashSet();
            foreach (ushort scheme in Supported)
            {
                if ((offered == null || offered.Contains(scheme)) && IsCompatible(scheme, privateKey))
                    return scheme;
            }
            return null;
        }

        public static bool IsCompatible(ushort scheme, AsymmetricKeyParameter key)
        {
            byte signature = (byte)scheme;
            if (scheme >= 0x0804 && scheme <= 0x0806)
                return key is RsaKeyParameters;
            return signature switch
            {
                0x01 => key is RsaKeyParameters,
                0x02 => key is DsaKeyParameters,
                0x03 => key is ECKeyParameters,
                _ => false,
            };
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
            if (!Supported.Contains(scheme) || !IsCompatible(scheme, publicKey))
                return false;

            ISigner signer = CreateSigner(scheme);
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.VerifySignature(signature);
        }

        private static ISigner CreateSigner(ushort scheme) => scheme switch
        {
            RsaPkcs1Sha1     => SignerUtilities.GetSigner("SHA1WITHRSA"),
            EcdsaSha1        => SignerUtilities.GetSigner("SHA1WITHECDSA"),
            DsaSha1          => SignerUtilities.GetSigner("SHA1WITHDSA"),
            DsaSha256        => SignerUtilities.GetSigner("SHA256WITHDSA"),
            DsaSha384        => SignerUtilities.GetSigner("SHA384WITHDSA"),
            DsaSha512        => SignerUtilities.GetSigner("SHA512WITHDSA"),
            RsaPkcs1Sha256   => SignerUtilities.GetSigner("SHA256WITHRSA"),
            RsaPkcs1Sha384   => SignerUtilities.GetSigner("SHA384WITHRSA"),
            RsaPkcs1Sha512   => SignerUtilities.GetSigner("SHA512WITHRSA"),
            EcdsaSha256      => SignerUtilities.GetSigner("SHA256WITHECDSA"),
            EcdsaSha384      => SignerUtilities.GetSigner("SHA384WITHECDSA"),
            EcdsaSha512      => SignerUtilities.GetSigner("SHA512WITHECDSA"),
            RsaPssRsaeSha256 => SignerUtilities.GetSigner("SHA256WITHRSAANDMGF1"),
            RsaPssRsaeSha384 => SignerUtilities.GetSigner("SHA384WITHRSAANDMGF1"),
            RsaPssRsaeSha512 => SignerUtilities.GetSigner("SHA512WITHRSAANDMGF1"),
            _ => throw new DtlsException(AlertDescription.IllegalParameter, $"Unsupported signature scheme 0x{scheme:X4}"),
        };
    }
}
