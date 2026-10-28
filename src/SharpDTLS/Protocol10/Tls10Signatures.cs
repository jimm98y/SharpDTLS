using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace SharpDTLS.Protocol10
{
    /// <summary>
    /// TLS 1.0/1.1 digital signatures, as used by DTLS 1.0 (RFC 4346 §4.7, RFC 4492 §5.4):
    /// RSA signs MD5(data) || SHA1(data) with PKCS#1 v1.5 padding and no DigestInfo; DSA and ECDSA use SHA-1.
    /// There is no SignatureAndHashAlgorithm field on the wire.
    /// </summary>
    internal static class Tls10Signatures
    {
        public static byte[] Sign(AsymmetricKeyParameter privateKey, byte[] content)
        {
            ISigner signer = CreateSigner(privateKey);
            signer.Init(true, privateKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(AsymmetricKeyParameter publicKey, byte[] content, byte[] signature)
        {
            ISigner signer = CreateSigner(publicKey);
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            return signer.VerifySignature(signature);
        }

        private static ISigner CreateSigner(AsymmetricKeyParameter key) => key switch
        {
            RsaKeyParameters => new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), new CombinedHash()),
            ECKeyParameters => SignerUtilities.GetSigner("SHA1WITHECDSA"),
            DsaKeyParameters => SignerUtilities.GetSigner("SHA1WITHDSA"),
            _ => throw new DtlsException(AlertDescription.UnsupportedCertificate, "Unsupported key type for DTLS 1.0 signatures."),
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
#if !NETSTANDARD2_0
            public void BlockUpdate(System.ReadOnlySpan<byte> input) { _md5.BlockUpdate(input); _sha1.BlockUpdate(input); }
#endif

            public int DoFinal(byte[] output, int outOff)
            {
                _md5.DoFinal(output, outOff);
                _sha1.DoFinal(output, outOff + 16);
                return 36;
            }

#if !NETSTANDARD2_0
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
