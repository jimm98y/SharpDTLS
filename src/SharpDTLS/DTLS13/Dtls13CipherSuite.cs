using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Tls.Crypto;
using System.Collections.Generic;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// Parameters of a DTLS 1.3 cipher suite (RFC 8446 Appendix B.4).
    /// </summary>
    public sealed class Dtls13CipherSuite
    {
        public const ushort TLS_AES_128_GCM_SHA256       = 0x1301;
        public const ushort TLS_AES_256_GCM_SHA384       = 0x1302;
        public const ushort TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

        // Preference order used by both the client (offer) and the server (selection).
        public static readonly ushort[] Supported =
        {
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        };

        private static readonly Dictionary<ushort, Dtls13CipherSuite> _suites = new()
        {
            [TLS_AES_128_GCM_SHA256]       = new Dtls13CipherSuite(TLS_AES_128_GCM_SHA256,       CryptoHashAlgorithm.sha256, 32, 16, false),
            [TLS_AES_256_GCM_SHA384]       = new Dtls13CipherSuite(TLS_AES_256_GCM_SHA384,       CryptoHashAlgorithm.sha384, 48, 32, false),
            [TLS_CHACHA20_POLY1305_SHA256] = new Dtls13CipherSuite(TLS_CHACHA20_POLY1305_SHA256, CryptoHashAlgorithm.sha256, 32, 32, true),
        };

        public ushort Id { get; }
        public int HashAlgorithm { get; }   // CryptoHashAlgorithm value
        public int HashLength { get; }
        public int KeyLength { get; }
        public int IvLength => 12;
        public int TagLength => 16;
        public bool IsChaCha20 { get; }

        private Dtls13CipherSuite(ushort id, int hashAlgorithm, int hashLength, int keyLength, bool isChaCha20)
        {
            Id = id;
            HashAlgorithm = hashAlgorithm;
            HashLength = hashLength;
            KeyLength = keyLength;
            IsChaCha20 = isChaCha20;
        }

        public static bool IsSupported(ushort id) => _suites.ContainsKey(id);

        public static Dtls13CipherSuite Get(ushort id)
        {
            if (!_suites.TryGetValue(id, out var suite))
                throw new DtlsException(AlertDescription.HandshakeFailure, $"Unsupported DTLS 1.3 cipher suite 0x{id:X4}");
            return suite;
        }

        public IDigest CreateDigest() => HashAlgorithm == CryptoHashAlgorithm.sha384 ? new Sha384Digest() : new Sha256Digest();

        public IAeadCipher CreateAead() => IsChaCha20 ? new ChaCha20Poly1305() : new GcmBlockCipher(new AesEngine());
    }
}
