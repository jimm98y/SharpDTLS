using SharpDTLS.Protocol13;
using System;

namespace SharpDTLS
{
    /// <summary>
    /// An external (out-of-band provisioned) pre-shared key for TLS/DTLS 1.3 (RFC 8446 §2.2, §4.2.11). TLS 1.3 binds
    /// every PSK to one hash; it is the hash of <see cref="CipherSuite"/>, and the handshake must negotiate a suite
    /// with that hash.
    /// </summary>
    public sealed class TlsExternalPsk
    {
        public TlsExternalPsk(byte[] identity, byte[] key, ushort cipherSuite = Dtls13CipherSuite.TLS_AES_128_GCM_SHA256)
        {
            if (identity == null || identity.Length == 0)
                throw new ArgumentException("The PSK identity must not be empty.", nameof(identity));
            if (key == null || key.Length == 0)
                throw new ArgumentException("The PSK must not be empty.", nameof(key));
            if (!Dtls13CipherSuite.IsSupported(cipherSuite))
                throw new ArgumentException($"Cipher suite 0x{cipherSuite:X4} is not supported.", nameof(cipherSuite));
            Identity = identity;
            Key = key;
            CipherSuite = cipherSuite;
        }

        public byte[] Identity { get; }
        public byte[] Key { get; }

        /// <summary>A suite whose hash is the PSK's hash.</summary>
        public ushort CipherSuite { get; }
    }
}
