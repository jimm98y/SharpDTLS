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
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls.Crypto;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// Parameters of a DTLS 1.3 cipher suite (RFC 8446 Appendix B.4, RFC 9150, draft-irtf-cfrg-aegis-aead-08).
    /// </summary>
    internal sealed class Dtls13CipherSuite
    {
        public const ushort TLS_AES_128_GCM_SHA256       = 0x1301;
        public const ushort TLS_AES_256_GCM_SHA384       = 0x1302;
        public const ushort TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
        public const ushort TLS_AES_128_CCM_SHA256       = 0x1304;
        public const ushort TLS_AES_128_CCM_8_SHA256     = 0x1305;
        public const ushort TLS_AEGIS_256_SHA512         = 0x1306;
        public const ushort TLS_AEGIS_128L_SHA256        = 0x1307;
        public const ushort TLS_SHA256_SHA256            = 0xC0B4;
        public const ushort TLS_SHA384_SHA384            = 0xC0B5;

        /// <summary>
        /// Default preference order for both the client (offer) and the server (selection), as in common
        /// TLS 1.3 stacks. CCM, CCM_8 (short tag), AEGIS (draft) and the integrity-only suites (RFC 9150 §9:
        /// never by default) are enabled by listing them in CipherSuites.
        /// </summary>
        public static readonly ushort[] Supported =
        {
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        };

        private static readonly Dictionary<ushort, Dtls13CipherSuite> _suites = new[]
        {
            new Dtls13CipherSuite(TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new BcAeadCipher(() => new GcmBlockCipher(new AesEngine()), 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_AES_256_GCM_SHA384, CryptoHashAlgorithm.sha384, 48, 32, 12, new BcAeadCipher(() => new GcmBlockCipher(new AesEngine()), 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_CHACHA20_POLY1305_SHA256, CryptoHashAlgorithm.sha256, 32, 32, 12, new BcAeadCipher(() => new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(), 16, aesMask: false)),
            new Dtls13CipherSuite(TLS_AES_128_CCM_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new BcAeadCipher(() => new CcmBlockCipher(new AesEngine()), 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_AES_128_CCM_8_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new BcAeadCipher(() => new CcmBlockCipher(new AesEngine()), 8, aesMask: true)),
            new Dtls13CipherSuite(TLS_AEGIS_256_SHA512, CryptoHashAlgorithm.sha512, 64, 32, 32, new AegisCipher(aegis256: true)),
            new Dtls13CipherSuite(TLS_AEGIS_128L_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 16, new AegisCipher(aegis256: false)),
            new Dtls13CipherSuite(TLS_SHA256_SHA256, CryptoHashAlgorithm.sha256, 32, 32, 32, new IntegrityOnlyCipher(sha384: false)),
            new Dtls13CipherSuite(TLS_SHA384_SHA384, CryptoHashAlgorithm.sha384, 48, 48, 48, new IntegrityOnlyCipher(sha384: true)),
        }.ToDictionary(s => s.Id);

        /// <summary>Every implemented DTLS 1.3 suite.</summary>
        public static IReadOnlyCollection<ushort> All => _suites.Keys;

        public ushort Id { get; }
        public int HashAlgorithm { get; }   // CryptoHashAlgorithm value
        public int HashLength { get; }
        public int KeyLength { get; }
        public int IvLength { get; }
        public int TagLength => Cipher.TagLength;

        /// <summary>RFC 9150 suites authenticate records but do not encrypt them.</summary>
        public bool IsIntegrityOnly => Cipher is IntegrityOnlyCipher;

        internal IDtls13RecordCipher Cipher { get; }

        private Dtls13CipherSuite(ushort id, int hashAlgorithm, int hashLength, int keyLength, int ivLength, IDtls13RecordCipher cipher,
            string labelPrefix = "dtls13")
        {
            Id = id;
            HashAlgorithm = hashAlgorithm;
            HashLength = hashLength;
            KeyLength = keyLength;
            IvLength = ivLength;
            Cipher = cipher;
            LabelPrefix = labelPrefix;
            LabelPrefixBytes = System.Text.Encoding.ASCII.GetBytes(labelPrefix);
        }

        /// <summary>The HKDF-Expand-Label prefix: "dtls13" (RFC 9147 §5.9), or "tls13 " for TLS 1.3 (RFC 8446 §7.1).</summary>
        public string LabelPrefix { get; }
        internal byte[] LabelPrefixBytes { get; }

        /// <summary>Whether this is the TLS 1.3 variant of the suite.</summary>
        public bool IsTls => LabelPrefix == "tls13 ";

        /// <summary>
        /// How many records one key may protect (RFC 9846 §5.5, RFC 9147 §4.5.3): 2^24.5 full-size records for the AES
        /// suites (GCM and CCM). For ChaCha20-Poly1305, AEGIS and the integrity-only suites only the 48-bit record
        /// sequence number bounds it.
        /// </summary>
        public ulong RecordLimit => Id is TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384 or TLS_AES_128_CCM_SHA256 or TLS_AES_128_CCM_8_SHA256
            ? 23_726_566UL
            : (1UL << 48) - 1;

        /// <summary>
        /// How many records that fail authentication one key may receive over DTLS (RFC 9147 §4.5.3): 2^36 for AES-GCM
        /// and ChaCha20-Poly1305, 2^23.5 for AES-CCM, 2^7 for AES-CCM_8. AEGIS and the integrity-only suites have no
        /// limit given, so only the 48-bit record sequence number bounds it.
        /// </summary>
        public ulong IntegrityLimit => Id switch
        {
            TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 => 1UL << 36,
            TLS_AES_128_CCM_SHA256 => 11_863_283UL,
            TLS_AES_128_CCM_8_SHA256 => 1UL << 7,
            _ => (1UL << 48) - 1,
        };

        /// <summary>After this many records under one key a KeyUpdate starts, leaving time for its ACK (DTLS) before <see cref="RecordLimit"/>.</summary>
        public ulong RekeyThreshold => RecordLimit / 4 * 3;

        private Dtls13CipherSuite _tls;

        /// <summary>The same suite for TLS 1.3, whose key schedule labels start with "tls13 ".</summary>
        public Dtls13CipherSuite ForTls()
            => IsTls ? this : _tls ??= new Dtls13CipherSuite(Id, HashAlgorithm, HashLength, KeyLength, IvLength, Cipher, "tls13 ");

        public static bool IsSupported(ushort id) => _suites.ContainsKey(id);

        public static Dtls13CipherSuite Get(ushort id)
        {
            if (!_suites.TryGetValue(id, out var suite))
                throw new DtlsException(AlertDescription.HandshakeFailure, $"Unsupported DTLS 1.3 cipher suite 0x{id:X4}");
            return suite;
        }

        public IDigest CreateDigest() => HashAlgorithm switch
        {
            CryptoHashAlgorithm.sha512 => new Sha512Digest(),
            CryptoHashAlgorithm.sha384 => new Sha384Digest(),
            _ => new Sha256Digest(),
        };
    }

    /// <summary>Record protection of a DTLS 1.3 cipher suite.</summary>
    internal interface IDtls13RecordCipher
    {
        int TagLength { get; }

        /// <summary>Returns ciphertext || tag.</summary>
        byte[] Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext);

        /// <summary>Returns the plaintext, or null when authentication fails.</summary>
        byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext);

        /// <summary>
        /// The record number mask (RFC 9147 §4.2.3) from the start of the ciphertext, or null when record
        /// numbers are sent in the clear (RFC 9150 §9).
        /// </summary>
        byte[] Mask(byte[] snKey, ReadOnlySpan<byte> ciphertext);
    }

    /// <summary>GCM, CCM, CCM_8 and ChaCha20-Poly1305 through BouncyCastle.</summary>
    internal sealed class BcAeadCipher : IDtls13RecordCipher
    {
        private readonly Func<IAeadCipher> _factory;
        private readonly bool _aesMask;

        public BcAeadCipher(Func<IAeadCipher> factory, int tagLength, bool aesMask)
        {
            _factory = factory;
            TagLength = tagLength;
            _aesMask = aesMask;
        }

        public int TagLength { get; }

        public byte[] Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
        {
            var aead = _factory();
            aead.Init(true, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, aad));
            byte[] output = new byte[aead.GetOutputSize(plaintext.Length)];
            int written = aead.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            aead.DoFinal(output, written);
            return output;
        }

        public byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext)
        {
            if (ciphertext.Length < TagLength)
                return null;
            try
            {
                var aead = _factory();
                aead.Init(false, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, aad));
                byte[] output = new byte[aead.GetOutputSize(ciphertext.Length)];
                int written = aead.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
                aead.DoFinal(output, written);
                return output;
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }
        }

        // AES-based AEADs: AES-ECB(sn_key, sample); ChaCha20: the block keyed by sn_key, with the sample
        // as counter (first 4 bytes, little-endian) and nonce (next 12).
        public byte[] Mask(byte[] snKey, ReadOnlySpan<byte> ciphertext)
        {
            if (!_aesMask)
                return ChaCha20Block.Compute(snKey, BinaryPrimitives.ReadUInt32LittleEndian(ciphertext), ciphertext.Slice(4, 12).ToArray());

            byte[] sample = ciphertext.Slice(0, 16).ToArray();
            var aes = new AesEngine();
            aes.Init(true, new KeyParameter(snKey));
            aes.ProcessBlock(sample, 0, sample, 0);
            return sample;
        }
    }

    /// <summary>AEGIS-128L / AEGIS-256 with a 128-bit tag (draft-irtf-cfrg-aegis-aead-08 §10, §11.1).</summary>
    internal sealed class AegisCipher : IDtls13RecordCipher
    {
        private readonly bool _aegis256;

        public AegisCipher(bool aegis256) => _aegis256 = aegis256;

        public int TagLength => 16;

        public byte[] Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
            => _aegis256 ? Aegis.Encrypt256(key, nonce, aad, plaintext) : Aegis.Encrypt128L(key, nonce, aad, plaintext);

        public byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext)
            => _aegis256 ? Aegis.Decrypt256(key, nonce, aad, ciphertext) : Aegis.Decrypt128L(key, nonce, aad, ciphertext);

        // mask = Stream(5, sn_key, ZeroPad(ciphertext[0..16], nonce_len))
        public byte[] Mask(byte[] snKey, ReadOnlySpan<byte> ciphertext)
        {
            byte[] nonce = new byte[_aegis256 ? 32 : 16];
            ciphertext.Slice(0, 16).CopyTo(nonce);
            return _aegis256 ? Aegis.Stream256(5, snKey, nonce) : Aegis.Stream128L(5, snKey, nonce);
        }
    }

    /// <summary>
    /// RFC 9150 integrity-only protection: inner || HMAC(write_key, nonce || additional_data || inner).
    /// </summary>
    internal sealed class IntegrityOnlyCipher : IDtls13RecordCipher
    {
        private readonly bool _sha384;

        public IntegrityOnlyCipher(bool sha384) => _sha384 = sha384;

        public int TagLength => _sha384 ? 48 : 32;

        public byte[] Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
        {
            byte[] output = new byte[plaintext.Length + TagLength];
            plaintext.CopyTo(output, 0);
            Mac(key, nonce, aad, plaintext).CopyTo(output, plaintext.Length);
            return output;
        }

        public byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext)
        {
            if (ciphertext.Length < TagLength)
                return null;
            byte[] plaintext = ciphertext.AsSpan(0, ciphertext.Length - TagLength).ToArray();
            return CryptographicOperations.FixedTimeEquals(Mac(key, nonce, aad, plaintext), ciphertext.AsSpan(plaintext.Length)) ? plaintext : null;
        }

        // RFC 9150 §9: record sequence numbers are sent unencrypted.
        public byte[] Mask(byte[] snKey, ReadOnlySpan<byte> ciphertext) => null;

        private byte[] Mac(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
        {
            var hmac = new HMac(_sha384 ? new Sha384Digest() : new Sha256Digest());
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(nonce, 0, nonce.Length);
            hmac.BlockUpdate(aad, 0, aad.Length);
            hmac.BlockUpdate(plaintext, 0, plaintext.Length);
            byte[] tag = new byte[hmac.GetMacSize()];
            hmac.DoFinal(tag, 0);
            return tag;
        }
    }
}
