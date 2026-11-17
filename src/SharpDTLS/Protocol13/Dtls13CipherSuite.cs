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
            new Dtls13CipherSuite(TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new AeadRecordCipher(TlsAeadAlgorithm.AesGcm, 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_AES_256_GCM_SHA384, CryptoHashAlgorithm.sha384, 48, 32, 12, new AeadRecordCipher(TlsAeadAlgorithm.AesGcm, 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_CHACHA20_POLY1305_SHA256, CryptoHashAlgorithm.sha256, 32, 32, 12, new AeadRecordCipher(TlsAeadAlgorithm.ChaCha20Poly1305, 16, aesMask: false)),
            new Dtls13CipherSuite(TLS_AES_128_CCM_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new AeadRecordCipher(TlsAeadAlgorithm.AesCcm, 16, aesMask: true)),
            new Dtls13CipherSuite(TLS_AES_128_CCM_8_SHA256, CryptoHashAlgorithm.sha256, 32, 16, 12, new AeadRecordCipher(TlsAeadAlgorithm.AesCcm8, 8, aesMask: true)),
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

    /// <summary>Record protection of a DTLS 1.3 cipher suite: of each traffic key, an <see cref="IDtls13Protection"/>.</summary>
    internal interface IDtls13RecordCipher
    {
        int TagLength { get; }

        /// <summary>The protection of one traffic key and its record number key (sn_key).</summary>
        IDtls13Protection Create(ITlsCrypto crypto, byte[] key, byte[] snKey);
    }

    /// <summary>The records of one traffic key, in one direction. Not thread-safe.</summary>
    internal interface IDtls13Protection : IDisposable
    {
        /// <summary>Writes ciphertext || tag; the output may be the plaintext itself.</summary>
        void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag);

        /// <summary>Writes the plaintext, false when authentication fails; the output may be the ciphertext itself.</summary>
        bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext);

        /// <summary>
        /// The first bytes of the record number mask (RFC 9147 §4.2.3) of the start of the ciphertext; false when record
        /// numbers are sent in the clear (RFC 9150 §9).
        /// </summary>
        bool Mask(ReadOnlySpan<byte> ciphertext, Span<byte> mask);
    }

    /// <summary>GCM, CCM, CCM_8 and ChaCha20-Poly1305, of the connection's <see cref="ITlsCrypto"/>.</summary>
    internal sealed class AeadRecordCipher : IDtls13RecordCipher
    {
        private readonly TlsAeadAlgorithm _algorithm;
        private readonly bool _aesMask;

        public AeadRecordCipher(TlsAeadAlgorithm algorithm, int tagLength, bool aesMask)
        {
            _algorithm = algorithm;
            TagLength = tagLength;
            _aesMask = aesMask;
        }

        public int TagLength { get; }

        public IDtls13Protection Create(ITlsCrypto crypto, byte[] key, byte[] snKey)
            => new Protection(crypto.CreateAead(_algorithm, key), _aesMask ? crypto.CreateBlockCipher(TlsBlockCipherAlgorithm.Aes, snKey) : null, snKey);

        private sealed class Protection : IDtls13Protection
        {
            private readonly ITlsAead _aead;
            private readonly ITlsBlockCipher _mask;
            private readonly byte[] _snKey;

            public Protection(ITlsAead aead, ITlsBlockCipher mask, byte[] snKey)
            {
                _aead = aead;
                _mask = mask;
                _snKey = snKey;
            }

            public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
                => _aead.Seal(nonce, aad, plaintext, ciphertextAndTag);

            public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
                => _aead.Open(nonce, aad, ciphertextAndTag, plaintext);

            // AES-based AEADs: AES-ECB(sn_key, sample); ChaCha20: the block keyed by sn_key, with the sample
            // as counter (first 4 bytes, little-endian) and nonce (next 12).
            public bool Mask(ReadOnlySpan<byte> ciphertext, Span<byte> mask)
            {
                if (_mask == null)
                {
                    Span<byte> block = stackalloc byte[64];
                    ChaCha20Block.Compute(_snKey, BinaryPrimitives.ReadUInt32LittleEndian(ciphertext), ciphertext.Slice(4, 12), block);
                    block.Slice(0, mask.Length).CopyTo(mask);
                    return true;
                }
                Span<byte> zeroIv = stackalloc byte[16];
                zeroIv.Clear();
                Span<byte> sample = stackalloc byte[16];
                _mask.EncryptCbc(zeroIv, ciphertext.Slice(0, 16), sample);
                sample.Slice(0, mask.Length).CopyTo(mask);
                return true;
            }

            public void Dispose()
            {
                (_aead as IDisposable)?.Dispose();
                (_mask as IDisposable)?.Dispose();
            }
        }
    }

    /// <summary>AEGIS-128L / AEGIS-256 with a 128-bit tag (draft-irtf-cfrg-aegis-aead-08 §10, §11.1).</summary>
    internal sealed class AegisCipher : IDtls13RecordCipher
    {
        private readonly bool _aegis256;

        public AegisCipher(bool aegis256) => _aegis256 = aegis256;

        public int TagLength => 16;

        public IDtls13Protection Create(ITlsCrypto crypto, byte[] key, byte[] snKey) => new Protection(_aegis256, key, snKey);

        // AEGIS is our own code, of arrays.
        private sealed class Protection : IDtls13Protection
        {
            private readonly bool _aegis256;
            private readonly byte[] _key, _snKey;

            public Protection(bool aegis256, byte[] key, byte[] snKey)
            {
                _aegis256 = aegis256;
                _key = key;
                _snKey = snKey;
            }

            public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
            {
                byte[] sealedData = _aegis256
                    ? Aegis.Encrypt256(_key, nonce.ToArray(), aad.ToArray(), plaintext.ToArray())
                    : Aegis.Encrypt128L(_key, nonce.ToArray(), aad.ToArray(), plaintext.ToArray());
                sealedData.CopyTo(ciphertextAndTag);
            }

            public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
            {
                byte[] result = _aegis256
                    ? Aegis.Decrypt256(_key, nonce.ToArray(), aad.ToArray(), ciphertextAndTag.ToArray())
                    : Aegis.Decrypt128L(_key, nonce.ToArray(), aad.ToArray(), ciphertextAndTag.ToArray());
                result?.CopyTo(plaintext);
                return result != null;
            }

            // mask = Stream(5, sn_key, ZeroPad(ciphertext[0..16], nonce_len))
            public bool Mask(ReadOnlySpan<byte> ciphertext, Span<byte> mask)
            {
                byte[] nonce = new byte[_aegis256 ? 32 : 16];
                ciphertext.Slice(0, 16).CopyTo(nonce);
                (_aegis256 ? Aegis.Stream256(5, _snKey, nonce) : Aegis.Stream128L(5, _snKey, nonce)).AsSpan(0, mask.Length).CopyTo(mask);
                return true;
            }

            public void Dispose()
            {
            }
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

        public IDtls13Protection Create(ITlsCrypto crypto, byte[] key, byte[] snKey)
            => new Protection(crypto.CreateHmac(_sha384 ? TlsHashAlgorithm.Sha384 : TlsHashAlgorithm.Sha256, key));

        private sealed class Protection : IDtls13Protection
        {
            private readonly ITlsHash _hmac;

            public Protection(ITlsHash hmac) => _hmac = hmac;

            public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
            {
                plaintext.CopyTo(ciphertextAndTag);
                Mac(nonce, aad, plaintext, ciphertextAndTag.Slice(plaintext.Length, _hmac.HashLength));
            }

            public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
            {
                int length = ciphertextAndTag.Length - _hmac.HashLength;
                if (length < 0)
                    return false;
                Span<byte> tag = stackalloc byte[_hmac.HashLength];
                Mac(nonce, aad, ciphertextAndTag.Slice(0, length), tag);
                if (!CryptographicOperations.FixedTimeEquals(tag, ciphertextAndTag.Slice(length)))
                    return false;
                ciphertextAndTag.Slice(0, length).CopyTo(plaintext);
                return true;
            }

            // RFC 9150 §9: record sequence numbers are sent unencrypted.
            public bool Mask(ReadOnlySpan<byte> ciphertext, Span<byte> mask) => false;

            private void Mac(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> tag)
            {
                _hmac.Append(nonce);
                _hmac.Append(aad);
                _hmac.Append(plaintext);
                _hmac.Finish(tag);
            }

            public void Dispose() => (_hmac as IDisposable)?.Dispose();
        }
    }
}
