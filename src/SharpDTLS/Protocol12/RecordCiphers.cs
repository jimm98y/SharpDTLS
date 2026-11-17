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
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// Protection for DTLS 1.0/1.2 records in one direction (RFC 5246 §6.2.3, RFC 6347 §4.1.2.1).
    /// The 64-bit sequence number used in MACs and nonces is epoch (16 bits) || sequence number (48 bits).
    /// </summary>
    internal interface IRecordCipher : IDisposable
    {
        /// <summary>The length of the fragment of <paramref name="plaintextLength"/> bytes.</summary>
        int FragmentLength(int plaintextLength);

        /// <summary>Writes the fragment of <paramref name="plaintext"/>: <see cref="FragmentLength"/> bytes.</summary>
        /// <param name="connectionId">The CID of a tls12_cid record (RFC 9146), which changes the MAC / AEAD input; empty otherwise.</param>
        void Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> plaintext, Span<byte> fragment,
            ReadOnlySpan<byte> connectionId);

        /// <summary>
        /// Writes the plaintext (at most <paramref name="fragment"/>.Length bytes) and returns its length. Throws
        /// <see cref="DtlsRecordDiscardedException"/> when the record does not authenticate.
        /// </summary>
        int Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment, Span<byte> plaintext,
            ReadOnlySpan<byte> connectionId);
    }

    internal static class RecordCiphers
    {
        /// <summary>The longest additional data: the CID form with a 255-byte CID.</summary>
        internal const int MaxAdditionalDataLength = 8 + 3 + 2 + 2 + 6 + 255 + 2;

        /// <summary>
        /// Length of the key block: MAC keys, encryption keys and fixed IVs for both directions. With
        /// <paramref name="implicitIv"/> (TLS 1.0, RFC 2246 §6.3) CBC suites also take their initial IVs from it.
        /// </summary>
        public static int KeyBlockLength(CipherSuiteInfo suite, bool implicitIv = false)
            => 2 * (suite.MacKeyLength + suite.KeyLength + IvLength(suite, implicitIv));

        private static int IvLength(CipherSuiteInfo suite, bool implicitIv)
            => implicitIv && suite.IsCbc ? BlockSize(suite.Cipher) : suite.FixedIvLength;

        private static int BlockSize(BulkCipherAlgorithm cipher)
            => cipher is BulkCipherAlgorithm.DesCbc or BulkCipherAlgorithm.TripleDesEdeCbc or BulkCipherAlgorithm.IdeaCbc ? 8 : 16;

        /// <summary>
        /// Splits the key block (client_write_MAC_key, server_write_MAC_key, client_write_key,
        /// server_write_key, client_write_IV, server_write_IV) into the two directional ciphers.
        /// </summary>
        public static (IRecordCipher ClientWrite, IRecordCipher ServerWrite) Create(CipherSuiteInfo suite, byte[] keyBlock, bool encryptThenMac,
            bool implicitIv = false, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            int mac = suite.MacKeyLength, key = suite.KeyLength, iv = IvLength(suite, implicitIv);
            byte[] Slice(int offset, int length) => keyBlock.AsSpan(offset, length).ToArray();

            byte[] clientMac = Slice(0, mac);
            byte[] serverMac = Slice(mac, mac);
            byte[] clientKey = Slice(2 * mac, key);
            byte[] serverKey = Slice(2 * mac + key, key);
            byte[] clientIv  = Slice(2 * mac + 2 * key, iv);
            byte[] serverIv  = Slice(2 * mac + 2 * key + iv, iv);

            return (CreateOne(crypto, suite, clientKey, clientIv, clientMac, encryptThenMac, implicitIv),
                    CreateOne(crypto, suite, serverKey, serverIv, serverMac, encryptThenMac, implicitIv));
        }

        private static IRecordCipher CreateOne(ITlsCrypto crypto, CipherSuiteInfo suite, byte[] key, byte[] iv, byte[] macKey, bool encryptThenMac, bool implicitIv)
        {
            TlsAeadAlgorithm? aead = suite.Cipher switch
            {
                BulkCipherAlgorithm.Aes128Gcm or BulkCipherAlgorithm.Aes256Gcm => TlsAeadAlgorithm.AesGcm,
                BulkCipherAlgorithm.Camellia128Gcm or BulkCipherAlgorithm.Camellia256Gcm => TlsAeadAlgorithm.CamelliaGcm,
                BulkCipherAlgorithm.Aria128Gcm or BulkCipherAlgorithm.Aria256Gcm => TlsAeadAlgorithm.AriaGcm,
                BulkCipherAlgorithm.Aes128Ccm or BulkCipherAlgorithm.Aes256Ccm => TlsAeadAlgorithm.AesCcm,
                BulkCipherAlgorithm.Aes128Ccm8 or BulkCipherAlgorithm.Aes256Ccm8 => TlsAeadAlgorithm.AesCcm8,
                _ => null,
            };
            if (aead != null)
                return new ImplicitNonceAeadRecordCipher(crypto.CreateAead(aead.Value, key), iv);
            if (suite.Cipher == BulkCipherAlgorithm.ChaCha20Poly1305)
                return new ChaCha20Poly1305RecordCipher(crypto.CreateAead(TlsAeadAlgorithm.ChaCha20Poly1305, key), iv);
            if (suite.Cipher == BulkCipherAlgorithm.Null)
                return new NullRecordCipher(crypto.CreateHmac(Hash(suite.Mac), macKey));

            TlsBlockCipherAlgorithm block = suite.Cipher switch
            {
                BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes256Cbc => TlsBlockCipherAlgorithm.Aes,
                BulkCipherAlgorithm.Camellia128Cbc or BulkCipherAlgorithm.Camellia256Cbc => TlsBlockCipherAlgorithm.Camellia,
                BulkCipherAlgorithm.Aria128Cbc or BulkCipherAlgorithm.Aria256Cbc => TlsBlockCipherAlgorithm.Aria,
                BulkCipherAlgorithm.SeedCbc => TlsBlockCipherAlgorithm.Seed,
                BulkCipherAlgorithm.TripleDesEdeCbc => TlsBlockCipherAlgorithm.TripleDes,
                BulkCipherAlgorithm.DesCbc => TlsBlockCipherAlgorithm.Des,
                BulkCipherAlgorithm.IdeaCbc => TlsBlockCipherAlgorithm.Idea,
                _ => throw new DtlsException(AlertDescription.InternalError, $"No record cipher for {suite.Cipher}"),
            };
            return new CbcRecordCipher(crypto.CreateBlockCipher(block, key), crypto.CreateHmac(Hash(suite.Mac), macKey), encryptThenMac, implicitIv ? iv : null);
        }

        internal static TlsHashAlgorithm Hash(MacAlgorithm mac) => mac switch
        {
            MacAlgorithm.HmacMd5 => TlsHashAlgorithm.Md5,
            MacAlgorithm.HmacSha1 => TlsHashAlgorithm.Sha1,
            MacAlgorithm.HmacSha256 => TlsHashAlgorithm.Sha256,
            MacAlgorithm.HmacSha384 => TlsHashAlgorithm.Sha384,
            _ => throw new ArgumentOutOfRangeException(nameof(mac)),
        };

        internal static void Dispose(object primitive) => (primitive as IDisposable)?.Dispose();

        /// <summary>A fragment of a new array, for the handshake and the tests.</summary>
        public static byte[] Encrypt(this IRecordCipher cipher, byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext,
            byte[] connectionId = null)
        {
            byte[] fragment = new byte[cipher.FragmentLength(plaintext.Length)];
            cipher.Encrypt(contentType, version, epoch, sequenceNumber, plaintext, fragment, connectionId);
            return fragment;
        }

        /// <summary>The plaintext as a new array, for the tests.</summary>
        public static byte[] Decrypt(this IRecordCipher cipher, byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment,
            byte[] connectionId = null)
        {
            byte[] plaintext = new byte[fragment.Length];
            int length = cipher.Decrypt(contentType, version, epoch, sequenceNumber, fragment, plaintext, connectionId);
            return plaintext.AsSpan(0, length).ToArray();
        }

        /// <summary>
        /// seq_num(8) || type(1) || version(2) || length(2): the MAC / AEAD additional data prefix. With a CID
        /// (RFC 9146 §5): seq_num_placeholder(8 × 0xff) || tls12_cid || cid_length || tls12_cid || version || epoch ||
        /// sequence_number || cid || length. Written to <paramref name="aad"/>, of <see cref="MaxAdditionalDataLength"/>
        /// bytes; returns its length.
        /// </summary>
        internal static int AdditionalData(Span<byte> aad, byte contentType, ushort version, ushort epoch, ulong sequenceNumber, int length,
            ReadOnlySpan<byte> connectionId)
        {
            if (connectionId.Length > 0)
            {
                const byte Tls12Cid = 25;
                aad.Slice(0, 8).Fill(0xff);
                aad[8] = Tls12Cid;
                aad[9] = (byte)connectionId.Length;
                aad[10] = Tls12Cid;
                BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(11), version);
                BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(13), epoch);
                BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(15), (ushort)(sequenceNumber >> 32));
                BinaryPrimitives.WriteUInt32BigEndian(aad.Slice(17), (uint)sequenceNumber);
                connectionId.CopyTo(aad.Slice(21));
                BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(21 + connectionId.Length), (ushort)length);
                return 23 + connectionId.Length;
            }

            BinaryPrimitives.WriteUInt64BigEndian(aad, ((ulong)epoch << 48) | (sequenceNumber & 0xFFFFFFFFFFFFUL));
            aad[8] = contentType;
            BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(9), version);
            BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(11), (ushort)length);
            return 13;
        }

        /// <summary>HMAC(additional data || data) into <paramref name="mac"/>.</summary>
        internal static void Mac(ITlsHash hmac, byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> connectionId, Span<byte> mac)
        {
            Span<byte> aad = stackalloc byte[MaxAdditionalDataLength];
            hmac.Append(aad.Slice(0, AdditionalData(aad, contentType, version, epoch, sequenceNumber, data.Length, connectionId)));
            hmac.Append(data);
            hmac.Finish(mac);
        }
    }

    /// <summary>
    /// AEAD with a 4-byte implicit and 8-byte explicit nonce: GCM (RFC 5288, RFC 6367, RFC 6209) and
    /// CCM / CCM_8 (RFC 6655).
    /// </summary>
    internal sealed class ImplicitNonceAeadRecordCipher : IRecordCipher
    {
        private const int ExplicitNonceLength = 8;
        private readonly ITlsAead _aead;
        private readonly byte[] _fixedIv;

        public ImplicitNonceAeadRecordCipher(ITlsAead aead, byte[] fixedIv)
        {
            _aead = aead;
            _fixedIv = fixedIv;
        }

        public int FragmentLength(int plaintextLength) => ExplicitNonceLength + plaintextLength + _aead.TagLength;

        public void Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> plaintext, Span<byte> fragment,
            ReadOnlySpan<byte> connectionId)
        {
            // The explicit nonce is the 64-bit record sequence number, which never repeats under one key.
            BinaryPrimitives.WriteUInt64BigEndian(fragment, ((ulong)epoch << 48) | sequenceNumber);
            Span<byte> nonce = stackalloc byte[12];
            Nonce(fragment, nonce);
            Span<byte> aad = stackalloc byte[RecordCiphers.MaxAdditionalDataLength];
            int aadLength = RecordCiphers.AdditionalData(aad, contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId);
            _aead.Seal(nonce, aad.Slice(0, aadLength), plaintext, fragment.Slice(ExplicitNonceLength, plaintext.Length + _aead.TagLength));
        }

        public int Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment, Span<byte> plaintext,
            ReadOnlySpan<byte> connectionId)
        {
            int plaintextLength = fragment.Length - ExplicitNonceLength - _aead.TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            Span<byte> nonce = stackalloc byte[12];
            Nonce(fragment, nonce);
            Span<byte> aad = stackalloc byte[RecordCiphers.MaxAdditionalDataLength];
            int aadLength = RecordCiphers.AdditionalData(aad, contentType, version, epoch, sequenceNumber, plaintextLength, connectionId);
            if (!_aead.Open(nonce, aad.Slice(0, aadLength), fragment.Slice(ExplicitNonceLength), plaintext))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return plaintextLength;
        }

        private void Nonce(ReadOnlySpan<byte> record, Span<byte> nonce)
        {
            _fixedIv.AsSpan(0, 4).CopyTo(nonce);
            record.Slice(0, ExplicitNonceLength).CopyTo(nonce.Slice(4));
        }

        public void Dispose() => RecordCiphers.Dispose(_aead);
    }

    /// <summary>NULL encryption with an HMAC (RFC 5246 §6.2.3.1): integrity only.</summary>
    internal sealed class NullRecordCipher : IRecordCipher
    {
        private readonly ITlsHash _mac;

        public NullRecordCipher(ITlsHash mac) => _mac = mac;

        public int FragmentLength(int plaintextLength) => plaintextLength + _mac.HashLength;

        public void Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> plaintext, Span<byte> fragment,
            ReadOnlySpan<byte> connectionId)
        {
            plaintext.CopyTo(fragment);
            RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, plaintext, connectionId, fragment.Slice(plaintext.Length, _mac.HashLength));
        }

        public int Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment, Span<byte> plaintext,
            ReadOnlySpan<byte> connectionId)
        {
            int length = fragment.Length - _mac.HashLength;
            if (length < 0)
                throw new DtlsRecordDiscardedException("Record too short");
            Span<byte> expected = stackalloc byte[_mac.HashLength];
            RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, fragment.Slice(0, length), connectionId, expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.Slice(length)))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            fragment.Slice(0, length).CopyTo(plaintext);
            return length;
        }

        public void Dispose() => RecordCiphers.Dispose(_mac);
    }

    /// <summary>ChaCha20-Poly1305 with nonce = IV XOR padded sequence number (RFC 7905).</summary>
    internal sealed class ChaCha20Poly1305RecordCipher : IRecordCipher
    {
        private readonly ITlsAead _aead;
        private readonly byte[] _iv;

        public ChaCha20Poly1305RecordCipher(ITlsAead aead, byte[] iv)
        {
            _aead = aead;
            _iv = iv;
        }

        public int FragmentLength(int plaintextLength) => plaintextLength + _aead.TagLength;

        public void Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> plaintext, Span<byte> fragment,
            ReadOnlySpan<byte> connectionId)
        {
            Span<byte> nonce = stackalloc byte[12];
            Nonce(epoch, sequenceNumber, nonce);
            Span<byte> aad = stackalloc byte[RecordCiphers.MaxAdditionalDataLength];
            int aadLength = RecordCiphers.AdditionalData(aad, contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId);
            _aead.Seal(nonce, aad.Slice(0, aadLength), plaintext, fragment.Slice(0, plaintext.Length + _aead.TagLength));
        }

        public int Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment, Span<byte> plaintext,
            ReadOnlySpan<byte> connectionId)
        {
            int plaintextLength = fragment.Length - _aead.TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            Span<byte> nonce = stackalloc byte[12];
            Nonce(epoch, sequenceNumber, nonce);
            Span<byte> aad = stackalloc byte[RecordCiphers.MaxAdditionalDataLength];
            int aadLength = RecordCiphers.AdditionalData(aad, contentType, version, epoch, sequenceNumber, plaintextLength, connectionId);
            if (!_aead.Open(nonce, aad.Slice(0, aadLength), fragment, plaintext))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return plaintextLength;
        }

        private void Nonce(ushort epoch, ulong sequenceNumber, Span<byte> nonce)
        {
            ByteSpans.XorNonce(_iv, ((ulong)epoch << 48) | sequenceNumber, nonce);
        }

        public void Dispose() => RecordCiphers.Dispose(_aead);
    }

    /// <summary>
    /// Block cipher in CBC mode with HMAC, either MAC-then-encrypt (RFC 5246 §6.2.3.2) or encrypt-then-MAC (RFC 7366).
    /// Records carry an explicit random IV, or in TLS 1.0 (RFC 2246 §6.2.3.2) none: the IV is the last ciphertext
    /// block of the previous record in the same direction, starting from the key block.
    /// </summary>
    internal sealed class CbcRecordCipher : IRecordCipher
    {
        private readonly ITlsBlockCipher _cipher;
        private readonly ITlsHash _mac;
        private readonly bool _encryptThenMac;
        private readonly int _blockSize;
        private readonly int _macLength;

        // TLS 1.0's chained IV; null for explicit IVs.
        private readonly byte[] _chainedIv;

        public CbcRecordCipher(ITlsBlockCipher cipher, ITlsHash mac, bool encryptThenMac, byte[] chainedIv = null)
        {
            _cipher = cipher;
            _mac = mac;
            _encryptThenMac = encryptThenMac;
            _chainedIv = chainedIv;
            _blockSize = cipher.BlockSize;
            _macLength = mac.HashLength;
        }

        private int ExplicitIvLength => _chainedIv == null ? _blockSize : 0;

        // MtE pads plaintext || MAC; EtM pads the plaintext and MACs IV || ciphertext
        private int Padded(int plaintextLength)
        {
            int content = plaintextLength + (_encryptThenMac ? 0 : _macLength);
            return content + _blockSize - content % _blockSize;
        }

        public int FragmentLength(int plaintextLength) => ExplicitIvLength + Padded(plaintextLength) + (_encryptThenMac ? _macLength : 0);

        public void Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> plaintext, Span<byte> fragment,
            ReadOnlySpan<byte> connectionId)
        {
            int content = plaintext.Length + (_encryptThenMac ? 0 : _macLength);
            int padded = Padded(plaintext.Length);

            Span<byte> iv = stackalloc byte[_blockSize];
            if (_chainedIv == null)
            {
                RandomNumberGenerator.Fill(iv);
                iv.CopyTo(fragment);
            }
            else
            {
                _chainedIv.CopyTo(iv);
            }

            var body = fragment.Slice(ExplicitIvLength, padded);
            plaintext.CopyTo(body);
            if (!_encryptThenMac)
                RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, plaintext, connectionId, body.Slice(plaintext.Length, _macLength));
            body.Slice(content).Fill((byte)(padded - content - 1));
            _cipher.EncryptCbc(iv, body, body);
            if (_encryptThenMac)
                RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, fragment.Slice(0, ExplicitIvLength + padded), connectionId,
                    fragment.Slice(ExplicitIvLength + padded, _macLength));
            Chain(body);
        }

        // The next record's IV is this record's last ciphertext block (TLS 1.0).
        private void Chain(ReadOnlySpan<byte> ciphertext)
        {
            if (_chainedIv != null)
                ciphertext.Slice(ciphertext.Length - _blockSize).CopyTo(_chainedIv);
        }

        public int Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment, Span<byte> plaintext,
            ReadOnlySpan<byte> connectionId)
            => _encryptThenMac
                ? DecryptEncryptThenMac(contentType, version, epoch, sequenceNumber, fragment, plaintext, connectionId)
                : DecryptMacThenEncrypt(contentType, version, epoch, sequenceNumber, fragment, plaintext, connectionId);

        private int DecryptEncryptThenMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment,
            Span<byte> plaintext, ReadOnlySpan<byte> connectionId)
        {
            int ivAndCiphertextLength = fragment.Length - _macLength;
            if (ivAndCiphertextLength < ExplicitIvLength + _blockSize || (ivAndCiphertextLength - ExplicitIvLength) % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            Span<byte> expected = stackalloc byte[_macLength];
            RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, fragment.Slice(0, ivAndCiphertextLength), connectionId, expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.Slice(ivAndCiphertextLength, _macLength)))
                throw new DtlsRecordDiscardedException("Record failed authentication");

            // The MAC was verified first, so padding errors cannot act as an oracle.
            var padded = plaintext.Slice(0, ivAndCiphertextLength - ExplicitIvLength);
            Decrypt(fragment.Slice(0, ivAndCiphertextLength), padded);
            int padLength = padded[padded.Length - 1];
            if (padLength + 1 > padded.Length)
                throw new DtlsRecordDiscardedException("Invalid padding");
            for (int i = padded.Length - padLength - 1; i < padded.Length; i++)
                if (padded[i] != padLength)
                    throw new DtlsRecordDiscardedException("Invalid padding");
            return padded.Length - padLength - 1;
        }

        /// <summary>
        /// Every failure takes the same path, and padding is checked in constant time over the maximum
        /// possible padding length, so the result cannot be used as a padding oracle. Residual timing
        /// from the MAC length (Lucky13) is not fully eliminated.
        /// </summary>
        private int DecryptMacThenEncrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment,
            Span<byte> output, ReadOnlySpan<byte> connectionId)
        {
            int ciphertextLength = fragment.Length - ExplicitIvLength;
            if (ciphertextLength < _macLength + 1 || ciphertextLength % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            var plaintext = output.Slice(0, ciphertextLength);
            Decrypt(fragment, plaintext);

            int padLength = plaintext[plaintext.Length - 1];
            int good = (padLength + 1 + _macLength <= plaintext.Length) ? 1 : 0;
            int toCheck = Math.Min(256, plaintext.Length);
            int mismatch = 0;
            for (int i = 1; i <= toCheck; i++)
            {
                int inPadding = ((padLength + 1 - i) >> 31) + 1; // 1 when i <= padLength + 1, else 0
                mismatch |= (plaintext[plaintext.Length - i] ^ padLength) & (-inPadding);
            }
            good &= mismatch == 0 ? 1 : 0;

            // With bad padding, MAC as if there were no padding so the work done is similar.
            int effectivePad = good == 1 ? padLength + 1 : 0;
            int contentLength = plaintext.Length - _macLength - effectivePad;

            Span<byte> expected = stackalloc byte[_macLength];
            RecordCiphers.Mac(_mac, contentType, version, epoch, sequenceNumber, plaintext.Slice(0, contentLength), connectionId, expected);
            good &= CryptographicOperations.FixedTimeEquals(expected, plaintext.Slice(contentLength, _macLength)) ? 1 : 0;

            if (good != 1)
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return contentLength;
        }

        // IV (explicit, or chained) || ciphertext into output; the chained IV moves on.
        private void Decrypt(ReadOnlySpan<byte> ivAndCiphertext, Span<byte> output)
        {
            var ciphertext = ivAndCiphertext.Slice(ExplicitIvLength);
            _cipher.DecryptCbc(_chainedIv ?? ivAndCiphertext.Slice(0, _blockSize), ciphertext, output);
            Chain(ciphertext);
        }

        public void Dispose()
        {
            RecordCiphers.Dispose(_cipher);
            RecordCiphers.Dispose(_mac);
        }
    }
}
