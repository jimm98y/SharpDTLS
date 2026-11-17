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
        /// <param name="connectionId">The CID of a tls12_cid record (RFC 9146), which changes the MAC / AEAD input; null otherwise.</param>
        byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null);

        /// <summary>Throws <see cref="DtlsRecordDiscardedException"/> when the record does not authenticate.</summary>
        byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null);
    }

    internal static class RecordCiphers
    {
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

        /// <summary>
        /// seq_num(8) || type(1) || version(2) || length(2): the MAC / AEAD additional data prefix. With a CID
        /// (RFC 9146 §5): seq_num_placeholder(8 × 0xff) || tls12_cid || cid_length || tls12_cid || version || epoch ||
        /// sequence_number || cid || length.
        /// </summary>
        internal static byte[] AdditionalData(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, int length, byte[] connectionId = null)
        {
            if (connectionId != null)
            {
                const byte Tls12Cid = 25;
                return new TlsWriter()
                    .WriteBytes(new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })
                    .WriteUInt8(Tls12Cid).WriteUInt8((byte)connectionId.Length).WriteUInt8(Tls12Cid)
                    .WriteUInt16(version).WriteUInt16(epoch)
                    .WriteUInt16((int)(sequenceNumber >> 32)).WriteUInt32((uint)sequenceNumber)
                    .WriteBytes(connectionId)
                    .WriteUInt16(length)
                    .ToArray();
            }

            byte[] aad = new byte[13];
            BinaryPrimitives.WriteUInt64BigEndian(aad, ((ulong)epoch << 48) | (sequenceNumber & 0xFFFFFFFFFFFFUL));
            aad[8] = contentType;
            BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(9), version);
            BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)length);
            return aad;
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] output = new byte[ExplicitNonceLength + plaintext.Length + _aead.TagLength];
            // The explicit nonce is the 64-bit record sequence number, which never repeats under one key.
            BinaryPrimitives.WriteUInt64BigEndian(output, ((ulong)epoch << 48) | sequenceNumber);
            Span<byte> nonce = stackalloc byte[12];
            Nonce(output, nonce);
            _aead.Seal(nonce, RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId), plaintext,
                output.AsSpan(ExplicitNonceLength));
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int plaintextLength = fragment.Length - ExplicitNonceLength - _aead.TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            Span<byte> nonce = stackalloc byte[12];
            Nonce(fragment, nonce);
            if (!_aead.Open(nonce, RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength, connectionId),
                    fragment.AsSpan(ExplicitNonceLength), plaintext))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return plaintext;
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] output = new byte[plaintext.Length + _mac.HashLength];
            Buffer.BlockCopy(plaintext, 0, output, 0, plaintext.Length);
            ComputeMac(contentType, version, epoch, sequenceNumber, plaintext, connectionId, output.AsSpan(plaintext.Length));
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int length = fragment.Length - _mac.HashLength;
            if (length < 0)
                throw new DtlsRecordDiscardedException("Record too short");
            Span<byte> expected = stackalloc byte[_mac.HashLength];
            ComputeMac(contentType, version, epoch, sequenceNumber, fragment.AsSpan(0, length), connectionId, expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.AsSpan(length)))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return fragment.AsSpan(0, length).ToArray();
        }

        private void ComputeMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> data, byte[] connectionId, Span<byte> mac)
        {
            _mac.Append(RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, data.Length, connectionId));
            _mac.Append(data);
            _mac.Finish(mac);
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] output = new byte[plaintext.Length + _aead.TagLength];
            Span<byte> nonce = stackalloc byte[12];
            Nonce(epoch, sequenceNumber, nonce);
            _aead.Seal(nonce, RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId), plaintext, output);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int plaintextLength = fragment.Length - _aead.TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            Span<byte> nonce = stackalloc byte[12];
            Nonce(epoch, sequenceNumber, nonce);
            if (!_aead.Open(nonce, RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength, connectionId), fragment, plaintext))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return plaintext;
        }

        private void Nonce(ushort epoch, ulong sequenceNumber, Span<byte> nonce)
        {
            _iv.CopyTo(nonce);
            ulong seq = ((ulong)epoch << 48) | sequenceNumber;
            for (int i = 0; i < 8; i++)
                nonce[11 - i] ^= (byte)(seq >> (8 * i));
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            // MtE pads plaintext || MAC; EtM pads the plaintext and MACs IV || ciphertext
            int content = plaintext.Length + (_encryptThenMac ? 0 : _macLength);
            int padded = content + _blockSize - content % _blockSize;
            byte[] record = new byte[ExplicitIvLength + padded + (_encryptThenMac ? _macLength : 0)];

            Span<byte> iv = stackalloc byte[_blockSize];
            if (_chainedIv == null)
            {
                RandomNumberGenerator.Fill(iv);
                iv.CopyTo(record);
            }
            else
            {
                _chainedIv.CopyTo(iv);
            }

            var body = record.AsSpan(ExplicitIvLength, padded);
            plaintext.CopyTo(body);
            if (!_encryptThenMac)
                ComputeMac(contentType, version, epoch, sequenceNumber, plaintext, connectionId, body.Slice(plaintext.Length, _macLength));
            body.Slice(content).Fill((byte)(padded - content - 1));
            _cipher.EncryptCbc(iv, body, body);
            if (_encryptThenMac)
                ComputeMac(contentType, version, epoch, sequenceNumber, record.AsSpan(0, ExplicitIvLength + padded), connectionId, record.AsSpan(ExplicitIvLength + padded));
            Chain(body);
            return record;
        }

        // The next record's IV is this record's last ciphertext block (TLS 1.0).
        private void Chain(ReadOnlySpan<byte> ciphertext)
        {
            if (_chainedIv != null)
                ciphertext.Slice(ciphertext.Length - _blockSize).CopyTo(_chainedIv);
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
            => _encryptThenMac
                ? DecryptEncryptThenMac(contentType, version, epoch, sequenceNumber, fragment, connectionId)
                : DecryptMacThenEncrypt(contentType, version, epoch, sequenceNumber, fragment, connectionId);

        private byte[] DecryptEncryptThenMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId)
        {
            int ivAndCiphertextLength = fragment.Length - _macLength;
            if (ivAndCiphertextLength < ExplicitIvLength + _blockSize || (ivAndCiphertextLength - ExplicitIvLength) % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            Span<byte> expected = stackalloc byte[_macLength];
            ComputeMac(contentType, version, epoch, sequenceNumber, fragment.AsSpan(0, ivAndCiphertextLength), connectionId, expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.AsSpan(ivAndCiphertextLength, _macLength)))
                throw new DtlsRecordDiscardedException("Record failed authentication");

            // The MAC was verified first, so padding errors cannot act as an oracle.
            byte[] padded = new byte[ivAndCiphertextLength - ExplicitIvLength];
            Decrypt(fragment.AsSpan(0, ivAndCiphertextLength), padded);
            int padLength = padded[padded.Length - 1];
            if (padLength + 1 > padded.Length)
                throw new DtlsRecordDiscardedException("Invalid padding");
            for (int i = padded.Length - padLength - 1; i < padded.Length; i++)
                if (padded[i] != padLength)
                    throw new DtlsRecordDiscardedException("Invalid padding");
            return padded.AsSpan(0, padded.Length - padLength - 1).ToArray();
        }

        /// <summary>
        /// Every failure takes the same path, and padding is checked in constant time over the maximum
        /// possible padding length, so the result cannot be used as a padding oracle. Residual timing
        /// from the MAC length (Lucky13) is not fully eliminated.
        /// </summary>
        private byte[] DecryptMacThenEncrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId)
        {
            int ciphertextLength = fragment.Length - ExplicitIvLength;
            if (ciphertextLength < _macLength + 1 || ciphertextLength % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            byte[] plaintext = new byte[ciphertextLength];
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
            ComputeMac(contentType, version, epoch, sequenceNumber, plaintext.AsSpan(0, contentLength), connectionId, expected);
            good &= CryptographicOperations.FixedTimeEquals(expected, plaintext.AsSpan(contentLength, _macLength)) ? 1 : 0;

            if (good != 1)
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return plaintext.AsSpan(0, contentLength).ToArray();
        }

        // IV (explicit, or chained) || ciphertext into output; the chained IV moves on.
        private void Decrypt(ReadOnlySpan<byte> ivAndCiphertext, Span<byte> output)
        {
            var ciphertext = ivAndCiphertext.Slice(ExplicitIvLength);
            _cipher.DecryptCbc(_chainedIv ?? ivAndCiphertext.Slice(0, _blockSize), ciphertext, output);
            Chain(ciphertext);
        }

        private void ComputeMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> data, byte[] connectionId, Span<byte> mac)
        {
            _mac.Append(RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, data.Length, connectionId));
            _mac.Append(data);
            _mac.Finish(mac);
        }

        public void Dispose()
        {
            RecordCiphers.Dispose(_cipher);
            RecordCiphers.Dispose(_mac);
        }
    }
}
