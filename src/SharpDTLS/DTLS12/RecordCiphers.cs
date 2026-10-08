using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// Protection for DTLS 1.0/1.2 records in one direction (RFC 5246 §6.2.3, RFC 6347 §4.1.2.1).
    /// The 64-bit sequence number used in MACs and nonces is epoch (16 bits) || sequence number (48 bits).
    /// </summary>
    public interface IRecordCipher
    {
        byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext);

        /// <summary>Throws <see cref="DtlsRecordDiscardedException"/> when the record does not authenticate.</summary>
        byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment);
    }

    public static class RecordCiphers
    {
        /// <summary>Length of the key block: MAC keys, encryption keys and fixed IVs for both directions.</summary>
        public static int KeyBlockLength(CipherSuiteInfo suite)
            => 2 * (suite.MacKeyLength + suite.KeyLength + suite.FixedIvLength);

        /// <summary>
        /// Splits the key block (client_write_MAC_key, server_write_MAC_key, client_write_key,
        /// server_write_key, client_write_IV, server_write_IV) into the two directional ciphers.
        /// </summary>
        public static (IRecordCipher ClientWrite, IRecordCipher ServerWrite) Create(CipherSuiteInfo suite, byte[] keyBlock, bool encryptThenMac)
        {
            int mac = suite.MacKeyLength, key = suite.KeyLength, iv = suite.FixedIvLength;
            byte[] Slice(int offset, int length) => keyBlock.AsSpan(offset, length).ToArray();

            byte[] clientMac = Slice(0, mac);
            byte[] serverMac = Slice(mac, mac);
            byte[] clientKey = Slice(2 * mac, key);
            byte[] serverKey = Slice(2 * mac + key, key);
            byte[] clientIv  = Slice(2 * mac + 2 * key, iv);
            byte[] serverIv  = Slice(2 * mac + 2 * key + iv, iv);

            return (CreateOne(suite, clientKey, clientIv, clientMac, encryptThenMac),
                    CreateOne(suite, serverKey, serverIv, serverMac, encryptThenMac));
        }

        private static IRecordCipher CreateOne(CipherSuiteInfo suite, byte[] key, byte[] iv, byte[] macKey, bool encryptThenMac)
        {
            switch (suite.Cipher)
            {
                case BulkCipherAlgorithm.Aes128Gcm:
                case BulkCipherAlgorithm.Aes256Gcm:
                    return new GcmRecordCipher(key, iv);
                case BulkCipherAlgorithm.ChaCha20Poly1305:
                    return new ChaCha20Poly1305RecordCipher(key, iv);
                case BulkCipherAlgorithm.Aes128Cbc:
                case BulkCipherAlgorithm.Aes256Cbc:
                    return new CbcRecordCipher(() => new AesEngine(), key, macKey, suite.Mac, encryptThenMac);
                default:
                    throw new DtlsException(AlertDescription.InternalError, $"No record cipher for {suite.Cipher}");
            }
        }

        /// <summary>seq_num(8) || type(1) || version(2) || length(2): the MAC / AEAD additional data prefix.</summary>
        internal static byte[] AdditionalData(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, int length)
        {
            byte[] aad = new byte[13];
            BinaryPrimitives.WriteUInt64BigEndian(aad, ((ulong)epoch << 48) | (sequenceNumber & 0xFFFFFFFFFFFFUL));
            aad[8] = contentType;
            BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(9), version);
            BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)length);
            return aad;
        }

        internal static IMac CreateHmac(MacAlgorithm mac) => mac switch
        {
            MacAlgorithm.HmacSha1 => new HMac(new Sha1Digest()),
            MacAlgorithm.HmacSha256 => new HMac(new Sha256Digest()),
            MacAlgorithm.HmacSha384 => new HMac(new Sha384Digest()),
            _ => throw new ArgumentOutOfRangeException(nameof(mac)),
        };
    }

    /// <summary>AES-GCM with a 4-byte implicit and 8-byte explicit nonce (RFC 5288).</summary>
    internal sealed class GcmRecordCipher : IRecordCipher
    {
        private const int ExplicitNonceLength = 8;
        private const int TagLength = 16;
        private readonly byte[] _key;
        private readonly byte[] _fixedIv;

        public GcmRecordCipher(byte[] key, byte[] fixedIv)
        {
            _key = key;
            _fixedIv = fixedIv;
        }

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext)
        {
            byte[] output = new byte[ExplicitNonceLength + plaintext.Length + TagLength];
            // The explicit nonce is the 64-bit record sequence number, which never repeats under one key.
            BinaryPrimitives.WriteUInt64BigEndian(output, ((ulong)epoch << 48) | sequenceNumber);

            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(output),
                RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length)));
            int written = gcm.ProcessBytes(plaintext, 0, plaintext.Length, output, ExplicitNonceLength);
            gcm.DoFinal(output, ExplicitNonceLength + written);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment)
        {
            int plaintextLength = fragment.Length - ExplicitNonceLength - TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            try
            {
                var gcm = new GcmBlockCipher(new AesEngine());
                gcm.Init(false, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(fragment),
                    RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength)));
                int written = gcm.ProcessBytes(fragment, ExplicitNonceLength, fragment.Length - ExplicitNonceLength, plaintext, 0);
                gcm.DoFinal(plaintext, written);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new DtlsRecordDiscardedException("Record failed authentication", ex);
            }
            return plaintext;
        }

        private byte[] Nonce(byte[] record)
        {
            byte[] nonce = new byte[12];
            Buffer.BlockCopy(_fixedIv, 0, nonce, 0, 4);
            Buffer.BlockCopy(record, 0, nonce, 4, ExplicitNonceLength);
            return nonce;
        }
    }

    /// <summary>ChaCha20-Poly1305 with nonce = IV XOR padded sequence number (RFC 7905).</summary>
    internal sealed class ChaCha20Poly1305RecordCipher : IRecordCipher
    {
        private const int TagLength = 16;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public ChaCha20Poly1305RecordCipher(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext)
        {
            byte[] output = new byte[plaintext.Length + TagLength];
            var aead = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            aead.Init(true, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(epoch, sequenceNumber),
                RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length)));
            int written = aead.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            aead.DoFinal(output, written);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment)
        {
            int plaintextLength = fragment.Length - TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            try
            {
                var aead = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
                aead.Init(false, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(epoch, sequenceNumber),
                    RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength)));
                int written = aead.ProcessBytes(fragment, 0, fragment.Length, plaintext, 0);
                aead.DoFinal(plaintext, written);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new DtlsRecordDiscardedException("Record failed authentication", ex);
            }
            return plaintext;
        }

        private byte[] Nonce(ushort epoch, ulong sequenceNumber)
        {
            byte[] nonce = (byte[])_iv.Clone();
            ulong seq = ((ulong)epoch << 48) | sequenceNumber;
            for (int i = 0; i < 8; i++)
                nonce[11 - i] ^= (byte)(seq >> (8 * i));
            return nonce;
        }
    }

    /// <summary>
    /// Block cipher in CBC mode with an explicit per-record IV and HMAC, either MAC-then-encrypt
    /// (RFC 5246 §6.2.3.2) or encrypt-then-MAC (RFC 7366).
    /// </summary>
    internal sealed class CbcRecordCipher : IRecordCipher
    {
        private readonly Func<IBlockCipher> _createEngine;
        private readonly byte[] _key;
        private readonly byte[] _macKey;
        private readonly MacAlgorithm _mac;
        private readonly bool _encryptThenMac;
        private readonly int _blockSize;
        private readonly int _macLength;
        private readonly SecureRandom _random = new SecureRandom();

        public CbcRecordCipher(Func<IBlockCipher> createEngine, byte[] key, byte[] macKey, MacAlgorithm mac, bool encryptThenMac)
        {
            _createEngine = createEngine;
            _key = key;
            _macKey = macKey;
            _mac = mac;
            _encryptThenMac = encryptThenMac;
            _blockSize = createEngine().GetBlockSize();
            _macLength = RecordCiphers.CreateHmac(mac).GetMacSize();
        }

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext)
        {
            byte[] iv = new byte[_blockSize];
            _random.NextBytes(iv);

            if (_encryptThenMac)
            {
                byte[] ciphertext = CbcProcess(true, iv, Pad(plaintext, plaintext.Length));
                byte[] ivAndCiphertext = Concat(iv, ciphertext);
                byte[] mac = ComputeMac(contentType, version, epoch, sequenceNumber, ivAndCiphertext);
                return Concat(ivAndCiphertext, mac);
            }

            byte[] macBefore = ComputeMac(contentType, version, epoch, sequenceNumber, plaintext);
            byte[] withMac = Concat(plaintext, macBefore);
            return Concat(iv, CbcProcess(true, iv, Pad(withMac, withMac.Length)));
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment)
            => _encryptThenMac
                ? DecryptEncryptThenMac(contentType, version, epoch, sequenceNumber, fragment)
                : DecryptMacThenEncrypt(contentType, version, epoch, sequenceNumber, fragment);

        private byte[] DecryptEncryptThenMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment)
        {
            int ivAndCiphertextLength = fragment.Length - _macLength;
            if (ivAndCiphertextLength < 2 * _blockSize || (ivAndCiphertextLength - _blockSize) % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            byte[] ivAndCiphertext = fragment.AsSpan(0, ivAndCiphertextLength).ToArray();
            byte[] expected = ComputeMac(contentType, version, epoch, sequenceNumber, ivAndCiphertext);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.AsSpan(ivAndCiphertextLength, _macLength)))
                throw new DtlsRecordDiscardedException("Record failed authentication");

            // The MAC was verified first, so padding errors cannot act as an oracle.
            byte[] padded = CbcProcess(false, ivAndCiphertext.AsSpan(0, _blockSize).ToArray(), ivAndCiphertext.AsSpan(_blockSize).ToArray());
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
        private byte[] DecryptMacThenEncrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment)
        {
            int ciphertextLength = fragment.Length - _blockSize;
            if (ciphertextLength < _macLength + 1 || ciphertextLength % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            byte[] plaintext = CbcProcess(false, fragment.AsSpan(0, _blockSize).ToArray(), fragment.AsSpan(_blockSize).ToArray());

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

            byte[] content = plaintext.AsSpan(0, contentLength).ToArray();
            byte[] expected = ComputeMac(contentType, version, epoch, sequenceNumber, content);
            good &= CryptographicOperations.FixedTimeEquals(expected, plaintext.AsSpan(contentLength, _macLength)) ? 1 : 0;

            if (good != 1)
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return content;
        }

        private byte[] ComputeMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] data)
        {
            var hmac = RecordCiphers.CreateHmac(_mac);
            hmac.Init(new KeyParameter(_macKey));
            byte[] header = RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, data.Length);
            hmac.BlockUpdate(header, 0, header.Length);
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);
            return mac;
        }

        // padding: padLength + 1 bytes, each equal to padLength, to a multiple of the block size
        private byte[] Pad(byte[] data, int length)
        {
            int padLength = _blockSize - 1 - (length % _blockSize);
            byte[] padded = new byte[length + padLength + 1];
            Buffer.BlockCopy(data, 0, padded, 0, length);
            for (int i = length; i < padded.Length; i++)
                padded[i] = (byte)padLength;
            return padded;
        }

        private byte[] CbcProcess(bool encrypt, byte[] iv, byte[] data)
        {
            var cbc = new CbcBlockCipher(_createEngine());
            cbc.Init(encrypt, new ParametersWithIV(new KeyParameter(_key), iv));
            byte[] output = new byte[data.Length];
            for (int i = 0; i < data.Length; i += _blockSize)
                cbc.ProcessBlock(data, i, output, i);
            return output;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
