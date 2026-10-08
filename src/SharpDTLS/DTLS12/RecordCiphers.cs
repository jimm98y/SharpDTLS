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
        /// <param name="connectionId">The CID of a tls12_cid record (RFC 9146), which changes the MAC / AEAD input; null otherwise.</param>
        byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null);

        /// <summary>Throws <see cref="DtlsRecordDiscardedException"/> when the record does not authenticate.</summary>
        byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null);
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
                    return new ImplicitNonceAeadRecordCipher(() => new GcmBlockCipher(new AesEngine()), key, iv, 16);
                case BulkCipherAlgorithm.Camellia128Gcm:
                case BulkCipherAlgorithm.Camellia256Gcm:
                    return new ImplicitNonceAeadRecordCipher(() => new GcmBlockCipher(new CamelliaEngine()), key, iv, 16);
                case BulkCipherAlgorithm.Aria128Gcm:
                case BulkCipherAlgorithm.Aria256Gcm:
                    return new ImplicitNonceAeadRecordCipher(() => new GcmBlockCipher(new AriaEngine()), key, iv, 16);
                case BulkCipherAlgorithm.Aes128Ccm:
                case BulkCipherAlgorithm.Aes256Ccm:
                    return new ImplicitNonceAeadRecordCipher(() => new CcmBlockCipher(new AesEngine()), key, iv, 16);
                case BulkCipherAlgorithm.Aes128Ccm8:
                case BulkCipherAlgorithm.Aes256Ccm8:
                    return new ImplicitNonceAeadRecordCipher(() => new CcmBlockCipher(new AesEngine()), key, iv, 8);
                case BulkCipherAlgorithm.ChaCha20Poly1305:
                    return new ChaCha20Poly1305RecordCipher(key, iv);
                case BulkCipherAlgorithm.Null:
                    return new NullRecordCipher(macKey, suite.Mac);
                default:
                    var engine = BlockCipherFactory(suite.Cipher)
                        ?? throw new DtlsException(AlertDescription.InternalError, $"No record cipher for {suite.Cipher}");
                    return new CbcRecordCipher(engine, key, macKey, suite.Mac, encryptThenMac);
            }
        }

        private static Func<IBlockCipher> BlockCipherFactory(BulkCipherAlgorithm cipher) => cipher switch
        {
            BulkCipherAlgorithm.Aes128Cbc or BulkCipherAlgorithm.Aes256Cbc => () => new AesEngine(),
            BulkCipherAlgorithm.Camellia128Cbc or BulkCipherAlgorithm.Camellia256Cbc => () => new CamelliaEngine(),
            BulkCipherAlgorithm.Aria128Cbc or BulkCipherAlgorithm.Aria256Cbc => () => new AriaEngine(),
            BulkCipherAlgorithm.SeedCbc => () => new SeedEngine(),
            BulkCipherAlgorithm.TripleDesEdeCbc => () => new DesEdeEngine(),
            BulkCipherAlgorithm.DesCbc => () => new DesEngine(),
            BulkCipherAlgorithm.IdeaCbc => () => new IdeaEngine(),
            _ => null,
        };

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

        internal static IMac CreateHmac(MacAlgorithm mac) => mac switch
        {
            MacAlgorithm.HmacMd5 => new HMac(new MD5Digest()),
            MacAlgorithm.HmacSha1 => new HMac(new Sha1Digest()),
            MacAlgorithm.HmacSha256 => new HMac(new Sha256Digest()),
            MacAlgorithm.HmacSha384 => new HMac(new Sha384Digest()),
            _ => throw new ArgumentOutOfRangeException(nameof(mac)),
        };
    }

    /// <summary>
    /// AEAD with a 4-byte implicit and 8-byte explicit nonce: GCM (RFC 5288, RFC 6367, RFC 6209) and
    /// CCM / CCM_8 (RFC 6655).
    /// </summary>
    internal sealed class ImplicitNonceAeadRecordCipher : IRecordCipher
    {
        private const int ExplicitNonceLength = 8;
        private readonly Func<IAeadBlockCipher> _create;
        private readonly byte[] _key;
        private readonly byte[] _fixedIv;
        private readonly int _tagLength;

        public ImplicitNonceAeadRecordCipher(Func<IAeadBlockCipher> create, byte[] key, byte[] fixedIv, int tagLength)
        {
            _create = create;
            _key = key;
            _fixedIv = fixedIv;
            _tagLength = tagLength;
        }

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] output = new byte[ExplicitNonceLength + plaintext.Length + _tagLength];
            // The explicit nonce is the 64-bit record sequence number, which never repeats under one key.
            BinaryPrimitives.WriteUInt64BigEndian(output, ((ulong)epoch << 48) | sequenceNumber);

            var aead = _create();
            aead.Init(true, new AeadParameters(new KeyParameter(_key), _tagLength * 8, Nonce(output),
                RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId)));
            int written = aead.ProcessBytes(plaintext, 0, plaintext.Length, output, ExplicitNonceLength);
            aead.DoFinal(output, ExplicitNonceLength + written);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int plaintextLength = fragment.Length - ExplicitNonceLength - _tagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            try
            {
                var aead = _create();
                aead.Init(false, new AeadParameters(new KeyParameter(_key), _tagLength * 8, Nonce(fragment),
                    RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength, connectionId)));
                int written = aead.ProcessBytes(fragment, ExplicitNonceLength, fragment.Length - ExplicitNonceLength, plaintext, 0);
                aead.DoFinal(plaintext, written);
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

    /// <summary>NULL encryption with an HMAC (RFC 5246 §6.2.3.1): integrity only.</summary>
    internal sealed class NullRecordCipher : IRecordCipher
    {
        private readonly byte[] _macKey;
        private readonly MacAlgorithm _mac;

        public NullRecordCipher(byte[] macKey, MacAlgorithm mac)
        {
            _macKey = macKey;
            _mac = mac;
        }

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] mac = ComputeMac(contentType, version, epoch, sequenceNumber, plaintext, plaintext.Length, connectionId);
            byte[] output = new byte[plaintext.Length + mac.Length];
            Buffer.BlockCopy(plaintext, 0, output, 0, plaintext.Length);
            Buffer.BlockCopy(mac, 0, output, plaintext.Length, mac.Length);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int macLength = RecordCiphers.CreateHmac(_mac).GetMacSize();
            int length = fragment.Length - macLength;
            if (length < 0)
                throw new DtlsRecordDiscardedException("Record too short");
            byte[] expected = ComputeMac(contentType, version, epoch, sequenceNumber, fragment, length, connectionId);
            if (!CryptographicOperations.FixedTimeEquals(expected, fragment.AsSpan(length, macLength)))
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return fragment.AsSpan(0, length).ToArray();
        }

        private byte[] ComputeMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] data, int length, byte[] connectionId)
        {
            var hmac = RecordCiphers.CreateHmac(_mac);
            hmac.Init(new KeyParameter(_macKey));
            byte[] header = RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, length, connectionId);
            hmac.BlockUpdate(header, 0, header.Length);
            hmac.BlockUpdate(data, 0, length);
            byte[] mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);
            return mac;
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] output = new byte[plaintext.Length + TagLength];
            var aead = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            aead.Init(true, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(epoch, sequenceNumber),
                RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintext.Length, connectionId)));
            int written = aead.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            aead.DoFinal(output, written);
            return output;
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
        {
            int plaintextLength = fragment.Length - TagLength;
            if (plaintextLength < 0)
                throw new DtlsRecordDiscardedException("Record too short");

            byte[] plaintext = new byte[plaintextLength];
            try
            {
                var aead = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
                aead.Init(false, new AeadParameters(new KeyParameter(_key), TagLength * 8, Nonce(epoch, sequenceNumber),
                    RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, plaintextLength, connectionId)));
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

        public byte[] Encrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] plaintext, byte[] connectionId = null)
        {
            byte[] iv = new byte[_blockSize];
            _random.NextBytes(iv);

            if (_encryptThenMac)
            {
                byte[] ciphertext = CbcProcess(true, iv, Pad(plaintext, plaintext.Length));
                byte[] ivAndCiphertext = Concat(iv, ciphertext);
                byte[] mac = ComputeMac(contentType, version, epoch, sequenceNumber, ivAndCiphertext, connectionId);
                return Concat(ivAndCiphertext, mac);
            }

            byte[] macBefore = ComputeMac(contentType, version, epoch, sequenceNumber, plaintext, connectionId);
            byte[] withMac = Concat(plaintext, macBefore);
            return Concat(iv, CbcProcess(true, iv, Pad(withMac, withMac.Length)));
        }

        public byte[] Decrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId = null)
            => _encryptThenMac
                ? DecryptEncryptThenMac(contentType, version, epoch, sequenceNumber, fragment, connectionId)
                : DecryptMacThenEncrypt(contentType, version, epoch, sequenceNumber, fragment, connectionId);

        private byte[] DecryptEncryptThenMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId)
        {
            int ivAndCiphertextLength = fragment.Length - _macLength;
            if (ivAndCiphertextLength < 2 * _blockSize || (ivAndCiphertextLength - _blockSize) % _blockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            byte[] ivAndCiphertext = fragment.AsSpan(0, ivAndCiphertextLength).ToArray();
            byte[] expected = ComputeMac(contentType, version, epoch, sequenceNumber, ivAndCiphertext, connectionId);
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
        private byte[] DecryptMacThenEncrypt(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] fragment, byte[] connectionId)
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
            byte[] expected = ComputeMac(contentType, version, epoch, sequenceNumber, content, connectionId);
            good &= CryptographicOperations.FixedTimeEquals(expected, plaintext.AsSpan(contentLength, _macLength)) ? 1 : 0;

            if (good != 1)
                throw new DtlsRecordDiscardedException("Record failed authentication");
            return content;
        }

        private byte[] ComputeMac(byte contentType, ushort version, ushort epoch, ulong sequenceNumber, byte[] data, byte[] connectionId)
        {
            var hmac = RecordCiphers.CreateHmac(_mac);
            hmac.Init(new KeyParameter(_macKey));
            byte[] header = RecordCiphers.AdditionalData(contentType, version, epoch, sequenceNumber, data.Length, connectionId);
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
