using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers.Binary;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// DTLS 1.3 record protection (RFC 9147 §4): AEAD with per-record nonce, record number
    /// encryption, unified header parsing and sequence number reconstruction.
    /// </summary>
    public static class Dtls13RecordProtection
    {
        private const int SampleLength = 16;

        public readonly struct UnprotectedRecord
        {
            public UnprotectedRecord(int epochBits, ulong sequenceNumber, byte[] innerPlaintext)
            {
                EpochBits = epochBits;
                SequenceNumber = sequenceNumber;
                InnerPlaintext = innerPlaintext;
            }

            public int EpochBits { get; }
            public ulong SequenceNumber { get; }

            /// <summary>TLSInnerPlaintext with zero padding removed; the last byte is the content type.</summary>
            public byte[] InnerPlaintext { get; }
        }

        /// <summary>
        /// Builds a protected record with a full unified header (16-bit sequence number, length present).
        /// </summary>
        public static byte[] Protect(Dtls13CryptoContext ctx, bool fromClient, int epoch, ulong sequenceNumber, byte[] innerPlaintext)
        {
            var suite = ctx.Suite;
            byte[] key   = fromClient ? ctx.ClientKey   : ctx.ServerKey;
            byte[] iv    = fromClient ? ctx.ClientIv    : ctx.ServerIv;
            byte[] snKey = fromClient ? ctx.ClientSnKey : ctx.ServerSnKey;

            const int headerLength = 5;

            // RFC 9147 §4.2.3: the record number mask needs 16 bytes of ciphertext, so short records
            // (possible with CCM_8's 8-byte tag) are zero-padded as TLSInnerPlaintext padding.
            if (innerPlaintext.Length + suite.TagLength < SampleLength)
                Array.Resize(ref innerPlaintext, SampleLength - suite.TagLength);

            int ciphertextLength = innerPlaintext.Length + suite.TagLength;
            if (ciphertextLength > 0xFFFF)
                throw new DtlsException(AlertDescription.RecordOverflow, "Record too large");

            byte[] record = new byte[headerLength + ciphertextLength];
            record[0] = (byte)(0x20 | 0x08 | 0x04 | (epoch & 0x03)); // fixed bits, S=1 (16-bit seq), L=1
            record[1] = (byte)(sequenceNumber >> 8);
            record[2] = (byte)sequenceNumber;
            record[3] = (byte)(ciphertextLength >> 8);
            record[4] = (byte)ciphertextLength;

            byte[] aad = new byte[headerLength];
            Buffer.BlockCopy(record, 0, aad, 0, headerLength);

            suite.Cipher.Seal(key, BuildNonce(iv, sequenceNumber), aad, innerPlaintext).CopyTo(record, headerLength);

            byte[] mask = ComputeMask(suite, snKey, record, headerLength);
            if (mask != null)
            {
                record[1] ^= mask[0];
                record[2] ^= mask[1];
            }

            return record;
        }

        /// <summary>
        /// Removes record number encryption, reconstructs the sequence number, rejects replays and
        /// decrypts the record. Throws <see cref="DtlsRecordDiscardedException"/> for records that must be dropped.
        /// </summary>
        public static UnprotectedRecord Unprotect(Dtls13CryptoContext ctx, bool fromClient, byte[] record)
        {
            if (!TryReadHeader(ctx, fromClient, record, out int headerLength, out int seqLength, out ulong sequenceNumber))
                throw new DtlsRecordDiscardedException("Malformed DTLS 1.3 record header");

            var window = fromClient ? ctx.ClientRecords : ctx.ServerRecords;
            if (window.IsDuplicate(sequenceNumber))
                throw new DtlsRecordDiscardedException($"Replayed record {sequenceNumber}");

            var suite = ctx.Suite;
            byte[] key = fromClient ? ctx.ClientKey : ctx.ServerKey;
            byte[] iv  = fromClient ? ctx.ClientIv  : ctx.ServerIv;

            // AAD is the header as sent, but before record number encryption (RFC 9147 §4).
            byte[] aad = new byte[headerLength];
            Buffer.BlockCopy(record, 0, aad, 0, headerLength);
            int seqOffset = headerLength - seqLength - (((record[0] & 0x04) != 0) ? 2 : 0);
            if (seqLength == 2)
            {
                aad[seqOffset]     = (byte)(sequenceNumber >> 8);
                aad[seqOffset + 1] = (byte)sequenceNumber;
            }
            else
            {
                aad[seqOffset] = (byte)sequenceNumber;
            }

            byte[] plaintext = suite.Cipher.Open(key, BuildNonce(iv, sequenceNumber), aad, record.AsSpan(headerLength).ToArray())
                ?? throw new DtlsRecordDiscardedException("Record failed authentication");

            window.Mark(sequenceNumber);

            // strip TLSInnerPlaintext zero padding; the last non-zero byte is the content type
            int end = plaintext.Length;
            while (end > 0 && plaintext[end - 1] == 0)
                end--;
            if (end == 0)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Record has no content type");

            if (end != plaintext.Length)
                Array.Resize(ref plaintext, end);

            return new UnprotectedRecord(record[0] & 0x03, sequenceNumber, plaintext);
        }

        /// <summary>
        /// Decodes the full sequence number of a protected record without decrypting it.
        /// Returns false for malformed headers.
        /// </summary>
        public static bool TryPeekSequenceNumber(Dtls13CryptoContext ctx, bool fromClient, byte[] record, out ulong sequenceNumber)
        {
            return TryReadHeader(ctx, fromClient, record, out _, out _, out sequenceNumber);
        }

        private static bool TryReadHeader(Dtls13CryptoContext ctx, bool fromClient, byte[] record, out int headerLength, out int seqLength, out ulong sequenceNumber)
        {
            headerLength = 0;
            seqLength = 0;
            sequenceNumber = 0;

            if (record.Length < 1 || (record[0] & 0xE0) != 0x20)
                return false;

            bool hasCid    = (record[0] & 0x10) != 0;
            bool seq16     = (record[0] & 0x08) != 0;
            bool hasLength = (record[0] & 0x04) != 0;

            if (hasCid)
                return false; // connection IDs are not negotiated yet

            seqLength = seq16 ? 2 : 1;
            headerLength = 1 + seqLength + (hasLength ? 2 : 0);

            if (record.Length < headerLength + SampleLength)
                return false;

            if (hasLength)
            {
                int declared = (record[headerLength - 2] << 8) | record[headerLength - 1];
                if (declared != record.Length - headerLength)
                    return false;
            }

            var suite = ctx.Suite;
            byte[] snKey = fromClient ? ctx.ClientSnKey : ctx.ServerSnKey;
            byte[] mask = ComputeMask(suite, snKey, record, headerLength) ?? new byte[2];

            ulong truncated = seq16
                ? (ulong)(((record[1] ^ mask[0]) << 8) | (record[2] ^ mask[1]))
                : (ulong)(record[1] ^ mask[0]);

            var window = fromClient ? ctx.ClientRecords : ctx.ServerRecords;
            sequenceNumber = window.Reconstruct(truncated, seqLength * 8);
            return true;
        }

        // RFC 8446 §5.3: nonce = iv XOR (64-bit sequence number, left-padded to iv length).
        // RFC 9147 §4: the epoch is not part of the AEAD sequence number in DTLS 1.3.
        internal static byte[] BuildNonce(byte[] iv, ulong sequenceNumber)
        {
            byte[] nonce = (byte[])iv.Clone();
            for (int i = 0; i < 8; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(sequenceNumber >> (8 * i));
            return nonce;
        }

        // RFC 9147 §4.2.3; null when the suite sends record numbers in the clear.
        internal static byte[] ComputeMask(Dtls13CipherSuite suite, byte[] snKey, byte[] record, int ciphertextOffset)
            => suite.Cipher.Mask(snKey, record.AsSpan(ciphertextOffset));
    }

    /// <summary>
    /// The raw ChaCha20 block function (RFC 8439 §2.3), needed because record number encryption
    /// takes the block counter from the ciphertext sample.
    /// </summary>
    internal static class ChaCha20Block
    {
        public static byte[] Compute(byte[] key, uint counter, byte[] nonce)
        {
            if (key.Length != 32) throw new ArgumentException("ChaCha20 key must be 32 bytes", nameof(key));
            if (nonce.Length != 12) throw new ArgumentException("ChaCha20 nonce must be 12 bytes", nameof(nonce));

            Span<uint> state = stackalloc uint[16];
            state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
            for (int i = 0; i < 8; i++)
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4, 4));
            state[12] = counter;
            for (int i = 0; i < 3; i++)
                state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4, 4));

            Span<uint> x = stackalloc uint[16];
            state.CopyTo(x);
            for (int i = 0; i < 10; i++)
            {
                QuarterRound(x, 0, 4, 8, 12); QuarterRound(x, 1, 5, 9, 13);
                QuarterRound(x, 2, 6, 10, 14); QuarterRound(x, 3, 7, 11, 15);
                QuarterRound(x, 0, 5, 10, 15); QuarterRound(x, 1, 6, 11, 12);
                QuarterRound(x, 2, 7, 8, 13); QuarterRound(x, 3, 4, 9, 14);
            }

            byte[] output = new byte[64];
            for (int i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4, 4), x[i] + state[i]);
            return output;
        }

        private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 8);
            x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 7);
        }
    }
}
