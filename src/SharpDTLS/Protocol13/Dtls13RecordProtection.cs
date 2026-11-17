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

using SharpDTLS.Protocol13.DTLS13;
using System;
using System.Buffers.Binary;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// DTLS 1.3 record protection (RFC 9147 §4): AEAD with per-record nonce, record number
    /// encryption, unified header parsing and sequence number reconstruction.
    /// </summary>
    internal static class Dtls13RecordProtection
    {
        private const int SampleLength = 16;

        public readonly struct UnprotectedRecord
        {
            public UnprotectedRecord(int epochBits, ulong sequenceNumber, byte[] innerPlaintext, byte[] connectionId = null)
            {
                EpochBits = epochBits;
                SequenceNumber = sequenceNumber;
                InnerPlaintext = innerPlaintext;
                ConnectionId = connectionId;
            }

            /// <summary>The record's connection ID, or null when it had none.</summary>
            public byte[] ConnectionId { get; }

            public int EpochBits { get; }
            public ulong SequenceNumber { get; }

            /// <summary>TLSInnerPlaintext with zero padding removed; the last byte is the content type.</summary>
            public byte[] InnerPlaintext { get; }
        }

        /// <summary>The length of the protected record of <paramref name="contentLength"/> bytes of content.</summary>
        public static int ProtectedLength(Dtls13CryptoContext ctx, int contentLength, int connectionIdLength)
            => 5 + connectionIdLength + InnerLength(ctx, contentLength) + ctx.Suite.TagLength;

        // RFC 9147 §4.2.3: the record number mask needs 16 bytes of ciphertext, so short records
        // (possible with CCM_8's 8-byte tag) are zero-padded as TLSInnerPlaintext padding.
        private static int InnerLength(Dtls13CryptoContext ctx, int contentLength) => Math.Max(contentLength + 1, SampleLength - ctx.Suite.TagLength);

        /// <summary>
        /// Builds a protected record with a full unified header (16-bit sequence number, length present), carrying
        /// <paramref name="connectionId"/> when one is given (RFC 9147 §4: C bit, CID right after the first byte).
        /// </summary>
        public static byte[] Protect(Dtls13CryptoContext ctx, bool fromClient, int epoch, ulong sequenceNumber, byte[] innerPlaintext,
            byte[] connectionId = null, ITlsCrypto crypto = null)
        {
            int cid = connectionId?.Length ?? 0;
            byte[] record = new byte[ProtectedLength(ctx, innerPlaintext.Length - 1, cid)];
            Protect(ctx, fromClient, epoch, sequenceNumber, innerPlaintext.AsSpan(0, innerPlaintext.Length - 1), innerPlaintext[innerPlaintext.Length - 1],
                connectionId, record, crypto);
            return record;
        }

        /// <summary>
        /// Writes the protected record of <paramref name="content"/> and its <paramref name="contentType"/> into
        /// <paramref name="record"/>, of <see cref="ProtectedLength"/> bytes.
        /// </summary>
        public static void Protect(Dtls13CryptoContext ctx, bool fromClient, int epoch, ulong sequenceNumber, ReadOnlySpan<byte> content, byte contentType,
            ReadOnlySpan<byte> connectionId, Span<byte> record, ITlsCrypto crypto)
        {
            var suite = ctx.Suite;
            var protection = ctx.Protection(fromClient, crypto);

            int cid = connectionId.Length;
            int headerLength = 5 + cid;
            int innerLength = InnerLength(ctx, content.Length);
            int ciphertextLength = innerLength + suite.TagLength;
            if (ciphertextLength > 0xFFFF)
                throw new DtlsException(AlertDescription.RecordOverflow, "Record too large");

            record[0] = (byte)(0x20 | (cid > 0 ? 0x10 : 0) | 0x08 | 0x04 | (epoch & 0x03)); // fixed bits, C, S=1 (16-bit seq), L=1
            connectionId.CopyTo(record.Slice(1));
            record[1 + cid] = (byte)(sequenceNumber >> 8);
            record[2 + cid] = (byte)sequenceNumber;
            record[3 + cid] = (byte)(ciphertextLength >> 8);
            record[4 + cid] = (byte)ciphertextLength;

            // TLSInnerPlaintext (content || type || zeros), sealed in place
            var body = record.Slice(headerLength, ciphertextLength);
            content.CopyTo(body);
            body[content.Length] = contentType;
            body.Slice(content.Length + 1, innerLength - content.Length - 1).Clear();
            byte[] iv = fromClient ? ctx.ClientIv : ctx.ServerIv;
            Span<byte> nonce = stackalloc byte[iv.Length];
            BuildNonce(iv, sequenceNumber, nonce);
            protection.Seal(nonce, record.Slice(0, headerLength), body.Slice(0, innerLength), body);

            Span<byte> mask = stackalloc byte[2];
            if (protection.Mask(body, mask))
            {
                record[1 + cid] ^= mask[0];
                record[2 + cid] ^= mask[1];
            }
        }

        /// <summary>
        /// Removes record number encryption, reconstructs the sequence number, rejects replays and
        /// decrypts the record. Throws <see cref="DtlsRecordDiscardedException"/> for records that must be dropped.
        /// </summary>
        /// <param name="connectionIdLength">Length of the CIDs the receiver expects (0 when it expects none).</param>
        public static UnprotectedRecord Unprotect(Dtls13CryptoContext ctx, bool fromClient, byte[] record, int connectionIdLength = 0, ITlsCrypto crypto = null)
        {
            byte[] plaintext = new byte[record.Length];
            int length = Unprotect(ctx, fromClient, record, plaintext, connectionIdLength, crypto, out ulong sequenceNumber);
            byte[] connectionId = (record[0] & 0x10) != 0 ? record.AsSpan(1, connectionIdLength).ToArray() : null;
            return new UnprotectedRecord(record[0] & 0x03, sequenceNumber, plaintext.AsSpan(0, length).ToArray(), connectionId);
        }

        /// <summary>
        /// As <see cref="Unprotect(Dtls13CryptoContext, bool, byte[], int, ITlsCrypto)"/>, into <paramref name="plaintext"/>
        /// (of the record's length at least): returns the length of the TLSInnerPlaintext without its padding, the content
        /// type last.
        /// </summary>
        public static int Unprotect(Dtls13CryptoContext ctx, bool fromClient, ReadOnlySpan<byte> record, Span<byte> plaintext, int connectionIdLength,
            ITlsCrypto crypto, out ulong sequenceNumber)
        {
            if (!TryReadHeader(ctx, fromClient, record, out int headerLength, out int seqLength, out sequenceNumber, connectionIdLength, crypto))
                throw new DtlsRecordDiscardedException("Malformed DTLS 1.3 record header");

            var window = fromClient ? ctx.ClientRecords : ctx.ServerRecords;
            if (window.IsDuplicate(sequenceNumber))
                throw new DtlsRecordDiscardedException("Replayed record");

            // AAD is the header as sent, but before record number encryption (RFC 9147 §4).
            Span<byte> aad = stackalloc byte[headerLength];
            record.Slice(0, headerLength).CopyTo(aad);
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

            var ciphertext = record.Slice(headerLength);
            if (ciphertext.Length < ctx.Suite.TagLength)
                throw new DtlsRecordAuthenticationException("Record failed authentication");
            byte[] iv = fromClient ? ctx.ClientIv : ctx.ServerIv;
            Span<byte> nonce = stackalloc byte[iv.Length];
            BuildNonce(iv, sequenceNumber, nonce);
            if (!ctx.Protection(fromClient, crypto).Open(nonce, aad, ciphertext, plaintext))
                throw new DtlsRecordAuthenticationException("Record failed authentication");

            window.Mark(sequenceNumber);

            // strip TLSInnerPlaintext zero padding; the last non-zero byte is the content type
            int end = ciphertext.Length - ctx.Suite.TagLength;
            while (end > 0 && plaintext[end - 1] == 0)
                end--;
            if (end == 0)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Record has no content type");
            return end;
        }

        /// <summary>
        /// Decodes the full sequence number of a protected record without decrypting it.
        /// Returns false for malformed headers.
        /// </summary>
        public static bool TryPeekSequenceNumber(Dtls13CryptoContext ctx, bool fromClient, byte[] record, out ulong sequenceNumber, int connectionIdLength = 0)
        {
            return TryReadHeader(ctx, fromClient, record, out _, out _, out sequenceNumber, connectionIdLength, null);
        }

        private static bool TryReadHeader(Dtls13CryptoContext ctx, bool fromClient, ReadOnlySpan<byte> record, out int headerLength, out int seqLength,
            out ulong sequenceNumber, int connectionIdLength, ITlsCrypto crypto)
        {
            headerLength = 0;
            seqLength = 0;
            sequenceNumber = 0;

            if (record.Length < 1 || (record[0] & 0xE0) != 0x20)
                return false;

            bool hasCid    = (record[0] & 0x10) != 0;
            bool seq16     = (record[0] & 0x08) != 0;
            bool hasLength = (record[0] & 0x04) != 0;

            // A CID we did not negotiate makes the record invalid (RFC 9147 §9).
            int cid = hasCid ? connectionIdLength : 0;
            if (hasCid && cid == 0)
                return false;

            seqLength = seq16 ? 2 : 1;
            headerLength = 1 + cid + seqLength + (hasLength ? 2 : 0);

            if (record.Length < headerLength + SampleLength)
                return false;

            if (hasLength)
            {
                int declared = (record[headerLength - 2] << 8) | record[headerLength - 1];
                if (declared != record.Length - headerLength)
                    return false;
            }

            Span<byte> mask = stackalloc byte[2];
            if (!ctx.Protection(fromClient, crypto).Mask(record.Slice(headerLength), mask))
                mask.Clear();

            ulong truncated = seq16
                ? (ulong)(((record[1 + cid] ^ mask[0]) << 8) | (record[2 + cid] ^ mask[1]))
                : (ulong)(record[1 + cid] ^ mask[0]);

            var window = fromClient ? ctx.ClientRecords : ctx.ServerRecords;
            sequenceNumber = window.Reconstruct(truncated, seqLength * 8);
            return true;
        }

        /// <summary>The length of the TLS 1.3 record of <paramref name="contentLength"/> bytes of content.</summary>
        internal static int TlsProtectedLength(Dtls13CryptoContext ctx, int contentLength) => 5 + contentLength + 1 + ctx.Suite.TagLength;

        /// <summary>
        /// A TLS 1.3 record (RFC 8446 §5.2): header opaque_type 23, legacy version 0x0303 and length, which is also the
        /// AAD; the nonce is the IV XOR the implicit 64-bit sequence number.
        /// </summary>
        internal static byte[] ProtectTls(Dtls13CryptoContext ctx, bool fromClient, ulong sequenceNumber, byte[] innerPlaintext, ITlsCrypto crypto = null)
        {
            byte[] record = new byte[TlsProtectedLength(ctx, innerPlaintext.Length - 1)];
            ProtectTls(ctx, fromClient, sequenceNumber, innerPlaintext.AsSpan(0, innerPlaintext.Length - 1), innerPlaintext[innerPlaintext.Length - 1], record, crypto);
            return record;
        }

        /// <summary>Writes the TLS 1.3 record into <paramref name="record"/>, of <see cref="TlsProtectedLength"/> bytes.</summary>
        internal static void ProtectTls(Dtls13CryptoContext ctx, bool fromClient, ulong sequenceNumber, ReadOnlySpan<byte> content, byte contentType,
            Span<byte> record, ITlsCrypto crypto)
        {
            int length = content.Length + 1 + ctx.Suite.TagLength;
            if (length > 16384 + 256)
                throw new DtlsException(AlertDescription.RecordOverflow, "Record too large");
            record[0] = 0x17;
            record[1] = 0x03;
            record[2] = 0x03;
            record[3] = (byte)(length >> 8);
            record[4] = (byte)length;
            var body = record.Slice(5, length);
            content.CopyTo(body);
            body[content.Length] = contentType;
            byte[] iv = fromClient ? ctx.ClientIv : ctx.ServerIv;
            Span<byte> nonce = stackalloc byte[iv.Length];
            BuildNonce(iv, sequenceNumber, nonce);
            ctx.Protection(fromClient, crypto).Seal(nonce, record.Slice(0, 5), body.Slice(0, content.Length + 1), body);
        }

        /// <summary>Opens a TLS 1.3 record; returns TLSInnerPlaintext without its zero padding, or null when authentication fails.</summary>
        internal static byte[] UnprotectTls(Dtls13CryptoContext ctx, bool fromClient, ulong sequenceNumber, byte[] record, ITlsCrypto crypto = null)
        {
            byte[] plaintext = new byte[record.Length];
            int length = UnprotectTls(ctx, fromClient, sequenceNumber, record, plaintext, crypto);
            return length < 0 ? null : plaintext.AsSpan(0, length).ToArray();
        }

        /// <summary>
        /// Opens a TLS 1.3 record into <paramref name="plaintext"/> (of the record's length at least): the length of the
        /// TLSInnerPlaintext without its zero padding, or -1 when authentication fails.
        /// </summary>
        internal static int UnprotectTls(Dtls13CryptoContext ctx, bool fromClient, ulong sequenceNumber, ReadOnlySpan<byte> record, Span<byte> plaintext,
            ITlsCrypto crypto)
        {
            var ciphertext = record.Slice(5);
            if (ciphertext.Length < ctx.Suite.TagLength)
                return -1;
            byte[] iv = fromClient ? ctx.ClientIv : ctx.ServerIv;
            Span<byte> nonce = stackalloc byte[iv.Length];
            BuildNonce(iv, sequenceNumber, nonce);
            if (!ctx.Protection(fromClient, crypto).Open(nonce, record.Slice(0, 5), ciphertext, plaintext))
                return -1;
            int end = ciphertext.Length - ctx.Suite.TagLength;
            while (end > 0 && plaintext[end - 1] == 0)
                end--;
            if (end == 0)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Record without a content type.");
            return end;
        }

        // RFC 8446 §5.3: nonce = iv XOR (64-bit sequence number, left-padded to iv length).
        // RFC 9147 §4: the epoch is not part of the AEAD sequence number in DTLS 1.3.
        internal static byte[] BuildNonce(byte[] iv, ulong sequenceNumber)
        {
            byte[] nonce = new byte[iv.Length];
            BuildNonce(iv, sequenceNumber, nonce);
            return nonce;
        }

        internal static void BuildNonce(byte[] iv, ulong sequenceNumber, Span<byte> nonce)
        {
            iv.CopyTo(nonce);
            for (int i = 0; i < 8; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(sequenceNumber >> (8 * i));
        }
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
            byte[] output = new byte[64];
            Compute(key, counter, nonce, output);
            return output;
        }

        public static void Compute(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce, Span<byte> output)
        {
            Span<uint> state = stackalloc uint[16];
            state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
            for (int i = 0; i < 8; i++)
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            state[12] = counter;
            for (int i = 0; i < 3; i++)
                state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));

            Span<uint> x = stackalloc uint[16];
            state.CopyTo(x);
            for (int i = 0; i < 10; i++)
            {
                QuarterRound(x, 0, 4, 8, 12); QuarterRound(x, 1, 5, 9, 13);
                QuarterRound(x, 2, 6, 10, 14); QuarterRound(x, 3, 7, 11, 15);
                QuarterRound(x, 0, 5, 10, 15); QuarterRound(x, 1, 6, 11, 12);
                QuarterRound(x, 2, 7, 8, 13); QuarterRound(x, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4, 4), x[i] + state[i]);
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
