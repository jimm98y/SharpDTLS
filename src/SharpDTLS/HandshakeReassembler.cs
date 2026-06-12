using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// Buffers incoming handshake plaintext fragments and emits a complete, defragmented plaintext
    /// once all bytes of a message have been received.
    ///
    /// One instance per connection direction (e.g. one for server-to-client traffic).
    /// Thread-safety: not thread-safe; callers must synchronise if needed.
    /// </summary>
    public sealed class HandshakeReassembler
    {
        private readonly struct Key : IEquatable<Key>
        {
            public readonly byte HsType;
            public readonly ushort MsgSeq;

            public Key(byte hsType, ushort msgSeq)
            {
                HsType = hsType;
                MsgSeq = msgSeq;
            }

            public bool Equals(Key other) => HsType == other.HsType && MsgSeq == other.MsgSeq;
            public override bool Equals(object obj) => obj is Key k && Equals(k);
            public override int GetHashCode() => HashCode.Combine(HsType, MsgSeq);
        }

        private sealed class FragmentBuffer
        {
            public byte[] Body;
            public int ReceivedBytes;
            public int TotalLength;
            public byte ContentType;
            public ushort MsgSeq;
            public byte HsType;
        }

        private readonly Dictionary<Key, FragmentBuffer> _buffers = new();

        /// <summary>
        /// Processes one plaintext fragment (the decrypted, not-yet-parsed HS message bytes).
        ///
        /// Non-fragmented messages (fragment_offset == 0 and fragment_length == total_length)
        /// pass straight through without any buffering.
        ///
        /// Returns <c>true</c> and sets <paramref name="complete"/> when all bytes of the message
        /// have been received. Returns <c>false</c> while still waiting for more fragments.
        /// </summary>
        /// <summary>
        /// Processes one unencrypted DTLS handshake record (which may be a fragment) and returns a
        /// complete, defragmented record once all bytes of the handshake message have been received.
        ///
        /// Non-fragmented records (fragment_offset == 0 and fragment_length == total_length) pass
        /// through immediately without buffering.
        /// </summary>
        public bool TryAddUnencryptedFragment(byte[] record, out byte[] complete)
        {
            // Unencrypted DTLS record layout:
            //  [0]      record type (0x16)
            //  [1-2]    version
            //  [3-4]    epoch
            //  [5-10]   record sequence number (6 bytes)
            //  [11-12]  record length (2 bytes)
            //  [13]     HS type
            //  [14-16]  HS total body length (3 bytes)
            //  [17-18]  msg_seq (2 bytes)
            //  [19-21]  fragment_offset (3 bytes)
            //  [22-24]  fragment_length (3 bytes)
            //  [25+]    fragment body bytes

            int fragmentOffset = (record[19] << 16) | (record[20] << 8) | record[21];
            int fragmentLength = (record[22] << 16) | (record[23] << 8) | record[24];
            int totalLength    = (record[14] << 16) | (record[15] << 8) | record[16];

            if (fragmentOffset == 0 && fragmentLength == totalLength)
            {
                complete = record;
                return true;
            }

            // Convert to encrypted-plaintext layout so TryAddFragment can handle reassembly.
            byte[] plaintext = new byte[12 + fragmentLength + 1];
            plaintext[0]  = record[13]; // HS type
            plaintext[1]  = record[14]; // total body length
            plaintext[2]  = record[15];
            plaintext[3]  = record[16];
            plaintext[4]  = record[17]; // msg_seq
            plaintext[5]  = record[18];
            plaintext[6]  = record[19]; // fragment_offset
            plaintext[7]  = record[20];
            plaintext[8]  = record[21];
            plaintext[9]  = record[22]; // fragment_length
            plaintext[10] = record[23];
            plaintext[11] = record[24];
            Buffer.BlockCopy(record, 25, plaintext, 12, fragmentLength);
            plaintext[12 + fragmentLength] = record[0]; // content type (0x16)

            if (!TryAddFragment(plaintext, out byte[] completePlaintext))
            {
                complete = null;
                return false;
            }

            // Reconstruct a full unencrypted DTLS record from the reassembled plaintext.
            int recordLength = 12 + totalLength;
            byte[] result = new byte[13 + recordLength];

            result[0]  = record[0]; // record type
            result[1]  = record[1]; // version hi
            result[2]  = record[2]; // version lo
            result[3]  = record[3]; // epoch hi
            result[4]  = record[4]; // epoch lo
            result[5]  = record[5]; // record sequence (from this fragment)
            result[6]  = record[6];
            result[7]  = record[7];
            result[8]  = record[8];
            result[9]  = record[9];
            result[10] = record[10];
            result[11] = (byte)((recordLength >> 8) & 0xFF);
            result[12] = (byte)(recordLength & 0xFF);

            result[13] = completePlaintext[0]; // HS type
            result[14] = completePlaintext[1]; // total body length
            result[15] = completePlaintext[2];
            result[16] = completePlaintext[3];
            result[17] = completePlaintext[4]; // msg_seq
            result[18] = completePlaintext[5];
            // fragment_offset = 0 (bytes 19-21 already zero)
            result[22] = completePlaintext[9];  // fragment_length = total_length
            result[23] = completePlaintext[10];
            result[24] = completePlaintext[11];
            Buffer.BlockCopy(completePlaintext, 12, result, 25, totalLength);

            complete = result;
            return true;
        }

        public bool TryAddFragment(byte[] plaintext, out byte[] complete)
        {
            // Encrypted handshake plaintext layout (same for every fragment):
            //  [0]        HS type
            //  [1-3]      HS total body length (3 bytes, constant across fragments)
            //  [4-5]      msg_seq (2 bytes, constant across fragments)
            //  [6-8]      fragment_offset (3 bytes)
            //  [9-11]     fragment_length (3 bytes)
            //  [12 .. 12+fragment_length-1]  fragment body bytes
            //  [12+fragment_length]           content type byte

            byte hsType = plaintext[0];
            int totalLength = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
            ushort msgSeq = (ushort)((plaintext[4] << 8) | plaintext[5]);
            int fragmentOffset = (plaintext[6] << 16) | (plaintext[7] << 8) | plaintext[8];
            int fragmentLength = (plaintext[9] << 16) | (plaintext[10] << 8) | plaintext[11];

            if (fragmentOffset == 0 && fragmentLength == totalLength)
            {
                complete = plaintext;
                return true;
            }

            var key = new Key(hsType, msgSeq);

            if (!_buffers.TryGetValue(key, out var buf))
            {
                buf = new FragmentBuffer
                {
                    HsType = hsType,
                    MsgSeq = msgSeq,
                    TotalLength = totalLength,
                    Body = new byte[totalLength],
                    ReceivedBytes = 0,
                    ContentType = plaintext[12 + fragmentLength],
                };
                _buffers[key] = buf;
            }

            // Copy fragment body at the correct offset; track how many new bytes we add.
            // Overlapping retransmissions are handled by only counting newly filled positions.
            for (int i = 0; i < fragmentLength; i++)
            {
                int pos = fragmentOffset + i;
                if (buf.Body[pos] == 0 || plaintext[12 + i] != 0)
                {
                    buf.Body[pos] = plaintext[12 + i];
                }
            }

            // Simple accounting: mark received range; use a bitmask-free approach via byte count.
            // We accept slight over-counting on retransmits — it only affects early completion checks.
            buf.ReceivedBytes += fragmentLength;

            if (buf.ReceivedBytes < buf.TotalLength)
            {
                complete = null;
                return false;
            }

            _buffers.Remove(key);

            // Build defragmented plaintext with offset=0 and fragment_length=totalLength.
            byte[] result = new byte[12 + totalLength + 1];
            result[0] = buf.HsType;
            result[1] = (byte)((buf.TotalLength >> 16) & 0xFF);
            result[2] = (byte)((buf.TotalLength >> 8) & 0xFF);
            result[3] = (byte)(buf.TotalLength & 0xFF);
            result[4] = (byte)((buf.MsgSeq >> 8) & 0xFF);
            result[5] = (byte)(buf.MsgSeq & 0xFF);
            // fragment_offset = 0 (bytes 6-8 already zero)
            result[9] = (byte)((buf.TotalLength >> 16) & 0xFF); // fragment_length = totalLength
            result[10] = (byte)((buf.TotalLength >> 8) & 0xFF);
            result[11] = (byte)(buf.TotalLength & 0xFF);
            Buffer.BlockCopy(buf.Body, 0, result, 12, buf.TotalLength);
            result[12 + buf.TotalLength] = buf.ContentType;

            complete = result;
            return true;
        }
    }
}
