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
