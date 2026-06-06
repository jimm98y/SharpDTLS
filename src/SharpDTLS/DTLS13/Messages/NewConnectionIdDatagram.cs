using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class NewConnectionIdDatagram : IDatagram
    {
        // Handshake type for NewConnectionID per TLS 1.3 post-handshake messages
        public byte HandshakeType { get; set; } = 0x19;

        public int SequenceNumber { get; set; } = 0;
        public byte[] ConnectionId { get; set; } = new byte[0];
        public byte[] StatelessResetToken { get; set; } = new byte[16];

        public byte[] Bytes { get; private set; }

        public NewConnectionIdDatagram()
        {
        }

        public NewConnectionIdDatagram(byte[] connectionId, byte[] statelessResetToken)
        {
            ConnectionId = connectionId ?? new byte[0];
            if (statelessResetToken != null && statelessResetToken.Length == 16)
                StatelessResetToken = statelessResetToken;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 1 + 16 + 2) throw new ArgumentException("Buffer too small to be a valid NewConnectionId.");

            Bytes = bytes.ToArray();

            if (bytes[0] != HandshakeType) throw new InvalidDataException("Not a NewConnectionId handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12; // payload start

            // connection id length
            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before connection id length.");
            int cidLen = bytes[pos++];
            if (bytes.Length < pos + cidLen) throw new ArgumentException("Buffer truncated in connection id field.");
            ConnectionId = new byte[cidLen];
            if (cidLen > 0) Buffer.BlockCopy(bytes, pos, ConnectionId, 0, cidLen);
            pos += cidLen;

            // stateless reset token (16 bytes)
            if (bytes.Length < pos + 16) throw new ArgumentException("Buffer truncated before stateless reset token.");
            StatelessResetToken = new byte[16];
            Buffer.BlockCopy(bytes, pos, StatelessResetToken, 0, 16);
            pos += 16;

            // extensions length (2 bytes)
            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before extensions length.");
            int extensionsLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (bytes.Length < pos + extensionsLength) throw new ArgumentException("Buffer truncated in extensions area.");

            // skip extensions for now
            pos += extensionsLength;

            // length check optional
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[512];

            data[0] = HandshakeType;

            // placeholder for length
            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            // fragment offset + length placeholders
            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            int cidLen = ConnectionId?.Length ?? 0;
            data[pos++] = (byte)cidLen;
            if (cidLen > 0)
            {
                Buffer.BlockCopy(ConnectionId, 0, data, pos, cidLen);
                pos += cidLen;
            }

            // stateless reset token
            if (StatelessResetToken == null || StatelessResetToken.Length != 16)
                StatelessResetToken = new byte[16];
            Buffer.BlockCopy(StatelessResetToken, 0, data, pos, 16);
            pos += 16;

            // extensions length = 0
            int extensionsLength = 0;
            data[pos++] = (byte)((extensionsLength >> 8) & 0xFF);
            data[pos++] = (byte)(extensionsLength & 0xFF);

            // trailing record type for parity
            data[pos++] = 0x16;

            // fill in length fields
            length = pos - 13;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            int fragmentOffset = 0;
            data[6] = (byte)((fragmentOffset >> 16) & 0xFF);
            data[7] = (byte)((fragmentOffset >> 8) & 0xFF);
            data[8] = (byte)(fragmentOffset & 0xFF);

            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
