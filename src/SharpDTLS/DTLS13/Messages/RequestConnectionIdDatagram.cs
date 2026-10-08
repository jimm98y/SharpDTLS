using System;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class RequestConnectionIdDatagram : IHandshakeDatagram
    {
        // Handshake type byte left configurable in case protocol mapping differs. Default to 0x18.
        public byte HandshakeType { get; set; } = 0x18;

        public int SequenceNumber { get; set; } = 0;

        // Requested Connection ID (optional payload for the request)
        public byte[] ConnectionId { get; set; } = new byte[0];

        public byte[] Bytes { get; private set; }

        public RequestConnectionIdDatagram()
        {
        }

        public RequestConnectionIdDatagram(byte[] connectionId)
        {
            ConnectionId = connectionId ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 1) throw new ArgumentException("Buffer too small to be a RequestConnectionIdDatagram.");

            Bytes = bytes.ToArray();

            // optional: validate handshake type if set
            if (bytes[0] != HandshakeType)
            {
                // don't throw; some inputs may omit or use different type mapping
            }

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            // skip fragment offset/length bytes[6..11]
            int pos = 12;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before connection id length.");
            int cidLen = bytes[pos++];
            if (bytes.Length < pos + cidLen) throw new ArgumentException("Buffer truncated in connection id field.");
            ConnectionId = new byte[cidLen];
            if (cidLen > 0) Buffer.BlockCopy(bytes, pos, ConnectionId, 0, cidLen);
            pos += cidLen;

            // extensions length (2 bytes) may follow
            if (bytes.Length >= pos + 2)
            {
                int extLen = (bytes[pos] << 8) | bytes[pos + 1];
                pos += 2;
                if (bytes.Length < pos + extLen) throw new ArgumentException("Buffer truncated in extensions area.");
                // skip for now
                pos += extLen;
            }

            // tolerant; do not require exact matching of length fields
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[512];

            data[0] = HandshakeType; // handshake message type (user-configurable)

            // placeholder for 3-byte length
            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            // handshake reconstruction data
            data[4] = (byte)((this.SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(this.SequenceNumber & 0xFF);

            // fragment offset (3 bytes) and fragment length (3 bytes) - placeholders
            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            // connection id length + connection id
            int cidLen = this.ConnectionId?.Length ?? 0;
            data[pos++] = (byte)cidLen;
            if (cidLen > 0)
            {
                Buffer.BlockCopy(this.ConnectionId, 0, data, pos, cidLen);
                pos += cidLen;
            }

            // extensions length (2 bytes) - none for now
            int extensionsLength = 0;
            data[pos++] = (byte)((extensionsLength >> 8) & 0xFF);
            data[pos++] = (byte)(extensionsLength & 0xFF);

            // record type (for parity with other datagrams)
            data[pos++] = 0x16;

            // fill in lengths
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
