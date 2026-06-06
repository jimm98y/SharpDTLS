using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10
{
    public class HelloVerifyDatagram : IDatagram
    {
        public byte[] Cookie { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public HelloVerifyDatagram()
        {
        }

        public HelloVerifyDatagram(byte[] cookie)
        {
            Cookie = cookie ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small for HelloVerify.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x03) throw new InvalidDataException("Not a HelloVerify handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            // Skip version (2 bytes)
            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before version.");
            pos += 2;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before cookie length.");
            int cookieLen = bytes[pos++];

            if (bytes.Length < pos + cookieLen) throw new ArgumentException("Buffer truncated for cookie.");
            Cookie = new byte[cookieLen];
            if (cookieLen > 0) Buffer.BlockCopy(bytes, pos, Cookie, 0, cookieLen);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[512];

            data[0] = 0x03; // HelloVerify

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            // Version (DTLS 1.0: 0xFF 0xFE)
            data[pos++] = 0xFF;
            data[pos++] = 0xFE;

            int cookieLen = Cookie?.Length ?? 0;
            data[pos++] = (byte)cookieLen;

            if (cookieLen > 0)
            {
                Buffer.BlockCopy(Cookie, 0, data, pos, cookieLen);
                pos += cookieLen;
            }

            // record type
            data[pos++] = 0x16;

            // fill in length
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
