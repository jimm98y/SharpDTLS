using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13
{
    public class FinishedDatagram : IDatagram
    {
        public int SequenceNumber { get; set; } = 4;
        public byte[] VerifyData { get; set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small to be a valid ServerExtensions message.");
            if (bytes[0] != 0x14) throw new InvalidDataException("Not an EncryptedExtensions handshake message.");

            Bytes = bytes.ToArray();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

            this.SequenceNumber = (bytes[4] << 8) | bytes[5];

            int fragmentOffset = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8];
            int fragmentLength = (bytes[9] << 16) | (bytes[10] << 8) | bytes[11];

            this.VerifyData = new byte[length];
            Buffer.BlockCopy(bytes, 12, this.VerifyData, 0, length);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x14; // handshake message type (finished)

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            // handshake reconstruction data
            data[4] = (byte)((this.SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(this.SequenceNumber & 0xFF);
            int fragmentOffset = 0;
            data[6] = 0;
            data[7] = 0;
            data[8] = 0;
            int fragmentLength = 0;
            data[9] = 0;
            data[10] = 0;
            data[11] = 0;

            Buffer.BlockCopy(this.VerifyData, 0, data, 12, this.VerifyData.Length);
            length = 12 + this.VerifyData.Length;

            // (handshake record)
            data[length] = 0x16;
            length += 1;

            // fill in lengths
            length = length - 13;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            fragmentOffset = 0;
            data[6] = (byte)((fragmentOffset >> 16) & 0xFF);
            data[7] = (byte)((fragmentOffset >> 8) & 0xFF);
            data[8] = (byte)(fragmentOffset & 0xFF);

            fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(13 + length).ToArray();

            return Bytes;
        }
    }
}
