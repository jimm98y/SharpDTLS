using System;
using System.IO;
using System.Linq;

namespace Dtls13Test.Messages
{
    public class AckDatagram : IDatagram
    {
        public long RecordEpoch { get; set; } = 2;
        public long RecordNumber { get; set; } = 0;

        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes)); if (bytes.Length < 19) throw new ArgumentException("Buffer too small for AckDatagram.");
            int length = (bytes[0] << 8) | bytes[1];
            if (length != 16) throw new InvalidDataException($"Unexpected payload length: {length}");

            this.Bytes = bytes.ToArray();

            this.RecordEpoch = 
                (((long)bytes[2] << 56) |
                ((long)bytes[3] << 48) |
                ((long)bytes[4] << 40) |
                ((long)bytes[5] << 32) |
                ((long)bytes[6] << 24) |
                ((long)bytes[7] << 16) |
                ((long)bytes[8] << 8) |
                (long)bytes[9]);

            this.RecordNumber =
                (((long)bytes[10] << 56) |
                ((long)bytes[11] << 48) |
                ((long)bytes[12] << 40) |
                ((long)bytes[13] << 32) |
                ((long)bytes[14] << 24) |
                ((long)bytes[15] << 16) |
                ((long)bytes[16] << 8) |
                (long)bytes[17]);

            if (bytes[18] != 0x1a) throw new InvalidDataException("Unexpected record type (expected 0x1a).");
        }


        public byte[] ToBytes()
        {
            byte[] data = new byte[19];

            int length = 16;
            data[0] = (byte)((length >> 8) & 0xFF);
            data[1] = (byte)(length & 0xFF);

            data[2] = (byte)((this.RecordEpoch >> 56) & 0xFF);
            data[3] = (byte)((this.RecordEpoch >> 48) & 0xFF);
            data[4] = (byte)((this.RecordEpoch >> 40) & 0xFF);
            data[5] = (byte)((this.RecordEpoch >> 32) & 0xFF);
            data[6] = (byte)((this.RecordEpoch >> 24) & 0xFF);
            data[7] = (byte)((this.RecordEpoch >> 16) & 0xFF);
            data[8] = (byte)((this.RecordEpoch >> 8) & 0xFF);
            data[9] = (byte)(this.RecordEpoch & 0xFF);

            data[10] = (byte)((this.RecordNumber >> 56) & 0xFF);
            data[11] = (byte)((this.RecordNumber >> 48) & 0xFF);
            data[12] = (byte)((this.RecordNumber >> 40) & 0xFF);
            data[13] = (byte)((this.RecordNumber >> 32) & 0xFF);
            data[14] = (byte)((this.RecordNumber >> 24) & 0xFF);
            data[15] = (byte)((this.RecordNumber >> 16) & 0xFF);
            data[16] = (byte)((this.RecordNumber >> 8) & 0xFF);
            data[17] = (byte)(this.RecordNumber & 0xFF);

            data[18] = 0x1a; // ACK record

            this.Bytes = data;

            return data;
        }
    }
}
