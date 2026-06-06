using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    public class FinishedDatagram : IDatagram
    {
        public byte[] VerifyData { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public FinishedDatagram()
        {
        }

        public FinishedDatagram(byte[] verifyData)
        {
            VerifyData = verifyData ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 13) throw new ArgumentException("Buffer too small for Finished.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x14) throw new InvalidDataException("Not a Finished handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;
            if (bytes.Length > pos && length > 0)
            {
                VerifyData = new byte[length];
                Buffer.BlockCopy(bytes, pos, VerifyData, 0, Math.Min(length, bytes.Length - pos));
            }
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[512];

            data[0] = 0x14; // Finished

            int verifyLen = VerifyData?.Length ?? 0;
            int length = verifyLen;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            if (verifyLen > 0)
            {
                Buffer.BlockCopy(VerifyData, 0, data, pos, verifyLen);
                pos += verifyLen;
            }

            // record type
            data[pos++] = 0x16;

            // update fragment length
            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }

    public class AlertDatagram : IDatagram
    {
        public byte AlertLevel { get; set; } = 0x02; // fatal
        public byte AlertDescription { get; set; } = 0x00; // close_notify
        public byte[] Bytes { get; private set; }

        public AlertDatagram()
        {
        }

        public AlertDatagram(byte level, byte description)
        {
            AlertLevel = level;
            AlertDescription = description;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 7) throw new ArgumentException("Buffer too small for Alert.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x15) throw new InvalidDataException("Not an Alert record.");

            int length = (bytes[1] << 8) | bytes[2];
            if (length != 2) throw new InvalidDataException("Alert should be 2 bytes.");

            AlertLevel = bytes[3];
            AlertDescription = bytes[4];
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[64];

            data[0] = 0x15; // Alert record type
            data[1] = 0x00; // Length high byte
            data[2] = 0x02; // Length low byte (2 bytes)

            data[3] = AlertLevel;
            data[4] = AlertDescription;

            Bytes = data.Take(5).ToArray();
            return Bytes;
        }
    }
}
