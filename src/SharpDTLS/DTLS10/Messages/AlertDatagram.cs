using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
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
