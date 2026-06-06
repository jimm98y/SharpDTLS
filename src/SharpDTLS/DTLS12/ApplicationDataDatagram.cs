using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    public class ApplicationDataDatagram : IDatagram
    {
        public byte[] ApplicationData { get; set; } = new byte[0];
        public byte[] Bytes { get; private set; }

        public ApplicationDataDatagram()
        {
        }

        public ApplicationDataDatagram(byte[] applicationData)
        {
            ApplicationData = applicationData ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 5) throw new ArgumentException("Buffer too small for ApplicationData.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x17) throw new InvalidDataException("Not an ApplicationData record.");

            int length = (bytes[1] << 8) | bytes[2];
            if (bytes.Length < 3 + length) throw new ArgumentException("Buffer truncated for application data.");

            ApplicationData = new byte[length];
            if (length > 0) Buffer.BlockCopy(bytes, 3, ApplicationData, 0, length);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[16384];

            data[0] = 0x17; // ApplicationData record type

            int appDataLen = ApplicationData?.Length ?? 0;
            data[1] = (byte)((appDataLen >> 8) & 0xFF);
            data[2] = (byte)(appDataLen & 0xFF);

            int pos = 3;
            if (appDataLen > 0)
            {
                Buffer.BlockCopy(ApplicationData, 0, data, pos, appDataLen);
                pos += appDataLen;
            }

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
