using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class ApplicationDataDatagram : IDatagram
    {
        public byte[] Bytes { get; private set; }
        public byte[] Data { get; set; }

        public ApplicationDataDatagram()
        { }

        public ApplicationDataDatagram(byte[] data)
        {
            this.Data = data;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes)); 

            this.Bytes = bytes.ToArray();
            if (bytes[bytes.Length - 1] != 0x17) throw new InvalidDataException("Unexpected record type (expected 0x17).");

            this.Data = bytes.Take(bytes.Length - 1).ToArray();
        }


        public byte[] ToBytes()
        {
            byte[] data = new byte[this.Data.Length + 1];
            Buffer.BlockCopy(this.Data, 0, data, 0, this.Data.Length);
            data[this.Data.Length] = 0x17; // application data
            this.Bytes = data;
            return data;
        }
    }
}
