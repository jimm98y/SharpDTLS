using System;
using System.Linq;

namespace SharpDTLS.Protocol10.Messages
{
    public class ApplicationDataDatagram : IDatagram
    {
        public byte[] Data  { get; set; }
        public byte[] Bytes { get; private set; }

        public ApplicationDataDatagram() { }
        public ApplicationDataDatagram(byte[] data) { Data = data; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Bytes = bytes.ToArray();
            Data  = bytes;
        }

        public byte[] ToBytes()
        {
            Bytes = Data ?? Array.Empty<byte>();
            return Bytes;
        }
    }
}
