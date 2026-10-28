using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol12.Messages
{
    // DTLS 1.2 application data payload (used as the inner datagram inside encrypted records).
    // ToBytes / FromBytes operate on the raw payload only — no record header.
    internal class ApplicationDataDatagram : IDatagram
    {
        public byte[] Data { get; set; }
        public byte[] Bytes { get; private set; }

        public ApplicationDataDatagram() { }

        public ApplicationDataDatagram(byte[] data)
        {
            Data = data;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Bytes = bytes.ToArray();
            Data = bytes;
        }

        public byte[] ToBytes()
        {
            Bytes = Data ?? Array.Empty<byte>();
            return Bytes;
        }
    }
}
