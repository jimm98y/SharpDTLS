using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10.Messages
{
    public class ServerHelloDoneDatagram : IDatagram
    {
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 13) throw new ArgumentException("Buffer too small for ServerHelloDone.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x0e) throw new InvalidDataException("Not a ServerHelloDone handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            if (length != 0) throw new InvalidDataException("ServerHelloDone should have zero-length payload.");
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[64];

            data[0] = 0x0e; // ServerHelloDone
            data[1] = 0x00; // length = 0
            data[2] = 0x00;
            data[3] = 0x00;

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            // record type
            data[12] = 0x16;

            Bytes = data.Take(13).ToArray();
            return Bytes;
        }
    }
}
