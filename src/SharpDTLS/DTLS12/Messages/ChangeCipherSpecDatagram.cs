using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    public class ChangeCipherSpecDatagram : IDatagram
    {
        public ushort Epoch { get; set; } = 0;
        public ulong SequenceNumber { get; set; } = 0;
        public byte CipherSpecType { get; set; } = 0x01; // change_cipher_spec
        public byte[] Bytes { get; private set; }

        public ChangeCipherSpecDatagram()
        {
        }

        public ChangeCipherSpecDatagram(byte cipherSpecType, ushort epoch = 0, ulong sequenceNumber = 0)
        {
            CipherSpecType = cipherSpecType;
            Epoch = epoch;
            SequenceNumber = sequenceNumber;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small for ChangeCipherSpec.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x14) throw new InvalidDataException("Not a ChangeCipherSpec record.");

            // Version (skip bytes[1] and bytes[2])
            // Epoch (2 bytes)
            Epoch = (ushort)((bytes[3] << 8) | bytes[4]);

            // Sequence number (6 bytes)
            SequenceNumber = ((ulong)bytes[5] << 40) | ((ulong)bytes[6] << 32) | ((ulong)bytes[7] << 24) |
                            ((ulong)bytes[8] << 16) | ((ulong)bytes[9] << 8) | bytes[10];

            // Length (2 bytes)
            int length = (bytes[11] << 8) | bytes[12];
            if (length != 1) throw new InvalidDataException("ChangeCipherSpec payload should be 1 byte.");

            CipherSpecType = bytes[13];
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[64];

            int pos = 0;
            data[pos++] = 0x14; // ChangeCipherSpec record type

            // Version (DTLS 1.2: 0xFE 0xFD)
            data[pos++] = 0xFE;
            data[pos++] = 0xFD;

            // Epoch (2 bytes)
            data[pos++] = (byte)((Epoch >> 8) & 0xFF);
            data[pos++] = (byte)(Epoch & 0xFF);

            // Sequence number (6 bytes)
            data[pos++] = (byte)((SequenceNumber >> 40) & 0xFF);
            data[pos++] = (byte)((SequenceNumber >> 32) & 0xFF);
            data[pos++] = (byte)((SequenceNumber >> 24) & 0xFF);
            data[pos++] = (byte)((SequenceNumber >> 16) & 0xFF);
            data[pos++] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[pos++] = (byte)(SequenceNumber & 0xFF);

            // Length (2 bytes)
            data[pos++] = 0x00;
            data[pos++] = 0x01; // 1 byte payload

            // Payload
            data[pos++] = CipherSpecType;

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
