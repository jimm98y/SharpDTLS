using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol10.Messages
{
    public class ServerHelloDoneDatagram : IDatagram
    {
        public ushort MessageSequenceNumber { get; set; } = 4;
        public int    RecordSequenceNumber  { get; set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x0E) throw new InvalidDataException("Not a ServerHelloDone.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);
        }

        public byte[] ToBytes()
        {
            byte[] buf = new byte[13 + 12];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = 0x00; buf[4] = 0x00;
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; buf[12] = 0x0C;

            buf[13] = 0x0E;
            buf[14] = 0x00; buf[15] = 0x00; buf[16] = 0x00;
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = 0x00; buf[23] = 0x00; buf[24] = 0x00;

            Bytes = buf;
            return Bytes;
        }
    }
}
