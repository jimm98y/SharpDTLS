using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol10.Messages
{
    public class AlertDatagram : IDatagram
    {
        public byte Level       { get; set; } = 0x01;
        public byte Description { get; set; } = 0x00;
        public int  Epoch { get; set; } = 0;
        public int  RecordSequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public AlertDatagram() { }
        public AlertDatagram(byte level, byte description) { Level = level; Description = description; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Bytes = bytes.ToArray();

            if (bytes.Length == 2)
            {
                Level       = bytes[0];
                Description = bytes[1];
                return;
            }

            if (bytes[0] != 0x15) throw new InvalidDataException("Not an Alert record.");
            Epoch = (bytes[3] << 8) | bytes[4];
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber = (int)seq;
            Level       = bytes[13];
            Description = bytes[14];
        }

        public byte[] ToBytes()
        {
            byte[] buf = new byte[15];

            buf[0] = 0x15;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = (byte)((Epoch >> 8) & 0xFF);
            buf[4] = (byte)(Epoch & 0xFF);
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; buf[12] = 0x02;
            buf[13] = Level;
            buf[14] = Description;

            Bytes = buf;
            return Bytes;
        }
    }
}
