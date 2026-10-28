using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol12.Messages
{
    // DTLS 1.2 Alert record (unencrypted during handshake, encrypted after CCS).
    // Sent as a full DTLS record: type(1)+version(2)+epoch(2)+seq(6)+length(2)+alert_level(1)+alert_desc(1)
    public class AlertDatagram : IDatagram
    {
        public byte Level       { get; set; } = 0x01; // 1=warning, 2=fatal
        public byte Description { get; set; } = 0x00; // 0=close_notify

        public int Epoch { get; set; } = 0;
        public int RecordSequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public AlertDatagram() { }

        public AlertDatagram(byte level, byte description)
        {
            Level       = level;
            Description = description;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Bytes = bytes.ToArray();

            // Decrypted alert plaintext is just [level, description] (2 bytes).
            // Unencrypted on-wire records start with content type 0x15 and have a 13-byte DTLS header.
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

            buf[0] = 0x15; // Alert
            buf[1] = 0xFE; buf[2] = 0xFD;
            buf[3] = (byte)((Epoch >> 8) & 0xFF);
            buf[4] = (byte)(Epoch & 0xFF);
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; buf[12] = 0x02; // length = 2
            buf[13] = Level;
            buf[14] = Description;

            Bytes = buf;
            return Bytes;
        }
    }
}
