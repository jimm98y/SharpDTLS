using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    public class ClientKeyExchangeDatagram : IDatagram
    {
        public ushort MessageSequenceNumber { get; set; } = 2;
        public int    RecordSequenceNumber  { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] Bytes { get; private set; }

        public ClientKeyExchangeDatagram() { }
        public ClientKeyExchangeDatagram(byte[] publicKey) { PublicKey = publicKey; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x10) throw new InvalidDataException("Not a ClientKeyExchange.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            byte pkLen = bytes[25];
            PublicKey = new byte[pkLen];
            Buffer.BlockCopy(bytes, 26, PublicKey, 0, pkLen);
        }

        public byte[] ToBytes()
        {
            int hsBodyLen = 1 + PublicKey.Length;
            byte[] buf = new byte[13 + 12 + hsBodyLen];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = 0x00; buf[4] = 0x00;
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            int recordBodyLen = 12 + hsBodyLen;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            buf[13] = 0x10;
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[23] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[24] = (byte)(hsBodyLen & 0xFF);

            buf[25] = (byte)PublicKey.Length;
            Buffer.BlockCopy(PublicKey, 0, buf, 26, PublicKey.Length);

            Bytes = buf.Take(13 + 12 + hsBodyLen).ToArray();
            return Bytes;
        }
    }
}
