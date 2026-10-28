using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol10.Messages
{
    public class ServerCertificateDatagram : IDatagram
    {
        public ushort MessageSequenceNumber { get; set; } = 2;
        public byte[] Certificate { get; set; }
        public int    RecordSequenceNumber  { get; set; }
        public byte[] Bytes { get; private set; }

        public ServerCertificateDatagram() { }
        public ServerCertificateDatagram(byte[] certificate) { Certificate = certificate; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x0B) throw new InvalidDataException("Not a Certificate message.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            int certLen = (bytes[28] << 16) | (bytes[29] << 8) | bytes[30];
            Certificate = new byte[certLen];
            Buffer.BlockCopy(bytes, 31, Certificate, 0, certLen);
        }

        public byte[] ToBytes()
        {
            int certLen     = Certificate.Length;
            int certListLen = 3 + certLen;
            int hsBodyLen   = 3 + certListLen;

            byte[] buf = new byte[2048];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = 0x00; buf[4] = 0x00;
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; buf[12] = 0x00;

            buf[13] = 0x0B;
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[23] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[24] = (byte)(hsBodyLen & 0xFF);

            buf[25] = (byte)((certListLen >> 16) & 0xFF);
            buf[26] = (byte)((certListLen >> 8) & 0xFF);
            buf[27] = (byte)(certListLen & 0xFF);
            buf[28] = (byte)((certLen >> 16) & 0xFF);
            buf[29] = (byte)((certLen >> 8) & 0xFF);
            buf[30] = (byte)(certLen & 0xFF);
            Buffer.BlockCopy(Certificate, 0, buf, 31, certLen);

            int total = 31 + certLen;
            int recordBodyLen = total - 13;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            Bytes = buf.Take(total).ToArray();
            return Bytes;
        }
    }
}
