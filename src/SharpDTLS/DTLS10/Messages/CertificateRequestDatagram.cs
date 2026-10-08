using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    // DTLS 1.0 CertificateRequest (RFC 4346 §7.4.4).
    // Body: certificate_types (1-byte count + bytes) + distinguished_names (2-byte length + data).
    public class CertificateRequestDatagram : IDatagram
    {
        public int    RecordSequenceNumber  { get; set; }
        public ushort MessageSequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x0D) throw new InvalidDataException("Not a CertificateRequest message.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);
        }

        public byte[] ToBytes()
        {
            // Body: cert_types_count(1) + rsa_sign(1) + ecdsa_sign(1) + dn_list_length(2)
            byte[] body = { 0x02, 0x01, 0x40, 0x00, 0x00 };
            int bodyLen = body.Length;
            int total   = 13 + 12 + bodyLen;
            byte[] buf  = new byte[total];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFF;
            buf[3] = 0x00; buf[4] = 0x00;
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8)  & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            int recordBodyLen = 12 + bodyLen;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            buf[13] = 0x0D;
            buf[14] = (byte)((bodyLen >> 16) & 0xFF);
            buf[15] = (byte)((bodyLen >> 8) & 0xFF);
            buf[16] = (byte)(bodyLen & 0xFF);
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0; buf[20] = 0; buf[21] = 0;
            buf[22] = (byte)((bodyLen >> 16) & 0xFF);
            buf[23] = (byte)((bodyLen >> 8) & 0xFF);
            buf[24] = (byte)(bodyLen & 0xFF);

            Buffer.BlockCopy(body, 0, buf, 25, bodyLen);

            Bytes = buf;
            return Bytes;
        }
    }
}
