using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    // DTLS 1.2 HelloVerifyRequest — sends a cookie to the client before the real handshake.
    // RFC 6347 Section 4.2.1
    public class HelloVerifyRequestDatagram : IDatagram
    {
        public byte[] Cookie { get; set; }
        public int RecordSequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public HelloVerifyRequestDatagram() { }

        public HelloVerifyRequestDatagram(byte[] cookie)
        {
            Cookie = cookie ?? throw new ArgumentNullException(nameof(cookie));
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x03) throw new InvalidDataException("Not a HelloVerifyRequest.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber = (int)seq;

            // body starts at offset 25: server_version(2) + cookie_length(1) + cookie
            byte cookieLen = bytes[27];
            Cookie = new byte[cookieLen];
            if (cookieLen > 0)
                Buffer.BlockCopy(bytes, 28, Cookie, 0, cookieLen);
        }

        public byte[] ToBytes()
        {
            int hsBodyLen = 2 + 1 + Cookie.Length; // server_version + cookie_length + cookie
            byte[] buf = new byte[13 + 12 + hsBodyLen];

            // DTLS record header
            buf[0] = 0x16;
            buf[1] = 0xFE;
            buf[2] = 0xFD;
            buf[3] = 0x00; buf[4] = 0x00; // epoch 0
            buf[5]  = (byte)((RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)((RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            int recordBodyLen = 12 + hsBodyLen;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            // Handshake header
            buf[13] = 0x03; // HelloVerifyRequest
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[17] = 0x00; buf[18] = 0x00; // msg_seq = 0
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00; // frag_offset
            buf[22] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[23] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[24] = (byte)(hsBodyLen & 0xFF);

            // Body
            buf[25] = 0xFE; buf[26] = 0xFD; // server_version
            buf[27] = (byte)Cookie.Length;
            if (Cookie.Length > 0)
                Buffer.BlockCopy(Cookie, 0, buf, 28, Cookie.Length);

            Bytes = buf;
            return Bytes;
        }
    }
}
