using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    public class ServerHelloDatagram : IDatagram
    {
        public byte[] ServerRandom { get; set; }
        public ushort SelectedCipherSuite { get; set; } = 0xC013; // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        public List<ITlsExtension> Extensions { get; set; } = new List<ITlsExtension>();
        public int    Epoch { get; set; } = 0;
        public int    RecordSequenceNumber  { get; set; }
        public ushort MessageSequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public ServerHelloDatagram() { }

        public ServerHelloDatagram(ushort cipherSuite, byte[] serverRandom, bool includeSrtp = false, ushort srtpProfile = 0x0001)
        {
            SelectedCipherSuite = cipherSuite;
            ServerRandom = serverRandom;
            if (includeSrtp)
                Extensions.Add(new ServerUseSrtpExtension(srtpProfile));
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x02) throw new InvalidDataException("Not a ServerHello.");

            Bytes = bytes.ToArray();
            Epoch = (bytes[3] << 8) | bytes[4];
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            ServerRandom = new byte[32];
            Buffer.BlockCopy(bytes, 27, ServerRandom, 0, 32);

            int sessionIdLen = bytes[59];
            int pos = 60 + sessionIdLen;

            SelectedCipherSuite = (ushort)((bytes[pos] << 8) | bytes[pos + 1]); pos += 2;
            pos += 1; // compression method

            if (pos + 2 > bytes.Length) return;
            int extLen = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2;
            int extEnd = pos + extLen;

            Extensions = new List<ITlsExtension>();
            while (pos < extEnd)
            {
                if (pos + 4 > bytes.Length) break;
                ushort extType    = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                ushort extDataLen = (ushort)((bytes[pos + 2] << 8) | bytes[pos + 3]);

                ITlsExtension ext = extType switch
                {
                    0x000e => new ServerUseSrtpExtension(),
                    0x000b => new ServerEcPointFormatsExtension(),
                    _ => null
                };

                if (ext != null)
                {
                    pos += ext.Read(pos, bytes);
                    Extensions.Add(ext);
                }
                else
                {
                    pos += 4 + extDataLen;
                }
            }
        }

        public byte[] ToBytes()
        {
            int extTotalLen = Extensions.Sum(e => e.CalculateLength());
            byte[] buf = new byte[65 + extTotalLen];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = (byte)((Epoch >> 8) & 0xFF);
            buf[4] = (byte)(Epoch & 0xFF);
            buf[5]  = (byte)((RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)((RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; buf[12] = 0x00;

            buf[13] = 0x02;
            buf[14] = 0x00; buf[15] = 0x00; buf[16] = 0x00;
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = 0x00; buf[23] = 0x00; buf[24] = 0x00;

            buf[25] = 0xFE; buf[26] = 0xFF; // server_version DTLS 1.0
            Buffer.BlockCopy(ServerRandom, 0, buf, 27, 32);
            buf[59] = 0x00; // session_id_length

            buf[60] = (byte)((SelectedCipherSuite >> 8) & 0xFF);
            buf[61] = (byte)(SelectedCipherSuite & 0xFF);
            buf[62] = 0x00; // null compression

            buf[63] = (byte)((extTotalLen >> 8) & 0xFF);
            buf[64] = (byte)(extTotalLen & 0xFF);

            int p = 65;
            foreach (var ext in Extensions) p += ext.Write(p, buf);

            int recordBodyLen = p - 13;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            int hsBodyLen = p - 13 - 4 - 8;
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[22] = buf[14]; buf[23] = buf[15]; buf[24] = buf[16];

            Bytes = buf.Take(p).ToArray();
            return Bytes;
        }
    }
}
