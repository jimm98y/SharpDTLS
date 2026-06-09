using SharpDTLS;
using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    // DTLS 1.0 ClientHello.
    // Uses CBC cipher suites (no AES-GCM) and omits EncryptThenMac / SignatureAlgorithms extensions.
    // Extension classes are shared with DTLS12 (same TLS wire format).
    public class ClientHelloDatagram : IDatagram
    {
        // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        public List<ushort> CipherSuites { get; set; } = new List<ushort> { 0xC013, 0xC014 };
        public List<ITlsExtension> Extensions { get; private set; } = new List<ITlsExtension>();
        public byte[] ClientRandom { get; set; }
        public byte[] Cookie { get; set; } = Array.Empty<byte>();
        public int    Epoch { get; set; } = 0;
        public int    RecordSequenceNumber  { get; set; } = 0;
        public ushort MessageSequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public ClientHelloDatagram() { }

        public ClientHelloDatagram(bool includeSrtp = true)
        {
            ClientRandom = CryptoUtils.GenerateRandom(32);
            Extensions   = new List<ITlsExtension>(GetDefaultExtensions(includeSrtp));
        }

        private static ITlsExtension[] GetDefaultExtensions(bool includeSrtp)
        {
            var list = new List<ITlsExtension>
            {
                new SupportedGroupsExtension(new ushort[] { 0x001d, 0x0017 }), // x25519, secp256r1
                new EcPointFormatsExtension(new byte[] { 0x00 }),               // uncompressed
            };
            if (includeSrtp)
                list.Add(new UseSrtpExtension(new ushort[] { 0x0001, 0x0007 }));
            return list.ToArray();
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 68) throw new ArgumentException("Buffer too small for ClientHello.");
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x01) throw new InvalidDataException("Not a ClientHello.");

            Bytes = bytes.ToArray();
            Epoch = (bytes[3] << 8) | bytes[4];
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            ClientRandom = new byte[32];
            Buffer.BlockCopy(bytes, 27, ClientRandom, 0, 32);

            int sessionIdLen = bytes[59];
            int pos = 60 + sessionIdLen;

            int cookieLen = bytes[pos++];
            Cookie = new byte[cookieLen];
            if (cookieLen > 0)
                Buffer.BlockCopy(bytes, pos, Cookie, 0, cookieLen);
            pos += cookieLen;

            int cipherSuitesLen = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2;
            CipherSuites = new List<ushort>();
            for (int i = 0; i < cipherSuitesLen; i += 2)
                CipherSuites.Add((ushort)((bytes[pos + i] << 8) | bytes[pos + i + 1]));
            pos += cipherSuitesLen;

            int compLen = bytes[pos++]; pos += compLen;

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
                    0x000a => new SupportedGroupsExtension(),
                    0x000b => new EcPointFormatsExtension(),
                    0x000f => new UseSrtpExtension(),
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
            byte[] buf = new byte[2048];

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
            buf[11] = 0x00;
            buf[12] = 0x00;

            buf[13] = 0x01;
            buf[14] = 0x00; buf[15] = 0x00; buf[16] = 0x00;
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = 0x00; buf[23] = 0x00; buf[24] = 0x00;

            buf[25] = 0xFE; buf[26] = 0xFF; // client_version DTLS 1.0
            Buffer.BlockCopy(ClientRandom, 0, buf, 27, 32);

            int p = 59;
            buf[p++] = 0x00; // session_id_length = 0

            buf[p++] = (byte)Cookie.Length;
            if (Cookie.Length > 0) { Buffer.BlockCopy(Cookie, 0, buf, p, Cookie.Length); p += Cookie.Length; }

            int csLen = CipherSuites.Count * 2;
            buf[p++] = (byte)((csLen >> 8) & 0xFF);
            buf[p++] = (byte)(csLen & 0xFF);
            foreach (var cs in CipherSuites) { buf[p++] = (byte)((cs >> 8) & 0xFF); buf[p++] = (byte)(cs & 0xFF); }

            buf[p++] = 0x01; buf[p++] = 0x00; // null compression

            int extTotalLen = Extensions.Sum(e => e.CalculateLength());
            buf[p++] = (byte)((extTotalLen >> 8) & 0xFF);
            buf[p++] = (byte)(extTotalLen & 0xFF);
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
