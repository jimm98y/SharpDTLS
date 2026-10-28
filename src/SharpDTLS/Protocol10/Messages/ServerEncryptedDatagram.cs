using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using SharpDTLS.Protocol13;
using System;
using System.Linq;

namespace SharpDTLS.Protocol10.Messages
{
    // Wraps a server-sent DTLS 1.0 record encrypted with AES-128-CBC + HMAC-SHA1 (MAC-then-Encrypt).
    //
    // Wire format:
    //   DTLS record header (13 bytes): type | version(2) | epoch(2) | seq(6) | length(2)
    //   IV (16 bytes): random explicit IV (TLS 1.1 style)
    //   Ciphertext: AES-128-CBC( fragment || HMAC-SHA1 || TLS-padding )
    //
    // MAC = HMAC-SHA1(server_MAC_key, epoch(2)||seq(6)||type(1)||version(2)||fragment_len(2)||fragment)
    // TLS padding: pad_len = 16 - ((fragment_len + 20) % 16), each byte = pad_len - 1
    public class ServerEncryptedDatagram : IDatagram
    {
        private readonly Dtls10CryptoContext _ctx;

        public IDatagram Datagram    { get; set; }
        public byte      ContentType { get; set; } = 0x16;
        public ushort    Epoch       { get; set; } = 1;
        public ulong     SequenceNumber { get; set; }
        public byte[]    Bytes { get; private set; }

        public ServerEncryptedDatagram(Dtls10CryptoContext ctx)
        {
            _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        }

        public ServerEncryptedDatagram(Dtls10CryptoContext ctx, IDatagram datagram, byte contentType = 0x16)
            : this(ctx)
        {
            Datagram    = datagram;
            ContentType = contentType;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Bytes = bytes.ToArray();

            ContentType = bytes[0];
            Epoch = (ushort)((bytes[3] << 8) | bytes[4]);
            ulong seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            SequenceNumber = seq;

            byte[] fragment = Dtls10RecordProtection.Open(bytes, _ctx.ServerKey, _ctx.ServerMacKey, Epoch, SequenceNumber, ContentType);

            // Mark only after the record authenticated (RFC 6347 §4.1.2.6).
            if (_ctx.ServerRecords.IsDuplicate(SequenceNumber))
                throw new DtlsRecordDiscardedException($"Replayed record {SequenceNumber}");
            _ctx.ServerRecords.Mark(SequenceNumber);

            if (ContentType == 0x16)
            {
                Datagram = fragment[0] switch
                {
                    0x14 => new FinishedDatagram(),
                    _ => throw new NotSupportedException($"Unknown handshake type 0x{fragment[0]:X2}")
                };
            }
            else if (ContentType == 0x17)
            {
                Datagram = new ApplicationDataDatagram();
            }
            else if (ContentType == 0x15)
            {
                Datagram = new AlertDatagram();
            }
            else
            {
                throw new NotSupportedException($"Unsupported content type 0x{ContentType:X2}");
            }

            Datagram.FromBytes(fragment);
        }

        public byte[] ToBytes()
        {
            byte[] fragment    = Datagram.ToBytes();
            int    fragmentLen = fragment.Length;

            byte[] mac    = ComputeMac(_ctx.ServerMacKey, Epoch, SequenceNumber, ContentType, fragment);
            int    padLen = 16 - ((fragmentLen + 20) % 16);
            if (padLen == 0) padLen = 16;
            byte   padByte = (byte)(padLen - 1);

            byte[] toEncrypt = new byte[fragmentLen + 20 + padLen];
            Buffer.BlockCopy(fragment, 0, toEncrypt, 0, fragmentLen);
            Buffer.BlockCopy(mac,      0, toEncrypt, fragmentLen, 20);
            for (int i = 0; i < padLen; i++)
                toEncrypt[fragmentLen + 20 + i] = padByte;

            byte[] iv         = Dtls13CryptoUtils.GenerateRandom(16);
            byte[] ciphertext = CbcEncrypt(_ctx.ServerKey, iv, toEncrypt);

            int    recordBodyLen = 16 + ciphertext.Length;
            byte[] buf = new byte[13 + recordBodyLen];

            buf[0] = ContentType;
            buf[1] = 0xFE; buf[2] = 0xFF; // DTLS 1.0
            buf[3] = (byte)((Epoch >> 8) & 0xFF);
            buf[4] = (byte)(Epoch & 0xFF);
            buf[5]  = (byte)((SequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)((SequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((SequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((SequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((SequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(SequenceNumber & 0xFF);
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            Buffer.BlockCopy(iv,         0, buf, 13, 16);
            Buffer.BlockCopy(ciphertext, 0, buf, 29, ciphertext.Length);

            Bytes = buf;
            return Bytes;
        }

        internal static byte[] ComputeMac(byte[] macKey, ushort epoch, ulong seqNum, byte contentType, byte[] fragment)
        {
            // MAC input: seq_num(8) + type(1) + version(2) + fragment_len(2) + fragment
            byte[] input = new byte[8 + 1 + 2 + 2 + fragment.Length];
            input[0] = (byte)((epoch >> 8) & 0xFF);
            input[1] = (byte)(epoch & 0xFF);
            input[2] = (byte)((seqNum >> 40) & 0xFF);
            input[3] = (byte)((seqNum >> 32) & 0xFF);
            input[4] = (byte)((seqNum >> 24) & 0xFF);
            input[5] = (byte)((seqNum >> 16) & 0xFF);
            input[6] = (byte)((seqNum >> 8) & 0xFF);
            input[7] = (byte)(seqNum & 0xFF);
            input[8]  = contentType;
            input[9]  = 0xFE; input[10] = 0xFF; // DTLS 1.0
            input[11] = (byte)((fragment.Length >> 8) & 0xFF);
            input[12] = (byte)(fragment.Length & 0xFF);
            Buffer.BlockCopy(fragment, 0, input, 13, fragment.Length);

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new KeyParameter(macKey));
            hmac.BlockUpdate(input, 0, input.Length);
            byte[] mac = new byte[20];
            hmac.DoFinal(mac, 0);
            return mac;
        }

        private static byte[] CbcEncrypt(byte[] key, byte[] iv, byte[] data)
        {
            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16)
                cipher.ProcessBlock(data, i, result, i);
            return result;
        }
    }
}
