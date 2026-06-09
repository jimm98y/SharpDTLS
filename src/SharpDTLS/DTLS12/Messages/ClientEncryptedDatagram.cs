using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    // Wraps a client-sent DTLS 1.2 record encrypted with AES-128-GCM (uses client write keys).
    public class ClientEncryptedDatagram : IDatagram
    {
        private readonly Dtls12CryptoContext _ctx;

        public IDatagram Datagram { get; set; }
        public byte ContentType { get; set; } = 0x16;
        public ushort Epoch { get; set; } = 1;
        public ulong SequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public ClientEncryptedDatagram(Dtls12CryptoContext ctx)
        {
            _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        }

        public ClientEncryptedDatagram(Dtls12CryptoContext ctx, IDatagram datagram, byte contentType = 0x16)
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

            ushort recordLen = (ushort)((bytes[11] << 8) | bytes[12]);

            byte[] explicitNonce = new byte[8];
            Buffer.BlockCopy(bytes, 13, explicitNonce, 0, 8);

            byte[] nonce = new byte[12];
            Buffer.BlockCopy(_ctx.ClientIv, 0, nonce, 0, 4);
            Buffer.BlockCopy(explicitNonce, 0, nonce, 4, 8);

            int ciphertextLen = recordLen - 8;
            int plaintextLen  = ciphertextLen - 16;

            byte[] aad = BuildAad(bytes, plaintextLen);

            byte[] work = new byte[ciphertextLen];
            Buffer.BlockCopy(bytes, 21, work, 0, ciphertextLen);

            Decrypt(_ctx.AeadDecryptEngine, work, 0, ciphertextLen, nonce, new KeyParameter(_ctx.ClientKey), 16, aad);

            byte[] plaintext = work.Take(plaintextLen).ToArray();

            if (ContentType == 0x16)
            {
                Datagram = plaintext[0] switch
                {
                    0x14 => new FinishedDatagram(),
                    _ => throw new NotSupportedException($"Unknown handshake type 0x{plaintext[0]:X2}")
                };
            }
            else if (ContentType == 0x17)
            {
                Datagram = new ApplicationDataDatagram();
            }
            else
            {
                throw new NotSupportedException($"Unsupported content type 0x{ContentType:X2}");
            }

            Datagram.FromBytes(plaintext);
        }

        public byte[] ToBytes()
        {
            byte[] plaintext = Datagram.ToBytes();
            int plaintextLen = plaintext.Length;

            byte[] explicitNonce = new byte[8];
            explicitNonce[0] = (byte)((Epoch >> 8) & 0xFF);
            explicitNonce[1] = (byte)(Epoch & 0xFF);
            explicitNonce[2] = (byte)((SequenceNumber >> 40) & 0xFF);
            explicitNonce[3] = (byte)((SequenceNumber >> 32) & 0xFF);
            explicitNonce[4] = (byte)((SequenceNumber >> 24) & 0xFF);
            explicitNonce[5] = (byte)((SequenceNumber >> 16) & 0xFF);
            explicitNonce[6] = (byte)((SequenceNumber >> 8) & 0xFF);
            explicitNonce[7] = (byte)(SequenceNumber & 0xFF);

            byte[] nonce = new byte[12];
            Buffer.BlockCopy(_ctx.ClientIv, 0, nonce, 0, 4);
            Buffer.BlockCopy(explicitNonce, 0, nonce, 4, 8);

            int recordBodyLen = 8 + plaintextLen + 16;
            byte[] buf = new byte[13 + recordBodyLen];

            buf[0] = ContentType;
            buf[1] = 0xFE; buf[2] = 0xFD;
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

            Buffer.BlockCopy(explicitNonce, 0, buf, 13, 8);
            Buffer.BlockCopy(plaintext, 0, buf, 21, plaintextLen);

            byte[] aad = BuildAad(buf, plaintextLen);
            Encrypt(_ctx.AeadEncryptEngine, buf, 21, 21 + plaintextLen, nonce, new KeyParameter(_ctx.ClientKey), 16, aad);

            Bytes = buf;
            return Bytes;
        }

        private static byte[] BuildAad(byte[] record, int plaintextLen)
        {
            byte[] aad = new byte[13];
            Buffer.BlockCopy(record, 3, aad, 0, 8);
            aad[8]  = record[0];
            aad[9]  = record[1];
            aad[10] = record[2];
            aad[11] = (byte)((plaintextLen >> 8) & 0xFF);
            aad[12] = (byte)(plaintextLen & 0xFF);
            return aad;
        }

        private static void Encrypt(IAeadBlockCipher engine, byte[] buf, int offset, int end,
            byte[] iv, KeyParameter key, int tagBytes, byte[] aad)
        {
            int len = end - offset;
            var p = new AeadParameters(key, tagBytes << 3, iv, aad);
            engine.Init(true, p);
            int written = engine.ProcessBytes(buf, offset, len, buf, offset);
            engine.DoFinal(buf, offset + written);
        }

        private static void Decrypt(IAeadBlockCipher engine, byte[] buf, int offset, int end,
            byte[] iv, KeyParameter key, int tagBytes, byte[] aad)
        {
            int len = end - offset;
            var p = new AeadParameters(key, tagBytes << 3, iv, aad);
            engine.Init(false, p);
            int written = engine.ProcessBytes(buf, offset, len, buf, offset);
            engine.DoFinal(buf, offset + written);
        }
    }
}
