using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    // Wraps a server-sent DTLS 1.2 encrypted record.
    //
    // AES-GCM wire format:
    //   DTLS record header (13 bytes): type | version(2) | epoch(2) | seq(6) | length(2)
    //   explicit_nonce (8 bytes): epoch(2) || seq_num(6)
    //   ciphertext + GCM tag (16 bytes)
    //   Nonce = server_write_IV(4) || explicit_nonce(8)
    //
    // ChaCha20-Poly1305 wire format (RFC 7905):
    //   DTLS record header (13 bytes)
    //   ciphertext + Poly1305 tag (16 bytes)  — no explicit nonce field
    //   Nonce = server_write_IV(12) XOR (0x00x4 || epoch(2) || seq(6))
    public class ServerEncryptedDatagram : IDatagram
    {
        private readonly Dtls12CryptoContext _ctx;

        public IDatagram Datagram { get; set; }
        public byte ContentType { get; set; } = 0x16;
        public ushort Epoch { get; set; } = 1;
        public ulong SequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public ServerEncryptedDatagram(Dtls12CryptoContext ctx)
        {
            _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        }

        public ServerEncryptedDatagram(Dtls12CryptoContext ctx, IDatagram datagram, byte contentType = 0x16)
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
            byte[] plaintext;

            if (_ctx.IsChaCha20)
            {
                // No explicit nonce; ciphertext starts at offset 13
                int ciphertextLen = recordLen;
                int plaintextLen  = ciphertextLen - 16;
                byte[] nonce = BuildChaCha20Nonce(_ctx.ServerIv, Epoch, SequenceNumber);
                byte[] aad   = BuildAad(bytes, plaintextLen);

                byte[] work = new byte[ciphertextLen];
                Buffer.BlockCopy(bytes, 13, work, 0, ciphertextLen);
                AeadProcess(false, _ctx.ChaChaDecryptEngine, work, 0, ciphertextLen, nonce, _ctx.ServerKey, 16, aad);
                plaintext = work.Take(plaintextLen).ToArray();
            }
            else
            {
                // GCM: 8-byte explicit nonce precedes ciphertext
                byte[] explicitNonce = new byte[8];
                Buffer.BlockCopy(bytes, 13, explicitNonce, 0, 8);
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(_ctx.ServerIv, 0, nonce, 0, 4);
                Buffer.BlockCopy(explicitNonce, 0, nonce, 4, 8);

                int ciphertextLen = recordLen - 8;
                int plaintextLen  = ciphertextLen - 16;
                byte[] aad  = BuildAad(bytes, plaintextLen);
                byte[] work = new byte[ciphertextLen];
                Buffer.BlockCopy(bytes, 21, work, 0, ciphertextLen);
                AeadProcess(false, _ctx.AeadDecryptEngine, work, 0, ciphertextLen, nonce, _ctx.ServerKey, 16, aad);
                plaintext = work.Take(plaintextLen).ToArray();
            }

            // Mark only after the record authenticated (RFC 6347 §4.1.2.6).
            if (_ctx.ServerRecords.IsDuplicate(SequenceNumber))
                throw new DtlsRecordDiscardedException($"Replayed record {SequenceNumber}");
            _ctx.ServerRecords.Mark(SequenceNumber);

            Datagram = ContentType == 0x16
                ? plaintext[0] switch
                {
                    0x04 => new NewSessionTicketDatagram(),
                    0x14 => new FinishedDatagram(),
                    _ => throw new NotSupportedException($"Unknown handshake type 0x{plaintext[0]:X2}")
                }
                : ContentType == 0x17
                    ? (IDatagram)new ApplicationDataDatagram()
                    : ContentType == 0x15
                        ? (IDatagram)new AlertDatagram()
                        : throw new NotSupportedException($"Unsupported content type 0x{ContentType:X2}");

            Datagram.FromBytes(plaintext);
        }

        public byte[] ToBytes()
        {
            byte[] plaintext    = Datagram.ToBytes();
            int    plaintextLen = plaintext.Length;

            if (_ctx.IsChaCha20)
            {
                byte[] nonce = BuildChaCha20Nonce(_ctx.ServerIv, Epoch, SequenceNumber);
                int recordBodyLen = plaintextLen + 16; // ciphertext + tag, no explicit nonce
                byte[] buf = new byte[13 + recordBodyLen];

                WriteRecordHeader(buf, ContentType, Epoch, SequenceNumber, recordBodyLen);
                Buffer.BlockCopy(plaintext, 0, buf, 13, plaintextLen);

                byte[] aad = BuildAad(buf, plaintextLen);
                AeadProcess(true, _ctx.ChaChaEncryptEngine, buf, 13, 13 + plaintextLen, nonce, _ctx.ServerKey, 16, aad);

                Bytes = buf;
            }
            else
            {
                byte[] explicitNonce = BuildExplicitNonce(Epoch, SequenceNumber);
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(_ctx.ServerIv, 0, nonce, 0, 4);
                Buffer.BlockCopy(explicitNonce, 0, nonce, 4, 8);

                int recordBodyLen = 8 + plaintextLen + 16;
                byte[] buf = new byte[13 + recordBodyLen];

                WriteRecordHeader(buf, ContentType, Epoch, SequenceNumber, recordBodyLen);
                Buffer.BlockCopy(explicitNonce, 0, buf, 13, 8);
                Buffer.BlockCopy(plaintext, 0, buf, 21, plaintextLen);

                byte[] aad = BuildAad(buf, plaintextLen);
                AeadProcess(true, _ctx.AeadEncryptEngine, buf, 21, 21 + plaintextLen, nonce, _ctx.ServerKey, 16, aad);

                Bytes = buf;
            }

            return Bytes;
        }

        // Nonce for ChaCha20-Poly1305 = IV XOR (zeros(4) || epoch(2) || seq(6))
        private static byte[] BuildChaCha20Nonce(byte[] iv, ushort epoch, ulong seq)
        {
            byte[] seqPadded = new byte[12];
            seqPadded[4]  = (byte)((epoch >> 8) & 0xFF);
            seqPadded[5]  = (byte)(epoch & 0xFF);
            seqPadded[6]  = (byte)((seq >> 40) & 0xFF);
            seqPadded[7]  = (byte)((seq >> 32) & 0xFF);
            seqPadded[8]  = (byte)((seq >> 24) & 0xFF);
            seqPadded[9]  = (byte)((seq >> 16) & 0xFF);
            seqPadded[10] = (byte)((seq >> 8)  & 0xFF);
            seqPadded[11] = (byte)(seq & 0xFF);
            byte[] nonce = new byte[12];
            for (int i = 0; i < 12; i++) nonce[i] = (byte)(iv[i] ^ seqPadded[i]);
            return nonce;
        }

        private static byte[] BuildExplicitNonce(ushort epoch, ulong seq)
        {
            var n = new byte[8];
            n[0] = (byte)((epoch >> 8) & 0xFF); n[1] = (byte)(epoch & 0xFF);
            n[2] = (byte)((seq >> 40) & 0xFF);  n[3] = (byte)((seq >> 32) & 0xFF);
            n[4] = (byte)((seq >> 24) & 0xFF);  n[5] = (byte)((seq >> 16) & 0xFF);
            n[6] = (byte)((seq >> 8)  & 0xFF);  n[7] = (byte)(seq & 0xFF);
            return n;
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

        private static void WriteRecordHeader(byte[] buf, byte contentType, ushort epoch, ulong seq, int bodyLen)
        {
            buf[0] = contentType;
            buf[1] = 0xFE; buf[2] = 0xFD;
            buf[3] = (byte)((epoch >> 8) & 0xFF); buf[4] = (byte)(epoch & 0xFF);
            buf[5]  = (byte)((seq >> 40) & 0xFF); buf[6]  = (byte)((seq >> 32) & 0xFF);
            buf[7]  = (byte)((seq >> 24) & 0xFF); buf[8]  = (byte)((seq >> 16) & 0xFF);
            buf[9]  = (byte)((seq >> 8)  & 0xFF); buf[10] = (byte)(seq & 0xFF);
            buf[11] = (byte)((bodyLen >> 8) & 0xFF); buf[12] = (byte)(bodyLen & 0xFF);
        }

        private static void AeadProcess(bool encrypt, IAeadCipher engine, byte[] buf, int offset, int end,
            byte[] nonce, byte[] key, int tagBytes, byte[] aad)
        {
            int len = end - offset;
            var p = new AeadParameters(new KeyParameter(key), tagBytes << 3, nonce, aad);
            engine.Init(encrypt, p);
            int written = engine.ProcessBytes(buf, offset, len, buf, offset);
            engine.DoFinal(buf, offset + written);
        }
    }
}
