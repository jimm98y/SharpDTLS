using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    // DTLS 1.2 CertificateVerify (RFC 5246 §7.4.8).
    // Body: hash_algorithm(1) + sig_algorithm(1) + signature_length(2) + signature.
    public class CertificateVerifyDatagram : IDatagram
    {
        public int    RecordSequenceNumber  { get; set; }
        public ushort MessageSequenceNumber { get; set; }
        public byte   HashAlgorithm  { get; set; } = 0x04; // SHA256
        public byte   SigAlgorithm   { get; set; } = 0x03; // ECDSA
        public byte[] Signature { get; set; }
        public byte[] Bytes { get; private set; }

        public CertificateVerifyDatagram() { }

        public CertificateVerifyDatagram(byte[] signature, byte hashAlg, byte sigAlg)
        {
            Signature     = signature;
            HashAlgorithm = hashAlg;
            SigAlgorithm  = sigAlg;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x0F) throw new InvalidDataException("Not a CertificateVerify message.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber  = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            HashAlgorithm = bytes[25];
            SigAlgorithm  = bytes[26];
            int sigLen = (bytes[27] << 8) | bytes[28];
            Signature = new byte[sigLen];
            Buffer.BlockCopy(bytes, 29, Signature, 0, sigLen);
        }

        public byte[] ToBytes()
        {
            int sigLen  = Signature.Length;
            int bodyLen = 4 + sigLen;  // hash(1) + sig_alg(1) + sig_len(2) + sig
            int total   = 13 + 12 + bodyLen;
            byte[] buf  = new byte[total];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFD;
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

            buf[13] = 0x0F;
            buf[14] = (byte)((bodyLen >> 16) & 0xFF);
            buf[15] = (byte)((bodyLen >> 8) & 0xFF);
            buf[16] = (byte)(bodyLen & 0xFF);
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0; buf[20] = 0; buf[21] = 0;
            buf[22] = (byte)((bodyLen >> 16) & 0xFF);
            buf[23] = (byte)((bodyLen >> 8) & 0xFF);
            buf[24] = (byte)(bodyLen & 0xFF);

            buf[25] = HashAlgorithm;
            buf[26] = SigAlgorithm;
            buf[27] = (byte)((sigLen >> 8) & 0xFF);
            buf[28] = (byte)(sigLen & 0xFF);
            Buffer.BlockCopy(Signature, 0, buf, 29, sigLen);

            Bytes = buf;
            return Bytes;
        }
    }
}
