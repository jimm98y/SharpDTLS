using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol12.Messages
{
    // DTLS 1.2 CertificateRequest (RFC 5246 §7.4.4).
    // Body: certificate_types + supported_signature_algorithms + distinguished_names.
    internal class CertificateRequestDatagram : IDatagram
    {
        public int    RecordSequenceNumber  { get; set; }
        public ushort MessageSequenceNumber { get; set; }

        /// <summary>supported_signature_algorithms: schemes accepted for the client's CertificateVerify.</summary>
        public ushort[] SupportedSignatureAlgorithms { get; set; } = Dtls12Signatures.Supported;

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

            // Body: certificate_types<1..2^8-1> supported_signature_algorithms<2..2^16-2> certificate_authorities<0..2^16-1>
            int pos = 25;
            int typesLength = bytes[pos++];
            pos += typesLength;
            int algsLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if ((algsLength & 1) != 0 || pos + algsLength > bytes.Length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid supported_signature_algorithms.");
            SupportedSignatureAlgorithms = new ushort[algsLength / 2];
            for (int i = 0; i < SupportedSignatureAlgorithms.Length; i++)
                SupportedSignatureAlgorithms[i] = (ushort)((bytes[pos + 2 * i] << 8) | bytes[pos + 2 * i + 1]);
        }

        public byte[] ToBytes()
        {
            // Body:
            //   cert_types_count(1)=2 + rsa_sign(1) + ecdsa_sign(1)
            //   supported_sig_algs_length(2) + algorithms
            //   dn_list_length(2)=0
            int algsLength = 2 * SupportedSignatureAlgorithms.Length;
            byte[] body = new byte[3 + 2 + algsLength + 2];
            body[0] = 0x02; body[1] = 0x01; body[2] = 0x40; // cert_types: rsa_sign, ecdsa_sign
            body[3] = (byte)(algsLength >> 8);
            body[4] = (byte)algsLength;
            for (int i = 0; i < SupportedSignatureAlgorithms.Length; i++)
            {
                body[5 + 2 * i] = (byte)(SupportedSignatureAlgorithms[i] >> 8);
                body[6 + 2 * i] = (byte)SupportedSignatureAlgorithms[i];
            }
            int bodyLen = body.Length;
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
