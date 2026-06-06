using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10.Messages
{
    public class CertificateRequestDatagram : IDatagram
    {
        public byte[] CertificateTypes { get; set; } = new byte[0];
        public byte[] SupportedSignatureAlgorithms { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public CertificateRequestDatagram()
        {
        }

        public CertificateRequestDatagram(byte[] certificateTypes)
        {
            CertificateTypes = certificateTypes ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small for CertificateRequest.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x0d) throw new InvalidDataException("Not a CertificateRequest handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before certificate types length.");
            int typesLen = bytes[pos++];
            if (bytes.Length < pos + typesLen) throw new ArgumentException("Buffer truncated for certificate types.");

            CertificateTypes = new byte[typesLen];
            if (typesLen > 0) Buffer.BlockCopy(bytes, pos, CertificateTypes, 0, typesLen);
            pos += typesLen;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before supported algorithms length.");
            int algorithmsLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;

            if (bytes.Length < pos + algorithmsLen) throw new ArgumentException("Buffer truncated for supported algorithms.");
            SupportedSignatureAlgorithms = new byte[algorithmsLen];
            if (algorithmsLen > 0) Buffer.BlockCopy(bytes, pos, SupportedSignatureAlgorithms, 0, algorithmsLen);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[1024];

            data[0] = 0x0d; // CertificateRequest

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            int typesLen = CertificateTypes?.Length ?? 0;
            data[pos++] = (byte)typesLen;
            if (typesLen > 0)
            {
                Buffer.BlockCopy(CertificateTypes, 0, data, pos, typesLen);
                pos += typesLen;
            }

            int algorithmsLen = SupportedSignatureAlgorithms?.Length ?? 0;
            data[pos++] = (byte)((algorithmsLen >> 8) & 0xFF);
            data[pos++] = (byte)(algorithmsLen & 0xFF);
            if (algorithmsLen > 0)
            {
                Buffer.BlockCopy(SupportedSignatureAlgorithms, 0, data, pos, algorithmsLen);
                pos += algorithmsLen;
            }

            // record type
            data[pos++] = 0x16;

            // fill in length
            length = pos - 13;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            int fragmentOffset = 0;
            data[6] = (byte)((fragmentOffset >> 16) & 0xFF);
            data[7] = (byte)((fragmentOffset >> 8) & 0xFF);
            data[8] = (byte)(fragmentOffset & 0xFF);

            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
