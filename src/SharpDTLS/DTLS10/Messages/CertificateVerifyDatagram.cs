using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10.Messages
{
    public class CertificateVerifyDatagram : IDatagram
    {
        public byte[] Signature { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public CertificateVerifyDatagram()
        {
        }

        public CertificateVerifyDatagram(byte[] signature)
        {
            Signature = signature ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 15) throw new ArgumentException("Buffer too small for CertificateVerify.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x0f) throw new InvalidDataException("Not a CertificateVerify handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before signature length.");
            int sigLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;

            if (bytes.Length < pos + sigLen) throw new ArgumentException("Buffer truncated for signature.");
            Signature = new byte[sigLen];
            if (sigLen > 0) Buffer.BlockCopy(bytes, pos, Signature, 0, sigLen);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x0f; // CertificateVerify

            int sigLen = Signature?.Length ?? 0;
            int length = 2 + sigLen;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            data[pos++] = (byte)((sigLen >> 8) & 0xFF);
            data[pos++] = (byte)(sigLen & 0xFF);

            if (sigLen > 0)
            {
                Buffer.BlockCopy(Signature, 0, data, pos, sigLen);
                pos += sigLen;
            }

            // record type
            data[pos++] = 0x16;

            // update fragment lengths
            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
