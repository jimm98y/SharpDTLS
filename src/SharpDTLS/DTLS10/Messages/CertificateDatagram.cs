using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    public class CertificateDatagram : IDatagram
    {
        public byte[] Certificate { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public CertificateDatagram()
        {
        }

        public CertificateDatagram(byte[] certificate)
        {
            Certificate = certificate ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 16) throw new ArgumentException("Buffer too small for Certificate.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x0b) throw new InvalidDataException("Not a Certificate handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            if (bytes.Length < pos + 3) throw new ArgumentException("Buffer truncated before certificates length.");
            int certificatesListLen = (bytes[pos] << 16) | (bytes[pos + 1] << 8) | bytes[pos + 2];
            pos += 3;

            if (bytes.Length < pos + 3) throw new ArgumentException("Buffer truncated before certificate length.");
            int certificateLen = (bytes[pos] << 16) | (bytes[pos + 1] << 8) | bytes[pos + 2];
            pos += 3;

            if (bytes.Length < pos + certificateLen) throw new ArgumentException("Buffer truncated for certificate data.");
            Certificate = new byte[certificateLen];
            if (certificateLen > 0) Buffer.BlockCopy(bytes, pos, Certificate, 0, certificateLen);
            pos += certificateLen;
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[4096];

            data[0] = 0x0b; // Certificate

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            int certLen = Certificate?.Length ?? 0;
            int certificatesListLen = 3 + certLen;
            data[pos++] = (byte)((certificatesListLen >> 16) & 0xFF);
            data[pos++] = (byte)((certificatesListLen >> 8) & 0xFF);
            data[pos++] = (byte)(certificatesListLen & 0xFF);

            data[pos++] = (byte)((certLen >> 16) & 0xFF);
            data[pos++] = (byte)((certLen >> 8) & 0xFF);
            data[pos++] = (byte)(certLen & 0xFF);

            if (certLen > 0)
            {
                Buffer.BlockCopy(Certificate, 0, data, pos, certLen);
                pos += certLen;
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
