using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.PostHandshake
{
    public class CertificateRequestDatagram : IDatagram
    {
        public byte HandshakeType { get; set; } = 0x0d; // CertificateRequest
        public int SequenceNumber { get; set; } = 0;
        public byte RequestContext { get; set; } = 0;
        // Extensions would go here, but we'll skip them for now

        public byte[] Bytes { get; private set; }

        public CertificateRequestDatagram()
        {
        }

        public CertificateRequestDatagram(byte requestContext)
        {
            RequestContext = requestContext;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 1 + 2) throw new ArgumentException("Buffer too small to be a valid CertificateRequest.");

            Bytes = bytes.ToArray();

            if (bytes[0] != HandshakeType) throw new InvalidDataException("Not a CertificateRequest handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            // request context
            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before request context.");
            RequestContext = bytes[pos++];

            // certificate request extensions
            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before extensions length.");
            int extensionsLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;

            if (bytes.Length < pos + extensionsLength) throw new ArgumentException("Buffer truncated in extensions area.");
            // Skip extensions for now
            pos += extensionsLength;
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[512];

            data[0] = HandshakeType; // CertificateRequest

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            // handshake reconstruction data
            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            // fragment offset and fragment length
            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            // request context
            data[pos++] = RequestContext;

            // certificate request extensions
            int extensionsLength = 0;
            data[pos++] = (byte)((extensionsLength >> 8) & 0xFF);
            data[pos++] = (byte)(extensionsLength & 0xFF);

            // trailing record type for parity
            data[pos++] = 0x16;

            // fill in lengths
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
