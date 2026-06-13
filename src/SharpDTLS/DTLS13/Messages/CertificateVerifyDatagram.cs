using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class CertificateVerifyDatagram : IDatagram
    {
        public int SequenceNumber { get; set; } = 3;
        public uint SignatureType { get; set; } = 0x0804; // assigned value for RSA-PSS-RSAE-SHA256 signature
        public byte[] Signature { get; set; } = null;
        public byte[] Bytes { get; private set; }

        public CertificateVerifyDatagram()
        {  }

        public CertificateVerifyDatagram(byte[] signature)
        {
            this.Signature = signature;
        }

        public CertificateVerifyDatagram(byte[] signature, uint signatureType)
        {
            this.Signature = signature;
            this.SignatureType = signatureType;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small to be a valid ServerExtensions message.");
            if (bytes[0] != 0x0f) throw new InvalidDataException("Not an EncryptedExtensions handshake message.");

            Bytes = bytes.ToArray();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

            this.SequenceNumber = (bytes[4] << 8) | bytes[5];

            int fragmentOffset = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8];
            int fragmentLength = (bytes[9] << 16) | (bytes[10] << 8) | bytes[11];

            this.SignatureType = (uint)(bytes[12] << 8 | bytes[13]);

            // signature length
            int signatureLength = (bytes[14] << 8) | bytes[15];

            this.Signature = new byte[signatureLength];
            Buffer.BlockCopy(bytes, 16, this.Signature, 0, signatureLength);
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x0f; // handshake message type (certificate verify)

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            // handshake reconstruction data
            data[4] = (byte)((this.SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(this.SequenceNumber & 0xFF);
            int fragmentOffset = 0;
            data[6] = 0;
            data[7] = 0;
            data[8] = 0;
            int fragmentLength = 0;
            data[9] = 0;
            data[10] = 0;
            data[11] = 0;

            // reserved value for RSA-PSS-RSAE-SHA256 signature
            data[12] = (byte)(this.SignatureType >> 8 & 0xFF);
            data[13] = (byte)(this.SignatureType & 0xFF); 

            // signaure length (2 bytes)
            int signatureLength = this.Signature.Length;
            data[14] = (byte)((signatureLength >> 8) & 0xFF);
            data[15] = (byte)(signatureLength & 0xFF);

            Buffer.BlockCopy(this.Signature, 0, data, 16, this.Signature.Length);

            length = 16 + this.Signature.Length;

            // type is 22 (handshake record)
            data[length] = 0x16;

            length = length + 1;

            // fill in lengths
            length = length - 13;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            fragmentOffset = 0;
            data[6] = (byte)((fragmentOffset >> 16) & 0xFF);
            data[7] = (byte)((fragmentOffset >> 8) & 0xFF);
            data[8] = (byte)(fragmentOffset & 0xFF);

            fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(13 + length).ToArray();

            return Bytes;
        }
    }
}
