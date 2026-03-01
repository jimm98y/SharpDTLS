namespace Dtls13Test.Messages
{
    public class CertificateDatagram : IDatagram
    {
        public int SequenceNumber { get; set; } = 2;
        public byte RequestContext { get; set; } = 0;
        public byte[] Certificate { get; set; } 
        public byte[] Bytes { get; private set; }

        public CertificateDatagram()
        { }

        public CertificateDatagram(byte[] certificate)
        {
            Certificate = certificate;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small to be a valid ServerExtensions message.");
            if (bytes[0] != 0x0b) throw new InvalidDataException("Not an EncryptedExtensions handshake message.");

            Bytes = bytes.ToArray();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

            this.SequenceNumber = (bytes[4] << 8) | bytes[5];

            int fragmentOffset = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8];
            int fragmentLength = (bytes[9] << 16) | (bytes[10] << 8) | bytes[11];

            this.RequestContext = bytes[12]; // request context

            // certificates length
            int certificatesLength = (bytes[13] << 16) | (bytes[14] << 8) | bytes[15];

            // certificate length
            int certificateLength = (bytes[16] << 16) | (bytes[17] << 8) | bytes[18];

            this.Certificate = new byte[certificateLength];
            Buffer.BlockCopy(bytes, 19, this.Certificate, 0, certificateLength);
            
            // certificate extensions length
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x0b; // handshake message type (certificate)

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

            data[12] = this.RequestContext; // request context

            // certificates length
            int certificatesLength = this.Certificate.Length + 3 + 2;
            data[13] = (byte)((certificatesLength >> 16) & 0xFF);
            data[14] = (byte)((certificatesLength >> 8) & 0xFF);
            data[15] = (byte)(certificatesLength & 0xFF);

            // certificate length
            int certificateLength = this.Certificate.Length;
            data[16] = (byte)((certificateLength >> 16) & 0xFF);
            data[17] = (byte)((certificateLength >> 8) & 0xFF);
            data[18] = (byte)(certificateLength & 0xFF);

            Buffer.BlockCopy(this.Certificate, 0, data, 19, this.Certificate.Length);

            length = 19 + this.Certificate.Length;

            // certificate extensions length
            int certificateExtensionsLength = 0;
            data[length + 0] = (byte)((certificateExtensionsLength >> 8) & 0xFF);
            data[length + 1] = (byte)(certificateExtensionsLength & 0xFF);

            // record type
            data[length + 2] = 0x16; // handshake record

            // fill in lengths
            length = length + 3 - 13;

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

            Bytes = data.Take(length + 13).ToArray();

            return Bytes;
        }
    }
}
