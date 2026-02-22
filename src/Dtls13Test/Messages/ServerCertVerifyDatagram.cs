namespace Dtls13Test.Messages
{
    public class ServerCertVerifyDatagram : IDatagram
    {
        public int SequenceNumber { get; set; } = 3;
        public uint SignatureType { get; set; } = 0x0804; // assigned value for RSA-PSS-RSAE-SHA256 signature
        public byte[] Signature { get; set; } = Convert.FromHexString("2c 76 3d 6a d3 d8 af 7f a3 7d a6 d8 d9 0e 73 7c ea 53 ee 7a ff a5 61 48 74 cc 68 48 9c 73 a2 f3 a0 43 cb ba e6 c2 7a 41 91 0e de 9a df c7 22 23 58 26 12 ec 96 79 fe 1f 9f a5 f4 a4 b6 12 f8 6f 40 88 49 a3 29 f7 63 e0 4f be 95 9a 91 e8 d1 8d 4a ba 79 29 57 6f a0 24 ec b2 37 d6 33 78 e9 8e e5 9d c9 59 49 b2 63 b3 06 53 0a 2e 6f b9 b2 2f a2 3c 64 32 33 43 03 89 33 01 fd 60 e2 05 82 6e b9 ec 41 4f ec 5f 9a 0d 6f 8f 3d 89 a0 9f 14 8e 0f 05 03 49 bc 1e 17 97 d9 28 1e ed f6 e7 66 9c e2 56 ae 79 d4 ee 8c 96 56 0d cf 07 6c 2a 45 a4 ee e8 d2 79 71 0f 0c e7 03 4a 3f 5c aa 94 41 4e ae df 61 08 48 66 e4 9e 81 88 3e e2 1a 12 59 3c cb 96 dd 11 76 9e 34 0f 1e 6c c2 14 b0 57 95 e5 4a fc 94 79 84 5e 4d f2 bf 96 9f bb 21 8c b9 c4 b8 34 a8 51 be 34 75 a1 45 2f 4b 33 55 4f 9d 65".Replace(" ", ""));

        public ServerCertVerifyDatagram()
        {  }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small to be a valid ServerExtensions message.");

            if (bytes[0] != 0x0f) throw new InvalidDataException("Not an EncryptedExtensions handshake message.");

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

            return data.Take(13 + length).ToArray();
        }
    }
}
