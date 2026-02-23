namespace Dtls13Test.Messages
{
    public class ServerExtensionsDatagram : IDatagram
    {
        public List<ITlsExtension> Extensions { get; private set; } = new List<ITlsExtension>();
        public int SequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public ServerExtensionsDatagram()
        {
            Extensions = new List<ITlsExtension>(GetDefaultExtensions());
        }

        private static ITlsExtension[] GetDefaultExtensions()
        {
            return new ITlsExtension[]
            {
                new ClientSupportedGroups(new ushort[] { 0x0017, 0x001d, 0x0018, 0x0019, 0x0100 }) // assigned value for the curve "x25519"
            };
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 14) throw new ArgumentException("Buffer too small to be a valid ServerExtensions message.");
            if (bytes[0] != 0x08) throw new InvalidDataException("Not an EncryptedExtensions handshake message.");

            Bytes = bytes.ToArray();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

            this.SequenceNumber = (bytes[4] << 8) | bytes[5];

            int fragmentOffset = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8];
            int fragmentLength = (bytes[9] << 16) | (bytes[10] << 8) | bytes[11];

            if (bytes.Length < 14) throw new ArgumentException("Buffer truncated before extensions length.");
            int extensionsLength = (bytes[12] << 8) | bytes[13];
            int extensionsStart = 14;
            int extensionsEnd = extensionsStart + extensionsLength;
            if (bytes.Length < extensionsEnd) throw new ArgumentException("Buffer truncated in extensions area.");

            Extensions = new List<ITlsExtension>();

            int pos = extensionsStart;
            while (pos < extensionsEnd)
            {
                if (pos + 4 > bytes.Length) throw new ArgumentException("Truncated extension header.");
                ushort extType = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                ushort extLen = (ushort)((bytes[pos + 2] << 8) | bytes[pos + 3]);

                ITlsExtension matching = extType switch
                {
                    0x000a => new ClientSupportedGroups(),
                    _ => null
                };

                if (matching != null)
                {
                    int consumed = matching.Read(pos, bytes);
                    if (consumed <= 0) throw new InvalidDataException($"Extension parser for 0x{extType:X4} returned invalid consumed length.");
                    Extensions.Add(matching);
                    pos += consumed;
                }
                else
                {
                    pos += 4 + extLen;
                }
            }

            if (pos != extensionsEnd) throw new InvalidDataException("Extensions parsing did not consume the expected length.");
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x08; // handshake message type (encrypted extensions)

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

            // Extensions 
            int extensionsLength = Extensions.Select(x => x.CalculateLength()).Sum();
            data[12] = (byte)((extensionsLength >> 8) & 0xff); // Extensions length in bytes (placeholder)
            data[13] = (byte)(extensionsLength & 0xff); // Extensions length in bytes (placeholder)
            int nextExtensionOffset = 14; // Starting offset for extensions
            foreach (var extension in Extensions)
            {
                int extensionLength = extension.Write(nextExtensionOffset, data);
                nextExtensionOffset += extensionLength;
            }
             
            data[nextExtensionOffset] = 0x16; // type is 22 (handshake record)
            nextExtensionOffset += 1;

            // fill in lengths
            length = nextExtensionOffset - 13; 
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

            Bytes = data.Take(nextExtensionOffset).ToArray();

            return Bytes;
        }
    }
}
