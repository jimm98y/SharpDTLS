namespace Dtls13Test.Messages
{
    public class ServerHelloDatagram : IDatagram
    {
        public byte[] ServerRandom { get; set; } 
        public byte[] PublicKey { get; private set; }
        public byte[] Bytes { get; private set; }
        public int Epoch { get; set; } = 0;
        public int RecordSequenceNumber { get; set; }
        public List<ITlsExtension> Extensions { get; private set; } = new List<ITlsExtension>();

        public ushort SelectedCipherSuite { get; set; } = 0x1301;

        public ServerHelloDatagram()
        { }

        public ServerHelloDatagram(byte[] publicKey, ushort selectedCipherSuite, byte[] serverRandom)
        {
            PublicKey = publicKey;
            SelectedCipherSuite = selectedCipherSuite;
            ServerRandom = serverRandom;
            Extensions = new List<ITlsExtension>(GetDefaultExtensions(publicKey));
        }

        private static ITlsExtension[] GetDefaultExtensions(byte[] publicKey)
        {
            return new ITlsExtension[]
            {
                new ServerKeyShareExtension(0x001d, publicKey),
                new ServerSupportedVersions(),
            };
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 65) throw new ArgumentException("Buffer too small to be a valid ServerHello.");
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x02) throw new InvalidDataException("Not a ServerHello handshake message.");

            Bytes = bytes.ToArray();
            Epoch = (bytes[3] << 8) | bytes[4];

            long seq = 0;
            for (int i = 5; i <= 10; i++)
            {
                seq = (seq << 8) | bytes[i];
            }
            RecordSequenceNumber = (int)seq;

            if (bytes.Length < 27 + 32) throw new ArgumentException("Buffer too small for ServerRandom.");
            ServerRandom = new byte[32];
            Buffer.BlockCopy(bytes, 27, ServerRandom, 0, 32);

            // Legacy session id length 
            if (bytes.Length < 60) throw new ArgumentException("Buffer truncated before session id / cipher suite.");
            int sessionIdLen = bytes[59];
            int cipherOffset = 60 + sessionIdLen;
            if (bytes.Length < cipherOffset + 3) throw new ArgumentException("Buffer truncated before cipher suite/compression.");

            // Selected cipher suite 
            SelectedCipherSuite = (ushort)((bytes[cipherOffset] << 8) | bytes[cipherOffset + 1]);

            // Compression method - DTLS1.3 doesn't use compression
            byte compression = bytes[cipherOffset + 2];

            // Extensions length
            int extLenOffset = cipherOffset + 3;
            if (bytes.Length < extLenOffset + 2) throw new ArgumentException("Buffer truncated before extensions length.");
            int extensionsLength = (bytes[extLenOffset] << 8) | bytes[extLenOffset + 1];
            int extensionsStart = extLenOffset + 2;
            int extensionsEnd = extensionsStart + extensionsLength;
            if (bytes.Length < extensionsEnd) throw new ArgumentException("Buffer truncated in extensions area.");

            Extensions = new List<ITlsExtension>();

            // Parse extensions
            int pos = extensionsStart;
            while (pos < extensionsEnd)
            {
                if (pos + 4 > bytes.Length) throw new ArgumentException("Truncated extension header.");
                ushort extType = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                ushort extLen = (ushort)((bytes[pos + 2] << 8) | bytes[pos + 3]);

                // Try to find an existing extension instance (so we update it), otherwise create a new one.
                ITlsExtension extensionInstance = extType switch
                {
                    0x0033 => new ServerKeyShareExtension(),
                    0x002b => new ServerSupportedVersions(),
                    0x002c => new CookieExtension(),    
                    _ => throw new NotSupportedException()
                };

                if (extensionInstance != null)
                {
                    int consumed = extensionInstance.Read(pos, bytes);
                    if (consumed <= 0) throw new InvalidDataException($"Extension parser for 0x{extType:X4} returned invalid consumed length.");

                    if (!Extensions.Contains(extensionInstance)) Extensions.Add(extensionInstance);
                    pos += consumed;

                    if(extensionInstance is ServerKeyShareExtension keyShareExt)
                    {
                        // If we successfully parsed a key share extension, we can populate the PublicKey property of the ServerHelloMessage for easier access.
                        PublicKey = keyShareExt.PublicKey;
                    }
                }
                else
                {
                    pos += 4 + extLen;
                }
            }

            // final sanity check
            if (pos != extensionsEnd) throw new InvalidDataException("Extensions parsing did not consume the expected length.");
        }

        public byte[] ToBytes()
        {
            byte[] serverHello = new byte[2048];

            // DTLS record header
            serverHello[0] = 0x16; // TLS record type 22 (Handshake)
            serverHello[1] = 0xFE; // DTLS 1.2 major version
            serverHello[2] = 0xFD; // DTLS 1.2 minor version
            serverHello[3] = (byte)((Epoch >> 8) & 0xff); // Epoch
            serverHello[4] = (byte)((Epoch) & 0xff); // Epoch
            serverHello[5] = (byte)((RecordSequenceNumber >> 40) & 0xff); // Record sequence number
            serverHello[6] = (byte)((RecordSequenceNumber >> 32) & 0xff); // Record sequence number
            serverHello[7] = (byte)((RecordSequenceNumber >> 24) & 0xff); // Record sequence number
            serverHello[8] = (byte)((RecordSequenceNumber >> 16) & 0xff); // Record sequence number
            serverHello[9] = (byte)((RecordSequenceNumber >> 8) & 0xff); // Record sequence number
            serverHello[10] = (byte)((RecordSequenceNumber) & 0xff); // Record sequence number
            serverHello[11] = 0x00; // Length (placeholder)
            serverHello[12] = 0x00; // Length (placeholder)

            // TLS handshake header
            serverHello[13] = 0x02; // Handshake type 1 (ServerHello)
            serverHello[14] = 0x00; // Length (placeholder)
            serverHello[15] = 0x00; // Length (placeholder)
            serverHello[16] = 0x00; // Length (placeholder)

            // Handshake reconstruction data
            ushort messageSequenceNumber = 0;
            uint fragmentOffset = 0;
            uint fragmentLength = 0;
            serverHello[17] = (byte)((messageSequenceNumber >> 8) & 0xff);
            serverHello[18] = (byte)(messageSequenceNumber & 0xff);
            serverHello[19] = (byte)((fragmentOffset >> 16) & 0xff);
            serverHello[20] = (byte)((fragmentOffset >> 8) & 0xff);
            serverHello[21] = (byte)(fragmentOffset & 0xff);
            serverHello[22] = (byte)((fragmentLength >> 16) & 0xff);
            serverHello[23] = (byte)((fragmentLength >> 8) & 0xff);
            serverHello[24] = (byte)(fragmentLength & 0xff);

            // Legacy server version
            serverHello[25] = 0xfe; // TLS 1.2 major version
            serverHello[26] = 0xfd; // TLS 1.2 minor version

            Buffer.BlockCopy(ServerRandom, 0, serverHello, 27, ServerRandom.Length);

            serverHello[59] = 0; // Legacy session ID

            serverHello[60] = (byte)((SelectedCipherSuite >> 8) & 0xff); // Cipher suite (placeholder)
            serverHello[61] = (byte)(SelectedCipherSuite & 0xff); // Cipher suite (placeholder)

            serverHello[62] = 0x00; // Compression method (null) - DTLS1.3 does not support compression

            // Extensions 
            int extensionsLength = Extensions.Select(x => x.CalculateLength()).Sum();
            serverHello[63] = (byte)((extensionsLength >> 8) & 0xff); // Extensions length in bytes (placeholder)
            serverHello[64] = (byte)(extensionsLength & 0xff); // Extensions length in bytes (placeholder)
            int nextExtensionOffset = 65; // Starting offset for extensions
            foreach (var extension in Extensions)
            {
                int extensionLength = extension.Write(nextExtensionOffset, serverHello);
                nextExtensionOffset += extensionLength;
            }

            // fill in lengths
            int length = nextExtensionOffset - 13; // Length of the TLS record (from Handshake type to end of extensions)
            serverHello[11] = (byte)((length >> 8) & 0xff); // Length (placeholder)
            serverHello[12] = (byte)(length & 0xff); // Length (placeholder)

            int tlsHandshakeLength = nextExtensionOffset - (13 + 4 + 8); // Length of the TLS handshake message (from Legacy client version to end of extensions)
            serverHello[14] = (byte)((tlsHandshakeLength >> 16) & 0xff); // Length (placeholder)
            serverHello[15] = (byte)((tlsHandshakeLength >> 8) & 0xff); // Length (placeholder)
            serverHello[16] = (byte)(tlsHandshakeLength & 0xff); // Length (placeholder)

            fragmentLength = (uint)tlsHandshakeLength;
            serverHello[22] = (byte)((fragmentLength >> 16) & 0xff);
            serverHello[23] = (byte)((fragmentLength >> 8) & 0xff);
            serverHello[24] = (byte)(fragmentLength & 0xff);

            Bytes = serverHello.Take(nextExtensionOffset).ToArray();

            return Bytes;
        }
    }

    public class ServerKeyShareExtension : ITlsExtension
    {
        public ushort KeyType { get; private set; }
        public byte[] PublicKey { get; private set; }

        public ServerKeyShareExtension()
        { }

        public ServerKeyShareExtension(ushort keyType, byte[] publicKey)
        {
            this.KeyType = keyType;
            this.PublicKey = publicKey;
        }

        public int CalculateLength()
        {
            return 8 + this.PublicKey.Length;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x0033) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extensionLength = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            this.KeyType = (ushort)((source[offset + 4] << 8) | source[offset + 5]);
            ushort publicKeyLength = (ushort)((source[offset + 6] << 8) | source[offset + 7]);

            if (source.Length < offset + 8 + publicKeyLength)
                throw new ArgumentException("Buffer too small to contain the declared public key.");

            this.PublicKey = new byte[publicKeyLength];
            Buffer.BlockCopy(source, offset + 8, this.PublicKey, 0, publicKeyLength);

            return 8 + publicKeyLength;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00; // Extension type 0x0033 (KeyShare)
            destination[offset + 1] = 0x33; // Extension type 0x0033 (KeyShare)

            int extensionLength = 2 + 2 + this.PublicKey.Length;
            destination[offset + 2] = (byte)((extensionLength >> 8) & 0xff); // Extension length 
            destination[offset + 3] = (byte)(extensionLength & 0xff); // Extension length 

            destination[offset + 4] = (byte)((KeyType >> 8) & 0xff); // assigned value for x25519 (key exchange via curve25519)
            destination[offset + 5] = (byte)(KeyType & 0xff); // assigned value for x25519 (key exchange via curve25519)

            destination[offset + 6] = (byte)((this.PublicKey.Length >> 8) & 0xff); //  bytes of public key follows
            destination[offset + 7] = (byte)(this.PublicKey.Length & 0xff); //  bytes of public key follows
            Buffer.BlockCopy(this.PublicKey, 0, destination, offset + 8, this.PublicKey.Length);

            return 8 + this.PublicKey.Length; // total length of the extension data
        }
    }

    public class ServerSupportedVersions : ITlsExtension
    {
        public ServerSupportedVersions()
        { }

        public int CalculateLength()
        {
            return 6;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (source.Length < offset + 6) throw new ArgumentException("Not enough data for SupportedVersions extension.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x002b) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extLen = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            if (extLen != 2) throw new InvalidDataException("Invalid SupportedVersions extension length.");

            byte major = source[offset + 4];
            byte minor = source[offset + 5];

            if (major != 0xFE || minor != 0xFC)
                throw new InvalidDataException($"Unsupported DTLS version: 0x{major:X2} 0x{minor:X2}");

            return 6;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x2b; // Extension type 0x002b (Supported Versions)
            destination[offset + 2] = 0x00; // Extension length
            destination[offset + 3] = 0x02; // Length of versions list (2 bytes)
            destination[offset + 4] = 0xfe; // DTLS 1.3 major version
            destination[offset + 5] = 0xfc; // DTLS 1.3 minor version
            return 6; // total length of the extension data
        }
    }

    public class CookieExtension : ITlsExtension
    {
        public byte[] Cookie { get; set; }

        public CookieExtension()
        { }

        public CookieExtension(byte[] cookie)
        {
            this.Cookie = cookie ?? throw new ArgumentNullException(nameof(cookie));
        }

        public int CalculateLength()
        {
            return 6 + this.Cookie.Length;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x002c) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extLen = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            ushort cookieLen = (ushort)((source[offset + 4] << 8) | source[offset + 5]);
            
            this.Cookie = new byte[cookieLen];
            Buffer.BlockCopy(source, offset + 6, this.Cookie, 0, cookieLen);

            return 6 + this.Cookie.Length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x2c; // Extension type 0x002c (Cookie)
            int length = 2 + this.Cookie.Length;
            destination[offset + 2] = (byte)((length >> 8) & 0xff); // Extension length
            destination[offset + 3] = (byte)(length & 0xff); // Extension length
            destination[offset + 4] = (byte)((this.Cookie.Length >> 8) & 0xff); // Cookie length
            destination[offset + 5] = (byte)(this.Cookie.Length & 0xff); // Cookie length
            Buffer.BlockCopy(this.Cookie, 0, destination, offset + 6, this.Cookie.Length);
            return 6 + this.Cookie.Length; // total length of the extension data
        }
    }
}
