using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class ClientHelloDatagram : IHandshakeDatagram
    {
        public List<ushort> CipherSuites = new List<ushort>(Dtls13CipherSuite.Supported);
        public byte[] PublicKey { get; private set; }
        public List<ITlsExtension> Extensions { get; private set; }
        public int Epoch { get; set; } = 0;
        public int RecordSequenceNumber { get; set; }

        /// <summary>Handshake message_seq (0 for the first ClientHello, 1 after a HelloRetryRequest).</summary>
        public int SequenceNumber { get; set; } = 0;
        public byte[] ClientRandom { get; set; } = null;
        public byte[] LegacySessionId { get; set; } = Array.Empty<byte>();
        public byte[] LegacyCookie { get; set; } = Array.Empty<byte>();
        public byte[] Bytes { get; private set; }

        public ClientHelloDatagram()
        { }

        public ClientHelloDatagram(byte[] publicKey)
        {
            PublicKey = publicKey;
            ClientRandom = Dtls13CryptoUtils.GenerateRandom(32);
            Extensions = new List<ITlsExtension>(GetDefaultExtensions(publicKey));
        }

        private static ITlsExtension[] GetDefaultExtensions(byte[] publicKey)
        {
            return new ITlsExtension[]
            {
                new ClientKeyShareExtension(0x001d, publicKey),
                new ClientSupportedVersions(),
                new ClientSignatureAlgorithms(new ushort[] { 0x0603, 0x0503, 0x0403, 0x0203, 0x0806, 0x080b, 0x0805, 0x080a, 0x0804, 0x0809, 0x0601, 0x0501, 0x0401, 0x0301, 0x0201 }),
                new EncryptThenMac(),
                new SupportedGroups(new ushort[] { 0x001d }) // assigned value for the curve "x25519"
            };
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 67) throw new ArgumentException("Buffer too small to be a valid ClientHello.");
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");

            Bytes = bytes.ToArray();
            Epoch = (bytes[3] << 8) | bytes[4];

            long seq = 0;
            for (int i = 5; i <= 10; i++)
            {
                seq = (seq << 8) | bytes[i];
            }
            RecordSequenceNumber = (int)seq;
            SequenceNumber = (bytes[17] << 8) | bytes[18];

            if (bytes.Length < 27 + 32) throw new ArgumentException("Buffer too small for ClientRandom.");
            ClientRandom = new byte[32];
            Buffer.BlockCopy(bytes, 27, ClientRandom, 0, 32);

            int p = 59;
            int sessionIdLen = bytes[p++];
            if (sessionIdLen > 32 || bytes.Length < p + sessionIdLen + 1) throw new DtlsException(AlertDescription.DecodeError, "Invalid legacy_session_id.");
            LegacySessionId = bytes.AsSpan(p, sessionIdLen).ToArray();
            p += sessionIdLen;

            int cookieLen = bytes[p++];
            if (bytes.Length < p + cookieLen + 2) throw new DtlsException(AlertDescription.DecodeError, "Invalid legacy_cookie.");
            LegacyCookie = bytes.AsSpan(p, cookieLen).ToArray();
            p += cookieLen;

            int cipherSuitesLen = (bytes[p] << 8) | bytes[p + 1];
            p += 2;
            if ((cipherSuitesLen & 1) != 0 || bytes.Length < p + cipherSuitesLen + 2) throw new DtlsException(AlertDescription.DecodeError, "Invalid cipher suites.");

            CipherSuites = new List<ushort>();
            for (int i = 0; i < cipherSuitesLen; i += 2)
            {
                ushort suite = (ushort)((bytes[p + i] << 8) | bytes[p + i + 1]);
                CipherSuites.Add(suite);
            }

            int compLenOffset = p + cipherSuitesLen;
            if (bytes.Length <= compLenOffset) throw new ArgumentException("Buffer truncated at compression methods length.");
            int compMethodsLen = bytes[compLenOffset];
            int compMethodsEnd = compLenOffset + 1 + compMethodsLen;

            if (bytes.Length < compMethodsEnd + 2) throw new ArgumentException("Buffer truncated before extensions length.");

            int extLenOffset = compMethodsEnd;
            int extensionsLength = (bytes[extLenOffset] << 8) | bytes[extLenOffset + 1];
            int extensionsStart = extLenOffset + 2;
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
                    ServerNameExtension.Type => new ServerNameExtension(),
                    AlpnExtension.Type => new AlpnExtension(),
                    ConnectionIdExtension.Type => new ConnectionIdExtension(),
                    0x0033 => new ClientKeyShareExtension(),
                    0x002b => new ClientSupportedVersions(),
                    0x000d => new ClientSignatureAlgorithms(),
                    0x0016 => new EncryptThenMac(),
                    0x000a => new SupportedGroups(),
                    0x002c => new CookieExtension(),
                    0x000e => new UseSrtpExtension(),
                    PskKeyExchangeModesExtension.Type => new PskKeyExchangeModesExtension(),
                    ClientPreSharedKeyExtension.Type => new ClientPreSharedKeyExtension(),
                    EarlyDataExtension.Type => new EarlyDataExtension(),
                    _ => new UnknownExtension()
                };

                if (matching != null)
                {
                    int consumed = matching.Read(pos, bytes);
                    if (consumed <= 0) throw new InvalidDataException($"Extension parser for 0x{extType:X4} returned invalid consumed length.");
                    pos += consumed;
                    Extensions.Add(matching);

                    if(matching is ClientKeyShareExtension keyShareExt)
                    {
                        PublicKey = keyShareExt.GetKeyShare(0x001d); // x25519 is the only group implemented
                    }
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
            byte[] clientHello = new byte[2048];

            // DTLS record header
            clientHello[0] = 0x16; // TLS record type 22 (Handshake)
            clientHello[1] = 0xFE; // DTLS 1.2 major version
            clientHello[2] = 0xFD; // DTLS 1.2 minor version
            clientHello[3] = (byte)((Epoch >> 8) & 0xff); // Epoch
            clientHello[4] = (byte)((Epoch) & 0xff); // Epoch
            clientHello[5] = (byte)(((long)RecordSequenceNumber >> 40) & 0xff); // Record sequence number
            clientHello[6] = (byte)(((long)RecordSequenceNumber >> 32) & 0xff); // Record sequence number
            clientHello[7] = (byte)((RecordSequenceNumber >> 24) & 0xff); // Record sequence number
            clientHello[8] = (byte)((RecordSequenceNumber >> 16) & 0xff); // Record sequence number
            clientHello[9] = (byte)((RecordSequenceNumber >> 8) & 0xff); // Record sequence number
            clientHello[10] = (byte)((RecordSequenceNumber) & 0xff); // Record sequence number
            clientHello[11] = 0x00; // Length (placeholder)
            clientHello[12] = 0x00; // Length (placeholder)

            // TLS handshake header
            clientHello[13] = 0x01; // Handshake type 1 (ClientHello)
            clientHello[14] = 0x00; // Length (placeholder)
            clientHello[15] = 0x00; // Length (placeholder)
            clientHello[16] = 0x00; // Length (placeholder)

            // Handshake reconstruction data
            ushort messageSequenceNumber = (ushort)SequenceNumber;
            uint fragmentOffset = 0;
            uint fragmentLength = 0;
            clientHello[17] = (byte)((messageSequenceNumber >> 8) & 0xff);
            clientHello[18] = (byte)(messageSequenceNumber & 0xff);
            clientHello[19] = (byte)((fragmentOffset >> 16) & 0xff);
            clientHello[20] = (byte)((fragmentOffset >> 8) & 0xff);
            clientHello[21] = (byte)(fragmentOffset & 0xff);
            clientHello[22] = (byte)((fragmentLength >> 16) & 0xff);
            clientHello[23] = (byte)((fragmentLength >> 8) & 0xff);
            clientHello[24] = (byte)(fragmentLength & 0xff);

            // Legacy client version
            clientHello[25] = 0xfe; // TLS 1.2 major version
            clientHello[26] = 0xfd; // TLS 1.2 minor version

            Buffer.BlockCopy(ClientRandom, 0, clientHello, 27, ClientRandom.Length);

            int p = 59;
            clientHello[p++] = (byte)LegacySessionId.Length;
            Buffer.BlockCopy(LegacySessionId, 0, clientHello, p, LegacySessionId.Length);
            p += LegacySessionId.Length;
            clientHello[p++] = (byte)LegacyCookie.Length; // MUST be empty for DTLS 1.3-only clients
            Buffer.BlockCopy(LegacyCookie, 0, clientHello, p, LegacyCookie.Length);
            p += LegacyCookie.Length;

            clientHello[p++] = (byte)((CipherSuites.Count * 2 >> 8) & 0xff); // Cipher Suites length
            clientHello[p++] = (byte)((CipherSuites.Count * 2) & 0xff); // Cipher Suites length
            for (int i = 0; i < CipherSuites.Count; i++)
            {
                clientHello[p++] = (byte)((CipherSuites[i] >> 8) & 0xff);
                clientHello[p++] = (byte)(CipherSuites[i] & 0xff);
            }

            // DTLS 1.3 no longer allows compression
            clientHello[p++] = 0x01; // Compression Methods length
            clientHello[p++] = 0x00; // Compression Method 0 (null)

            // Extensions
            int extensionsLength = Extensions.Select(x => x.CalculateLength()).Sum();
            clientHello[p++] = (byte)((extensionsLength >> 8) & 0xff); // Extensions length in bytes
            clientHello[p++] = (byte)(extensionsLength & 0xff); // Extensions length in bytes
            int nextExtensionOffset = p; // Starting offset for extensions
            foreach (var extension in Extensions)
            {
                int extensionLength = extension.Write(nextExtensionOffset, clientHello);
                nextExtensionOffset += extensionLength;
            }

            // fill in lengths
            int length = nextExtensionOffset - 13; // Length of the TLS record (from Handshake type to end of extensions)
            clientHello[11] = (byte)((length >> 8) & 0xff); // Length (placeholder)
            clientHello[12] = (byte)(length & 0xff); // Length (placeholder)

            int tlsHandshakeLength = nextExtensionOffset - (13 + 4 + 8); // Length of the TLS handshake message (from Legacy client version to end of extensions)
            clientHello[14] = (byte)((tlsHandshakeLength >> 16) & 0xff); // Length (placeholder)
            clientHello[15] = (byte)((tlsHandshakeLength >> 8) & 0xff); // Length (placeholder)
            clientHello[16] = (byte)(tlsHandshakeLength & 0xff); // Length (placeholder)

            fragmentLength = (uint)tlsHandshakeLength;
            clientHello[22] = (byte)((fragmentLength >> 16) & 0xff);
            clientHello[23] = (byte)((fragmentLength >> 8) & 0xff);
            clientHello[24] = (byte)(fragmentLength & 0xff);

            Bytes = clientHello.Take(nextExtensionOffset).ToArray();

            return Bytes;
        }
    }

   

    public class ClientKeyShareExtension : ITlsExtension
    {
        /// <summary>All offered key shares in client preference order.</summary>
        public List<(ushort Group, byte[] KeyExchange)> Entries { get; private set; } = new();

        // Convenience accessors for the first offered share.
        public ushort KeyType => Entries.Count > 0 ? Entries[0].Group : (ushort)0;
        public byte[] PublicKey => Entries.Count > 0 ? Entries[0].KeyExchange : null;

        public ClientKeyShareExtension()
        { }

        public ClientKeyShareExtension(ushort keyType, byte[] publicKey)
        {
            Entries.Add((keyType, publicKey));
        }

        public byte[] GetKeyShare(ushort group)
        {
            foreach (var entry in Entries)
                if (entry.Group == group)
                    return entry.KeyExchange;
            return null;
        }

        public int CalculateLength()
        {
            return 6 + Entries.Sum(e => 4 + e.KeyExchange.Length);
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (source.Length < offset + 6) throw new DtlsException(AlertDescription.DecodeError, "Truncated key_share extension.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x0033) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            int extensionLength = (source[offset + 2] << 8) | source[offset + 3];
            int listLength = (source[offset + 4] << 8) | source[offset + 5];
            if (extensionLength != 2 + listLength || source.Length < offset + 4 + extensionLength)
                throw new DtlsException(AlertDescription.DecodeError, "Inconsistent key_share extension length.");

            Entries = new();
            int pos = offset + 6;
            int end = pos + listLength;
            while (pos < end)
            {
                if (pos + 4 > end) throw new DtlsException(AlertDescription.DecodeError, "Truncated key_share entry.");
                ushort group = (ushort)((source[pos] << 8) | source[pos + 1]);
                int keyLength = (source[pos + 2] << 8) | source[pos + 3];
                pos += 4;
                if (keyLength == 0 || pos + keyLength > end) throw new DtlsException(AlertDescription.DecodeError, "Invalid key_share entry.");
                Entries.Add((group, source.AsSpan(pos, keyLength).ToArray()));
                pos += keyLength;
            }

            return 4 + extensionLength;
        }

        public int Write(int offset, byte[] destination)
        {
            int listLength = Entries.Sum(e => 4 + e.KeyExchange.Length);
            int extensionLength = 2 + listLength;

            destination[offset] = 0x00; // Extension type 0x0033 (KeyShare)
            destination[offset + 1] = 0x33;
            destination[offset + 2] = (byte)((extensionLength >> 8) & 0xff);
            destination[offset + 3] = (byte)(extensionLength & 0xff);
            destination[offset + 4] = (byte)((listLength >> 8) & 0xff);
            destination[offset + 5] = (byte)(listLength & 0xff);

            int pos = offset + 6;
            foreach (var (group, key) in Entries)
            {
                destination[pos++] = (byte)(group >> 8);
                destination[pos++] = (byte)group;
                destination[pos++] = (byte)(key.Length >> 8);
                destination[pos++] = (byte)key.Length;
                Buffer.BlockCopy(key, 0, destination, pos, key.Length);
                pos += key.Length;
            }

            return 4 + extensionLength;
        }
    }

    public class ClientSupportedVersions : ITlsExtension
    {
        public const ushort Dtls13 = 0xFEFC;
        public const ushort Dtls12 = 0xFEFD;

        public List<ushort> Versions { get; private set; } = new List<ushort> { Dtls13 };

        public ClientSupportedVersions()
        { }

        public int CalculateLength()
        {
            return 5 + 2 * Versions.Count;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (source.Length < offset + 5) throw new DtlsException(AlertDescription.DecodeError, "Truncated supported_versions extension.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x002b) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            int extLen = (source[offset + 2] << 8) | source[offset + 3];
            int listLen = source[offset + 4];
            if (extLen != 1 + listLen || (listLen & 1) != 0 || listLen == 0 || source.Length < offset + 4 + extLen)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid supported_versions extension.");

            Versions = new List<ushort>();
            for (int i = 0; i < listLen; i += 2)
                Versions.Add((ushort)((source[offset + 5 + i] << 8) | source[offset + 6 + i]));

            return 4 + extLen;
        }

        public int Write(int offset, byte[] destination)
        {
            int listLen = 2 * Versions.Count;
            destination[offset] = 0x00;
            destination[offset + 1] = 0x2b; // Extension type 0x002b (Supported Versions)
            destination[offset + 2] = (byte)((1 + listLen) >> 8);
            destination[offset + 3] = (byte)(1 + listLen);
            destination[offset + 4] = (byte)listLen;
            for (int i = 0; i < Versions.Count; i++)
            {
                destination[offset + 5 + 2 * i] = (byte)(Versions[i] >> 8);
                destination[offset + 6 + 2 * i] = (byte)Versions[i];
            }
            return 5 + listLen;
        }
    }

    public class ClientSignatureAlgorithms : ITlsExtension
    {
        public ushort[] SignatureAlgorithms { get; private set; }

        public ClientSignatureAlgorithms()
        { }

        public ClientSignatureAlgorithms(ushort[] signatureAlgorithms)
        {
            this.SignatureAlgorithms = signatureAlgorithms;
        }

        public int CalculateLength()
        {
            return 6 + 2 * this.SignatureAlgorithms.Length;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (source.Length < offset + 6) throw new ArgumentException("Not enough data for SignatureAlgorithms extension header.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x000d) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extensionLength = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            ushort algorithmsListLength = (ushort)((source[offset + 4] << 8) | source[offset + 5]);

            // extensionLength should equal 2 (algorithms list length field) + algorithmsListLength
            if (extensionLength != (ushort)(2 + algorithmsListLength))
                throw new InvalidDataException("Inconsistent extension length for SignatureAlgorithms extension.");

            if ((algorithmsListLength & 1) != 0)
                throw new InvalidDataException("Algorithms list length must be even (each algorithm is 2 bytes).");

            if (source.Length < offset + 6 + algorithmsListLength)
                throw new ArgumentException("Buffer too small to contain the declared signature algorithms.");

            int count = algorithmsListLength / 2;
            this.SignatureAlgorithms = new ushort[count];
            for (int i = 0; i < count; i++)
            {
                SignatureAlgorithms[i] = (ushort)((source[offset + 6 + i * 2] << 8) | source[offset + 6 + i * 2 + 1]);
            }

            // bytes consumed: 6 (header) + algorithmsListLength
            return 6 + algorithmsListLength;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x0d; // extension type 0x000d (Signature Algorithms)

            int extensionLength = 2 + 2 * this.SignatureAlgorithms.Length;
            destination[offset + 2] = (byte)((extensionLength >> 8) & 0xff); // extension length
            destination[offset + 3] = (byte)((extensionLength) & 0xff); // extension length

            int algorithmsListLength = 2 * this.SignatureAlgorithms.Length;
            destination[offset + 4] = (byte)((algorithmsListLength >> 8) & 0xff); // algorithms list length
            destination[offset + 5] = (byte)((algorithmsListLength) & 0xff); // algorithms list length

            for (int i = 0; i < this.SignatureAlgorithms.Length; i++)
            {
                destination[offset + 6 + i * 2] = (byte)((this.SignatureAlgorithms[i] >> 8) & 0xff);
                destination[offset + 7 + i * 2] = (byte)(this.SignatureAlgorithms[i] & 0xff);
            }

            return 6 + 2 * this.SignatureAlgorithms.Length;
        }
    }

    public class EncryptThenMac : ITlsExtension
    {
        public EncryptThenMac()
        {  }

        public int CalculateLength()
        {
            return 4;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (source.Length < offset + 4) throw new ArgumentException("Not enough data for EncryptThenMac extension.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x0016) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extLen = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            if (extLen != 0) throw new InvalidDataException("Encrypt-then-MAC extension must have zero length.");

            return 4; // header only, no payload
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x16; // Extension type 0x0016 (Encrypt-then-MAC)
            destination[offset + 2] = 0x00; // Extension length
            destination[offset + 3] = 0x00; // Extension length (0 bytes of data)
            return 4;
        }
    }

    public class SupportedGroups : ITlsExtension
    {
        public ushort[] Groups { get; private set; }

        public SupportedGroups()
        { }

        public SupportedGroups(ushort[] supportedGroups)
        {
            this.Groups = supportedGroups;
        }

        public int CalculateLength()
        {
            return 6 + 2 * this.Groups.Length;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (source.Length < offset + 6) throw new ArgumentException("Not enough data for SupportedGroups extension.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x000a) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extensionLength = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            ushort groupListLength = (ushort)((source[offset + 4] << 8) | source[offset + 5]);

            // extensionLength should equal 2 (group list length field) + groupListLength
            if (extensionLength != (ushort)(2 + groupListLength))
                throw new InvalidDataException("Inconsistent extension length for SupportedGroups extension.");

            if ((groupListLength & 1) != 0)
                throw new InvalidDataException("Group list length must be even (each group id is 2 bytes).");

            if (source.Length < offset + 6 + groupListLength)
                throw new ArgumentException("Buffer too small to contain the declared supported groups.");

            int count = groupListLength / 2;
            this.Groups = new ushort[count];
            for (int i = 0; i < count; i++)
            {
                this.Groups[i] = (ushort)((source[offset + 6 + i * 2] << 8) | source[offset + 6 + i * 2 + 1]);
            }

            return 6 + groupListLength;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x0a; // extension type 0x000a (Supported Groups)

            int extensionLength = 2 + 2 * this.Groups.Length;
            destination[offset + 2] = (byte)((extensionLength >> 8) & 0xff); // extension length
            destination[offset + 3] = (byte)((extensionLength) & 0xff); // extension length

            int groupListLength = 2 * this.Groups.Length;
            destination[offset + 4] = (byte)((groupListLength >> 8) & 0xff); // group list length
            destination[offset + 5] = (byte)((groupListLength) & 0xff); // group list length

            for (int i = 0; i < this.Groups.Length; i++)
            {
                destination[offset + 6 + i * 2] = (byte)((this.Groups[i] >> 8) & 0xff);
                destination[offset + 7 + i * 2] = (byte)(this.Groups[i] & 0xff);
            }

            return 6 + 2 * this.Groups.Length;
        }
    }

    public class UseSrtpExtension : ITlsExtension
    {
        public ushort[] SrtpProtectionProfiles { get; private set; }
        public byte[] MasterKeyIdentifier { get; private set; }

        public UseSrtpExtension()
        {
            SrtpProtectionProfiles = new ushort[] { 0x0001, 0x0007 }; // SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AEAD_AES_128_GCM
            MasterKeyIdentifier = new byte[0]; // Empty MKI
        }

        public UseSrtpExtension(ushort[] srtpProtectionProfiles, byte[] masterKeyIdentifier = null)
        {
            this.SrtpProtectionProfiles = srtpProtectionProfiles;
            this.MasterKeyIdentifier = masterKeyIdentifier ?? new byte[0];
        }

        public int CalculateLength()
        {
            // 4 (extension header) + 2 (profile list length) + 2*profiles + 1 (mki length) + mki data
            return 4 + 2 + 2 * this.SrtpProtectionProfiles.Length + 1 + this.MasterKeyIdentifier.Length;
        }

        public int Read(int offset, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (source.Length < offset + 6) throw new ArgumentException("Not enough data for UseSrtp extension header.");

            ushort extType = (ushort)((source[offset] << 8) | source[offset + 1]);
            if (extType != 0x000e) throw new InvalidDataException($"Unexpected extension type: 0x{extType:X4}");

            ushort extensionLength = (ushort)((source[offset + 2] << 8) | source[offset + 3]);
            ushort profileListLength = (ushort)((source[offset + 4] << 8) | source[offset + 5]);

            if ((profileListLength & 1) != 0)
                throw new InvalidDataException("Profile list length must be even (each profile is 2 bytes).");

            if (source.Length < offset + 6 + profileListLength + 1)
                throw new ArgumentException("Buffer too small to contain the declared SRTP profiles.");

            int profileCount = profileListLength / 2;
            this.SrtpProtectionProfiles = new ushort[profileCount];
            for (int i = 0; i < profileCount; i++)
            {
                SrtpProtectionProfiles[i] = (ushort)((source[offset + 6 + i * 2] << 8) | source[offset + 6 + i * 2 + 1]);
            }

            int mkiLengthOffset = offset + 6 + profileListLength;
            byte mkiLength = source[mkiLengthOffset];

            if (source.Length < mkiLengthOffset + 1 + mkiLength)
                throw new ArgumentException("Buffer too small to contain the declared MKI.");

            this.MasterKeyIdentifier = new byte[mkiLength];
            if (mkiLength > 0)
            {
                Buffer.BlockCopy(source, mkiLengthOffset + 1, this.MasterKeyIdentifier, 0, mkiLength);
            }

            // Validate extension length matches
            int expectedExtensionLength = 2 + profileListLength + 1 + mkiLength;
            if (extensionLength != expectedExtensionLength)
                throw new InvalidDataException("Inconsistent extension length for UseSrtp extension.");

            return 4 + expectedExtensionLength;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x0e; // extension type 0x000e (use_srtp, RFC 5764)

            int extensionLength = 2 + 2 * this.SrtpProtectionProfiles.Length + 1 + this.MasterKeyIdentifier.Length;
            destination[offset + 2] = (byte)((extensionLength >> 8) & 0xff); // extension length
            destination[offset + 3] = (byte)(extensionLength & 0xff); // extension length

            int profileListLength = 2 * this.SrtpProtectionProfiles.Length;
            destination[offset + 4] = (byte)((profileListLength >> 8) & 0xff); // profile list length
            destination[offset + 5] = (byte)(profileListLength & 0xff); // profile list length

            for (int i = 0; i < this.SrtpProtectionProfiles.Length; i++)
            {
                destination[offset + 6 + i * 2] = (byte)((this.SrtpProtectionProfiles[i] >> 8) & 0xff);
                destination[offset + 7 + i * 2] = (byte)(this.SrtpProtectionProfiles[i] & 0xff);
            }

            int mkiLengthOffset = offset + 6 + profileListLength;
            destination[mkiLengthOffset] = (byte)this.MasterKeyIdentifier.Length;

            if (this.MasterKeyIdentifier.Length > 0)
            {
                Buffer.BlockCopy(this.MasterKeyIdentifier, 0, destination, mkiLengthOffset + 1, this.MasterKeyIdentifier.Length);
            }

            return 4 + extensionLength;
        }
    }
}
