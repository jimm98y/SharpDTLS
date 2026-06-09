using SharpDTLS;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
{
    // DTLS 1.2 ClientHello.
    // Cookie lives in the handshake body (offset 60), not as an extension (unlike DTLS 1.3).
    public class ClientHelloDatagram : IDatagram
    {
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        public List<ushort> CipherSuites { get; set; } = new List<ushort> { 0xC02F, 0xC030 };
        public List<ITlsExtension> Extensions { get; private set; } = new List<ITlsExtension>();
        public byte[] ClientRandom { get; set; }
        public byte[] Cookie { get; set; } = Array.Empty<byte>();
        public int Epoch { get; set; } = 0;
        public int RecordSequenceNumber { get; set; } = 0;
        public ushort MessageSequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public ClientHelloDatagram() { }

        public ClientHelloDatagram(bool includeSrtp = true)
        {
            ClientRandom = CryptoUtils.GenerateRandom(32);
            Extensions = new List<ITlsExtension>(GetDefaultExtensions(includeSrtp));
        }

        private static ITlsExtension[] GetDefaultExtensions(bool includeSrtp)
        {
            var list = new List<ITlsExtension>
            {
                new SupportedGroupsExtension(new ushort[] { 0x001d, 0x0017 }), // x25519, secp256r1
                new EcPointFormatsExtension(new byte[] { 0x00 }),               // uncompressed
                new SignatureAlgorithmsExtension(new ushort[]
                {
                    0x0401, // rsa_pkcs1_sha256
                    0x0501, // rsa_pkcs1_sha384
                    0x0601, // rsa_pkcs1_sha512
                    0x0403, // ecdsa_secp256r1_sha256
                    0x0503, // ecdsa_secp384r1_sha384
                    0x0804, // rsa_pss_rsae_sha256
                }),
                new EncryptThenMacExtension(),
            };
            if (includeSrtp)
                list.Add(new UseSrtpExtension(new ushort[] { 0x0001, 0x0007 }));
            return list.ToArray();
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 68) throw new ArgumentException("Buffer too small for ClientHello.");
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x01) throw new InvalidDataException("Not a ClientHello.");

            Bytes = bytes.ToArray();
            Epoch = (bytes[3] << 8) | bytes[4];
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            ClientRandom = new byte[32];
            Buffer.BlockCopy(bytes, 27, ClientRandom, 0, 32);

            // bytes[59] = session_id_length (always 0 in our implementation)
            int sessionIdLen = bytes[59];
            int pos = 60 + sessionIdLen;

            // DTLS cookie field
            int cookieLen = bytes[pos++];
            Cookie = new byte[cookieLen];
            if (cookieLen > 0)
                Buffer.BlockCopy(bytes, pos, Cookie, 0, cookieLen);
            pos += cookieLen;

            int cipherSuitesLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            CipherSuites = new List<ushort>();
            for (int i = 0; i < cipherSuitesLen; i += 2)
                CipherSuites.Add((ushort)((bytes[pos + i] << 8) | bytes[pos + i + 1]));
            pos += cipherSuitesLen;

            int compLen = bytes[pos++];
            pos += compLen;

            if (pos + 2 > bytes.Length) return;
            int extLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            int extEnd = pos + extLen;

            Extensions = new List<ITlsExtension>();
            while (pos < extEnd)
            {
                if (pos + 4 > bytes.Length) break;
                ushort extType = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                ushort extDataLen = (ushort)((bytes[pos + 2] << 8) | bytes[pos + 3]);

                ITlsExtension ext = extType switch
                {
                    0x000a => new SupportedGroupsExtension(),
                    0x000b => new EcPointFormatsExtension(),
                    0x000d => new SignatureAlgorithmsExtension(),
                    0x0016 => new EncryptThenMacExtension(),
                    0x000f => new UseSrtpExtension(),
                    _ => null
                };

                if (ext != null)
                {
                    pos += ext.Read(pos, bytes);
                    Extensions.Add(ext);
                }
                else
                {
                    pos += 4 + extDataLen;
                }
            }
        }

        public byte[] ToBytes()
        {
            byte[] buf = new byte[2048];

            // DTLS record header
            buf[0] = 0x16;   // Handshake
            buf[1] = 0xFE;   // DTLS 1.2
            buf[2] = 0xFD;
            buf[3] = (byte)((Epoch >> 8) & 0xFF);
            buf[4] = (byte)(Epoch & 0xFF);
            buf[5]  = (byte)((RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)((RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            buf[11] = 0x00; // length placeholder
            buf[12] = 0x00;

            // Handshake header
            buf[13] = 0x01; // ClientHello
            buf[14] = 0x00; // length placeholder
            buf[15] = 0x00;
            buf[16] = 0x00;
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; // fragment offset
            buf[20] = 0x00;
            buf[21] = 0x00;
            buf[22] = 0x00; // fragment length placeholder
            buf[23] = 0x00;
            buf[24] = 0x00;

            // ClientHello body
            buf[25] = 0xFE; // client_version DTLS 1.2
            buf[26] = 0xFD;
            Buffer.BlockCopy(ClientRandom, 0, buf, 27, 32);

            int p = 59;
            buf[p++] = 0x00; // session_id_length = 0

            // DTLS cookie
            buf[p++] = (byte)Cookie.Length;
            if (Cookie.Length > 0)
            {
                Buffer.BlockCopy(Cookie, 0, buf, p, Cookie.Length);
                p += Cookie.Length;
            }

            // Cipher suites
            int csLen = CipherSuites.Count * 2;
            buf[p++] = (byte)((csLen >> 8) & 0xFF);
            buf[p++] = (byte)(csLen & 0xFF);
            foreach (var cs in CipherSuites)
            {
                buf[p++] = (byte)((cs >> 8) & 0xFF);
                buf[p++] = (byte)(cs & 0xFF);
            }

            // Compression methods
            buf[p++] = 0x01;
            buf[p++] = 0x00; // null

            // Extensions
            int extTotalLen = Extensions.Sum(e => e.CalculateLength());
            buf[p++] = (byte)((extTotalLen >> 8) & 0xFF);
            buf[p++] = (byte)(extTotalLen & 0xFF);
            foreach (var ext in Extensions)
                p += ext.Write(p, buf);

            // Fill lengths
            int recordBodyLen = p - 13;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            int hsBodyLen = p - 13 - 4 - 8; // skip type(1)+len(3)+seq(2)+frag_off(3)+frag_len(3)
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[22] = buf[14]; buf[23] = buf[15]; buf[24] = buf[16]; // frag_length = length

            Bytes = buf.Take(p).ToArray();
            return Bytes;
        }
    }

    // ── Extensions ──────────────────────────────────────────────────────────────

    public class SupportedGroupsExtension : ITlsExtension
    {
        public ushort[] Groups { get; private set; }

        public SupportedGroupsExtension() { }
        public SupportedGroupsExtension(ushort[] groups) { Groups = groups; }

        public int CalculateLength() => 6 + 2 * Groups.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen     = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            ushort listLen    = (ushort)((src[offset + 4] << 8) | src[offset + 5]);
            int count = listLen / 2;
            Groups = new ushort[count];
            for (int i = 0; i < count; i++)
                Groups[i] = (ushort)((src[offset + 6 + i * 2] << 8) | src[offset + 7 + i * 2]);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0A; // 0x000a
            int listLen = Groups.Length * 2;
            int extLen  = 2 + listLen;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)((listLen >> 8) & 0xFF);
            dst[offset + 5] = (byte)(listLen & 0xFF);
            for (int i = 0; i < Groups.Length; i++)
            {
                dst[offset + 6 + i * 2]     = (byte)((Groups[i] >> 8) & 0xFF);
                dst[offset + 7 + i * 2]     = (byte)(Groups[i] & 0xFF);
            }
            return 6 + listLen;
        }
    }

    public class EcPointFormatsExtension : ITlsExtension
    {
        public byte[] Formats { get; private set; }

        public EcPointFormatsExtension() { }
        public EcPointFormatsExtension(byte[] formats) { Formats = formats; }

        public int CalculateLength() => 5 + Formats.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen  = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            byte   listLen = src[offset + 4];
            Formats = new byte[listLen];
            Buffer.BlockCopy(src, offset + 5, Formats, 0, listLen);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0B; // 0x000b
            int extLen = 1 + Formats.Length;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)Formats.Length;
            Buffer.BlockCopy(Formats, 0, dst, offset + 5, Formats.Length);
            return 5 + Formats.Length;
        }
    }

    public class SignatureAlgorithmsExtension : ITlsExtension
    {
        public ushort[] Algorithms { get; private set; }

        public SignatureAlgorithmsExtension() { }
        public SignatureAlgorithmsExtension(ushort[] algorithms) { Algorithms = algorithms; }

        public int CalculateLength() => 6 + 2 * Algorithms.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen  = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            ushort listLen = (ushort)((src[offset + 4] << 8) | src[offset + 5]);
            int count = listLen / 2;
            Algorithms = new ushort[count];
            for (int i = 0; i < count; i++)
                Algorithms[i] = (ushort)((src[offset + 6 + i * 2] << 8) | src[offset + 7 + i * 2]);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0D; // 0x000d
            int listLen = Algorithms.Length * 2;
            int extLen  = 2 + listLen;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)((listLen >> 8) & 0xFF);
            dst[offset + 5] = (byte)(listLen & 0xFF);
            for (int i = 0; i < Algorithms.Length; i++)
            {
                dst[offset + 6 + i * 2]     = (byte)((Algorithms[i] >> 8) & 0xFF);
                dst[offset + 7 + i * 2]     = (byte)(Algorithms[i] & 0xFF);
            }
            return 6 + listLen;
        }
    }

    public class EncryptThenMacExtension : ITlsExtension
    {
        public int CalculateLength() => 4;

        public int Read(int offset, byte[] src) => 4;

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x16; // 0x0016
            dst[offset + 2] = 0x00;
            dst[offset + 3] = 0x00;
            return 4;
        }
    }

    public class UseSrtpExtension : ITlsExtension
    {
        public ushort[] ProtectionProfiles { get; private set; }
        public byte[] MasterKeyIdentifier { get; private set; }

        public UseSrtpExtension()
        {
            ProtectionProfiles = new ushort[] { 0x0001, 0x0007 };
            MasterKeyIdentifier = Array.Empty<byte>();
        }

        public UseSrtpExtension(ushort[] profiles, byte[] mki = null)
        {
            ProtectionProfiles = profiles;
            MasterKeyIdentifier = mki ?? Array.Empty<byte>();
        }

        public int CalculateLength() => 4 + 2 + 2 * ProtectionProfiles.Length + 1 + MasterKeyIdentifier.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen     = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            ushort profileLen = (ushort)((src[offset + 4] << 8) | src[offset + 5]);
            int count = profileLen / 2;
            ProtectionProfiles = new ushort[count];
            for (int i = 0; i < count; i++)
                ProtectionProfiles[i] = (ushort)((src[offset + 6 + i * 2] << 8) | src[offset + 7 + i * 2]);
            int mkiLenOffset = offset + 6 + profileLen;
            byte mkiLen = src[mkiLenOffset];
            MasterKeyIdentifier = new byte[mkiLen];
            if (mkiLen > 0) Buffer.BlockCopy(src, mkiLenOffset + 1, MasterKeyIdentifier, 0, mkiLen);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0F; // 0x000f
            int profileLen = 2 * ProtectionProfiles.Length;
            int extLen = 2 + profileLen + 1 + MasterKeyIdentifier.Length;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)((profileLen >> 8) & 0xFF);
            dst[offset + 5] = (byte)(profileLen & 0xFF);
            for (int i = 0; i < ProtectionProfiles.Length; i++)
            {
                dst[offset + 6 + i * 2]     = (byte)((ProtectionProfiles[i] >> 8) & 0xFF);
                dst[offset + 7 + i * 2]     = (byte)(ProtectionProfiles[i] & 0xFF);
            }
            int mkiOffset = offset + 6 + profileLen;
            dst[mkiOffset] = (byte)MasterKeyIdentifier.Length;
            if (MasterKeyIdentifier.Length > 0)
                Buffer.BlockCopy(MasterKeyIdentifier, 0, dst, mkiOffset + 1, MasterKeyIdentifier.Length);
            return 4 + extLen;
        }
    }

    public class ServerUseSrtpExtension : ITlsExtension
    {
        public ushort SelectedProfile { get; set; } = 0x0001;
        public byte[] MasterKeyIdentifier { get; set; } = Array.Empty<byte>();

        public ServerUseSrtpExtension() { }
        public ServerUseSrtpExtension(ushort profile, byte[] mki = null)
        {
            SelectedProfile = profile;
            MasterKeyIdentifier = mki ?? Array.Empty<byte>();
        }

        public int CalculateLength() => 4 + 2 + 1 + MasterKeyIdentifier.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            SelectedProfile = (ushort)((src[offset + 4] << 8) | src[offset + 5]);
            byte mkiLen = src[offset + 6];
            MasterKeyIdentifier = new byte[mkiLen];
            if (mkiLen > 0) Buffer.BlockCopy(src, offset + 7, MasterKeyIdentifier, 0, mkiLen);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0F; // 0x000f
            int extLen = 2 + 1 + MasterKeyIdentifier.Length;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)((SelectedProfile >> 8) & 0xFF);
            dst[offset + 5] = (byte)(SelectedProfile & 0xFF);
            dst[offset + 6] = (byte)MasterKeyIdentifier.Length;
            if (MasterKeyIdentifier.Length > 0)
                Buffer.BlockCopy(MasterKeyIdentifier, 0, dst, offset + 7, MasterKeyIdentifier.Length);
            return 4 + extLen;
        }
    }

    public class ServerEcPointFormatsExtension : ITlsExtension
    {
        public byte[] Formats { get; private set; } = new byte[] { 0x00 };

        public int CalculateLength() => 5 + Formats.Length;

        public int Read(int offset, byte[] src)
        {
            ushort extLen  = (ushort)((src[offset + 2] << 8) | src[offset + 3]);
            byte   listLen = src[offset + 4];
            Formats = new byte[listLen];
            Buffer.BlockCopy(src, offset + 5, Formats, 0, listLen);
            return 4 + extLen;
        }

        public int Write(int offset, byte[] dst)
        {
            dst[offset]     = 0x00;
            dst[offset + 1] = 0x0B;
            int extLen = 1 + Formats.Length;
            dst[offset + 2] = (byte)((extLen >> 8) & 0xFF);
            dst[offset + 3] = (byte)(extLen & 0xFF);
            dst[offset + 4] = (byte)Formats.Length;
            Buffer.BlockCopy(Formats, 0, dst, offset + 5, Formats.Length);
            return 5 + Formats.Length;
        }
    }
}
