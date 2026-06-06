using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS10.Messages
{
    public class ClientHelloDatagram : IDatagram
    {
        public byte[] ClientRandom { get; set; } = new byte[32];
        public byte[] SessionId { get; set; } = new byte[0];
        public byte[] Cookie { get; set; } = new byte[0];
        public List<ushort> CipherSuites { get; set; } = new List<ushort>();
        public List<byte> CompressionMethods { get; set; } = new List<byte> { 0x00 }; // null compression
        public List<ITlsExtension> Extensions { get; set; } = new List<ITlsExtension>();

        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public ClientHelloDatagram()
        {
        }

        public ClientHelloDatagram(byte[] clientRandom, List<ushort> cipherSuites)
        {
            ClientRandom = clientRandom ?? new byte[32];
            CipherSuites = cipherSuites ?? new List<ushort>();
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 60) throw new ArgumentException("Buffer too small for DTLS 1.0 ClientHello.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x01) throw new InvalidDataException("Not a ClientHello handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12; // after handshake header

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before version.");
            // version bytes (0xFF 0xFE for DTLS 1.0)
            pos += 2;

            if (bytes.Length < pos + 32) throw new ArgumentException("Buffer truncated for client random.");
            ClientRandom = new byte[32];
            Buffer.BlockCopy(bytes, pos, ClientRandom, 0, 32);
            pos += 32;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated for session ID length.");
            int sessionIdLen = bytes[pos++];
            if (bytes.Length < pos + sessionIdLen) throw new ArgumentException("Buffer truncated for session ID.");
            SessionId = new byte[sessionIdLen];
            if (sessionIdLen > 0) Buffer.BlockCopy(bytes, pos, SessionId, 0, sessionIdLen);
            pos += sessionIdLen;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated for cookie length.");
            int cookieLen = bytes[pos++];
            if (bytes.Length < pos + cookieLen) throw new ArgumentException("Buffer truncated for cookie.");
            Cookie = new byte[cookieLen];
            if (cookieLen > 0) Buffer.BlockCopy(bytes, pos, Cookie, 0, cookieLen);
            pos += cookieLen;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated for cipher suites length.");
            int cipherSuitesLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (bytes.Length < pos + cipherSuitesLen) throw new ArgumentException("Buffer truncated for cipher suites.");

            CipherSuites = new List<ushort>();
            for (int i = 0; i < cipherSuitesLen; i += 2)
            {
                ushort suite = (ushort)((bytes[pos + i] << 8) | bytes[pos + i + 1]);
                CipherSuites.Add(suite);
            }
            pos += cipherSuitesLen;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated for compression methods length.");
            int compLen = bytes[pos++];
            if (bytes.Length < pos + compLen) throw new ArgumentException("Buffer truncated for compression methods.");

            CompressionMethods = new List<byte>();
            for (int i = 0; i < compLen; i++)
            {
                CompressionMethods.Add(bytes[pos + i]);
            }
            pos += compLen;

            // Parse extensions if present
            Extensions = new List<ITlsExtension>();
            if (bytes.Length > pos)
            {
                if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before extensions length.");
                int extensionsLen = (bytes[pos] << 8) | bytes[pos + 1];
                pos += 2;

                int extensionsEnd = pos + extensionsLen;
                if (bytes.Length < extensionsEnd) throw new ArgumentException("Buffer truncated in extensions area.");

                while (pos < extensionsEnd)
                {
                    if (pos + 4 > bytes.Length) throw new ArgumentException("Buffer truncated in extension header.");

                    ushort extType = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                    ushort extLen = (ushort)((bytes[pos + 2] << 8) | bytes[pos + 3]);

                    ITlsExtension ext = null;
                    switch (extType)
                    {
                        case 0x0000: // server_name
                            ext = new ServerNameIndicationExtension();
                            break;
                        case 0x0005: // status_request
                            ext = new StatusRequestExtension();
                            break;
                        case 0x000a: // supported_groups
                            ext = new SupportedGroupsExtension();
                            break;
                        case 0x000b: // ec_point_formats
                            ext = new EcPointFormatsExtension();
                            break;
                        case 0x000d: // signature_algorithms
                            ext = new SignatureAlgorithmsExtension();
                            break;
                        case 0x000f: // use_srtp
                            ext = new UseSrtpExtension();
                            break;
                        case 0x0010: // application_layer_protocol_negotiation
                            ext = new ApplicationLayerProtocolNegotiationExtension();
                            break;
                        case 0x0015: // padding
                            ext = new PaddingExtension();
                            break;
                        case 0x0016: // encrypt_then_mac
                            ext = new EncryptThenMacExtension();
                            break;
                        case 0x0017: // extended_master_secret
                            ext = new ExtendedMasterSecretExtension();
                            break;
                        case 0x0023: // session_ticket
                            ext = new SessionTicketExtension();
                            break;
                        case 0x002b: // supported_versions
                            ext = new SupportedVersionsExtension();
                            break;
                        case 0x002c: // cookie (DTLS)
                            ext = new CookieExtension();
                            break;
                        case 0xFF01: // renegotiation_info
                            ext = new RenegotiationInfoExtension();
                            break;
                        default:
                            // Skip unknown extension
                            pos += 4 + extLen;
                            continue;
                    }

                    if (ext != null)
                    {
                        int consumed = ext.Read(pos, bytes);
                        pos += consumed;
                        Extensions.Add(ext);
                    }
                }
            }
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[4096];

            data[0] = 0x01; // ClientHello

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            // fragment offset and length
            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            // version 0xFF 0xFE (DTLS 1.0)
            data[pos++] = 0xFF;
            data[pos++] = 0xFE;

            // client random
            Buffer.BlockCopy(ClientRandom, 0, data, pos, 32);
            pos += 32;

            // session ID
            int sessionIdLen = SessionId?.Length ?? 0;
            data[pos++] = (byte)sessionIdLen;
            if (sessionIdLen > 0)
            {
                Buffer.BlockCopy(SessionId, 0, data, pos, sessionIdLen);
                pos += sessionIdLen;
            }

            // cookie
            int cookieLen = Cookie?.Length ?? 0;
            data[pos++] = (byte)cookieLen;
            if (cookieLen > 0)
            {
                Buffer.BlockCopy(Cookie, 0, data, pos, cookieLen);
                pos += cookieLen;
            }

            // cipher suites
            int cipherSuitesLen = (CipherSuites?.Count ?? 0) * 2;
            data[pos++] = (byte)((cipherSuitesLen >> 8) & 0xFF);
            data[pos++] = (byte)(cipherSuitesLen & 0xFF);
            if (cipherSuitesLen > 0)
            {
                for (int i = 0; i < CipherSuites.Count; i++)
                {
                    data[pos++] = (byte)((CipherSuites[i] >> 8) & 0xFF);
                    data[pos++] = (byte)(CipherSuites[i] & 0xFF);
                }
            }

            // compression methods
            int compLen = CompressionMethods?.Count ?? 1;
            data[pos++] = (byte)compLen;
            for (int i = 0; i < compLen; i++)
            {
                data[pos++] = CompressionMethods[i];
            }

            // extensions
            int extensionsLen = Extensions?.Sum(e => e.CalculateLength()) ?? 0;
            if (extensionsLen > 0)
            {
                data[pos++] = (byte)((extensionsLen >> 8) & 0xFF);
                data[pos++] = (byte)(extensionsLen & 0xFF);

                foreach (var ext in Extensions)
                {
                    pos += ext.Write(pos, data);
                }
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
