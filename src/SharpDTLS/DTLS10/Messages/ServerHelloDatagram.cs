using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS10.Messages
{
    public class ServerHelloDatagram : IDatagram
    {
        public byte[] ServerRandom { get; set; } = new byte[32];
        public byte[] SessionId { get; set; } = new byte[0];
        public ushort SelectedCipherSuite { get; set; }
        public byte SelectedCompressionMethod { get; set; } = 0x00;
        public List<ITlsExtension> Extensions { get; set; } = new List<ITlsExtension>();

        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public ServerHelloDatagram()
        {
        }

        public ServerHelloDatagram(byte[] serverRandom, ushort selectedCipherSuite)
        {
            ServerRandom = serverRandom ?? new byte[32];
            SelectedCipherSuite = selectedCipherSuite;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 50) throw new ArgumentException("Buffer too small for DTLS 1.0 ServerHello.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x02) throw new InvalidDataException("Not a ServerHello handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before version.");
            pos += 2;

            if (bytes.Length < pos + 32) throw new ArgumentException("Buffer truncated for server random.");
            ServerRandom = new byte[32];
            Buffer.BlockCopy(bytes, pos, ServerRandom, 0, 32);
            pos += 32;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated for session ID length.");
            int sessionIdLen = bytes[pos++];
            if (bytes.Length < pos + sessionIdLen) throw new ArgumentException("Buffer truncated for session ID.");
            SessionId = new byte[sessionIdLen];
            if (sessionIdLen > 0) Buffer.BlockCopy(bytes, pos, SessionId, 0, sessionIdLen);
            pos += sessionIdLen;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated for cipher suite.");
            SelectedCipherSuite = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
            pos += 2;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated for compression method.");
            SelectedCompressionMethod = bytes[pos++];

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

            data[0] = 0x02; // ServerHello

            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            // version 0xFF 0xFE (DTLS 1.0)
            data[pos++] = 0xFF;
            data[pos++] = 0xFE;

            // server random
            Buffer.BlockCopy(ServerRandom, 0, data, pos, 32);
            pos += 32;

            // session ID
            int sessionIdLen = SessionId?.Length ?? 0;
            data[pos++] = (byte)sessionIdLen;
            if (sessionIdLen > 0)
            {
                Buffer.BlockCopy(SessionId, 0, data, pos, sessionIdLen);
                pos += sessionIdLen;
            }

            // selected cipher suite
            data[pos++] = (byte)((SelectedCipherSuite >> 8) & 0xFF);
            data[pos++] = (byte)(SelectedCipherSuite & 0xFF);

            // compression method
            data[pos++] = SelectedCompressionMethod;

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
