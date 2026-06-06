using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS12.Messages
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
            if (bytes.Length < 60) throw new ArgumentException("Buffer too small for DTLS 1.2 ClientHello.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x01) throw new InvalidDataException("Not a ClientHello handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12; // after handshake header

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before version.");
            // version bytes (0xFE 0xFD for DTLS 1.2)
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

            // version 0xFE 0xFD (DTLS 1.2)
            data[pos++] = 0xFE;
            data[pos++] = 0xFD;

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

    public class ExtendedMasterSecretExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0017; // extended_master_secret

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            // This extension has no data payload, just type and length
            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);
            buffer[offset + 2] = 0x00;
            buffer[offset + 3] = 0x00; // length = 0

            return 4;
        }

        public int CalculateLength()
        {
            return 4; // type (2) + length (2) + no payload
        }
    }

    public class StatusRequestExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0005; // status_request

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            // Payload: 1 byte status_type (0x01 = ocsp) + responder_id_list + request_extensions
            byte[] payload = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 };

            buffer[offset + 2] = (byte)((payload.Length >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payload.Length & 0xFF);

            Buffer.BlockCopy(payload, 0, buffer, offset + 4, payload.Length);

            return 4 + payload.Length;
        }

        public int CalculateLength()
        {
            return 4 + 5; // type (2) + length (2) + payload (5)
        }
    }

    public class SignatureAlgorithmsExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x000d; // signature_algorithms

        public ushort[] SupportedAlgorithms { get; set; } = new ushort[]
        {
            0x0603, // ECDSA_SECP256R1_SHA256
            0x0503, // RSA_PSS_RSAE_SHA256
            0x0401, // ECDSA_SECP256R1_SHA1
            0x0501, // RSA_PKCS1_SHA256
        };

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 2 > buffer.Length)
                throw new ArgumentException("Buffer truncated in signature algorithms length.");

            ushort algorithmsLength = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            SupportedAlgorithms = new ushort[algorithmsLength / 2];
            for (int i = 0; i < SupportedAlgorithms.Length; i++)
            {
                if (pos + 2 > buffer.Length)
                    throw new ArgumentException("Buffer truncated in signature algorithms.");

                SupportedAlgorithms[i] = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
                pos += 2;
            }

            return pos - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int algorithmsDataLen = (SupportedAlgorithms?.Length ?? 0) * 2;
            int payloadLen = 2 + algorithmsDataLen; // length field (2) + algorithms data

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)((algorithmsDataLen >> 8) & 0xFF);
            buffer[offset + 5] = (byte)(algorithmsDataLen & 0xFF);

            for (int i = 0; i < (SupportedAlgorithms?.Length ?? 0); i++)
            {
                buffer[offset + 6 + i * 2] = (byte)((SupportedAlgorithms[i] >> 8) & 0xFF);
                buffer[offset + 7 + i * 2] = (byte)(SupportedAlgorithms[i] & 0xFF);
            }

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int algorithmsDataLen = (SupportedAlgorithms?.Length ?? 0) * 2;
            return 4 + 2 + algorithmsDataLen; // type (2) + length (2) + alg_length (2) + algorithms
        }
    }

    public class SupportedGroupsExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x000a; // supported_groups (elliptic_curves)

        public ushort[] SupportedGroups { get; set; } = new ushort[]
        {
            0x001d, // x25519
            0x0018, // secp256r1
            0x0019, // secp384r1
        };

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 2 > buffer.Length)
                throw new ArgumentException("Buffer truncated in supported groups length.");

            ushort groupsLength = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            SupportedGroups = new ushort[groupsLength / 2];
            for (int i = 0; i < SupportedGroups.Length; i++)
            {
                if (pos + 2 > buffer.Length)
                    throw new ArgumentException("Buffer truncated in supported groups.");

                SupportedGroups[i] = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
                pos += 2;
            }

            return pos - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int groupsDataLen = (SupportedGroups?.Length ?? 0) * 2;
            int payloadLen = 2 + groupsDataLen; // length field (2) + groups data

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)((groupsDataLen >> 8) & 0xFF);
            buffer[offset + 5] = (byte)(groupsDataLen & 0xFF);

            for (int i = 0; i < (SupportedGroups?.Length ?? 0); i++)
            {
                buffer[offset + 6 + i * 2] = (byte)((SupportedGroups[i] >> 8) & 0xFF);
                buffer[offset + 7 + i * 2] = (byte)(SupportedGroups[i] & 0xFF);
            }

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int groupsDataLen = (SupportedGroups?.Length ?? 0) * 2;
            return 4 + 2 + groupsDataLen; // type (2) + length (2) + groups_length (2) + groups
        }
    }

    public class EcPointFormatsExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x000b; // ec_point_formats

        public byte[] SupportedFormats { get; set; } = new byte[] { 0x00 }; // uncompressed

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 1 > buffer.Length)
                throw new ArgumentException("Buffer truncated in formats length.");

            byte formatsLength = buffer[pos++];
            if (pos + formatsLength > buffer.Length)
                throw new ArgumentException("Buffer truncated in formats.");

            SupportedFormats = new byte[formatsLength];
            Buffer.BlockCopy(buffer, pos, SupportedFormats, 0, formatsLength);

            return pos + formatsLength - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int formatsDataLen = (SupportedFormats?.Length ?? 0);
            int payloadLen = 1 + formatsDataLen; // length field (1) + formats data

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)formatsDataLen;

            if (formatsDataLen > 0)
                Buffer.BlockCopy(SupportedFormats, 0, buffer, offset + 5, formatsDataLen);

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int formatsDataLen = (SupportedFormats?.Length ?? 0);
            return 4 + 1 + formatsDataLen; // type (2) + length (2) + formats_length (1) + formats
        }
    }

    public class EncryptThenMacExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0016; // encrypt_then_mac

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);
            buffer[offset + 2] = 0x00;
            buffer[offset + 3] = 0x00; // length = 0

            return 4;
        }

        public int CalculateLength() => 4;
    }

    public class UseSrtpExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x000f; // use_srtp

        public ushort[] SrtpProtectionProfiles { get; set; } = new ushort[] { 0x0001, 0x0007 };
        public byte[] MasterKeyIdentifier { get; set; } = new byte[0];

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 6 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            ushort profileListLength = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            SrtpProtectionProfiles = new ushort[profileListLength / 2];
            for (int i = 0; i < SrtpProtectionProfiles.Length; i++)
            {
                SrtpProtectionProfiles[i] = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
                pos += 2;
            }

            byte mkiLength = buffer[pos++];
            MasterKeyIdentifier = new byte[mkiLength];
            if (mkiLength > 0)
                Buffer.BlockCopy(buffer, pos, MasterKeyIdentifier, 0, mkiLength);

            return pos + mkiLength - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int profileListLength = (SrtpProtectionProfiles?.Length ?? 0) * 2;
            int mkiLength = MasterKeyIdentifier?.Length ?? 0;
            int payloadLen = 2 + profileListLength + 1 + mkiLength;

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)((profileListLength >> 8) & 0xFF);
            buffer[offset + 5] = (byte)(profileListLength & 0xFF);

            int pos = offset + 6;
            for (int i = 0; i < (SrtpProtectionProfiles?.Length ?? 0); i++)
            {
                buffer[pos++] = (byte)((SrtpProtectionProfiles[i] >> 8) & 0xFF);
                buffer[pos++] = (byte)(SrtpProtectionProfiles[i] & 0xFF);
            }

            buffer[pos++] = (byte)mkiLength;
            if (mkiLength > 0)
                Buffer.BlockCopy(MasterKeyIdentifier, 0, buffer, pos, mkiLength);

            return pos - offset;
        }

        public int CalculateLength()
        {
            int profileListLength = (SrtpProtectionProfiles?.Length ?? 0) * 2;
            int mkiLength = MasterKeyIdentifier?.Length ?? 0;
            return 4 + 2 + profileListLength + 1 + mkiLength;
        }
    }

    public class ServerNameIndicationExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0000; // server_name

        public string HostName { get; set; } = "";

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 2 > buffer.Length)
                throw new ArgumentException("Buffer truncated in server name list length.");

            ushort listLength = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            if (pos + 1 > buffer.Length)
                throw new ArgumentException("Buffer truncated in name type.");

            byte nameType = buffer[pos++];
            if (nameType != 0) throw new InvalidOperationException("Only host_name (0) type supported.");

            if (pos + 2 > buffer.Length)
                throw new ArgumentException("Buffer truncated in hostname length.");

            ushort hostNameLen = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            HostName = System.Text.Encoding.ASCII.GetString(buffer, pos, hostNameLen);
            pos += hostNameLen;

            return pos - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = 0x00;
            buffer[offset + 1] = 0x00; // type = server_name

            byte[] hostNameBytes = System.Text.Encoding.ASCII.GetBytes(HostName ?? "");
            int listLength = 1 + 2 + hostNameBytes.Length;
            int payloadLen = 2 + listLength;

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)((listLength >> 8) & 0xFF);
            buffer[offset + 5] = (byte)(listLength & 0xFF);

            buffer[offset + 6] = 0x00; // name_type = host_name

            buffer[offset + 7] = (byte)((hostNameBytes.Length >> 8) & 0xFF);
            buffer[offset + 8] = (byte)(hostNameBytes.Length & 0xFF);

            if (hostNameBytes.Length > 0)
                Buffer.BlockCopy(hostNameBytes, 0, buffer, offset + 9, hostNameBytes.Length);

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            byte[] hostNameBytes = System.Text.Encoding.ASCII.GetBytes(HostName ?? "");
            int listLength = 1 + 2 + hostNameBytes.Length;
            return 4 + 2 + listLength;
        }
    }

    public class SupportedVersionsExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x002b; // supported_versions

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = 0x00;
            buffer[offset + 1] = 0x2b; // type = supported_versions

            // DTLS 1.2 (0xFE 0xFD)
            buffer[offset + 2] = 0x00;
            buffer[offset + 3] = 0x03; // length = 3
            buffer[offset + 4] = 0x02; // versions_length = 2
            buffer[offset + 5] = 0xFE; // DTLS 1.2 major
            buffer[offset + 6] = 0xFD; // DTLS 1.2 minor

            return 7;
        }

        public int CalculateLength() => 7;
    }

    public class SessionTicketExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0023; // session_ticket

        public byte[] TicketData { get; set; } = new byte[0];

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            TicketData = new byte[length];
            if (length > 0)
                Buffer.BlockCopy(buffer, offset + 4, TicketData, 0, length);

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int len = TicketData?.Length ?? 0;
            buffer[offset + 2] = (byte)((len >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(len & 0xFF);

            if (len > 0)
                Buffer.BlockCopy(TicketData, 0, buffer, offset + 4, len);

            return 4 + len;
        }

        public int CalculateLength()
        {
            int len = TicketData?.Length ?? 0;
            return 4 + len;
        }
    }

    public class RenegotiationInfoExtension : ITlsExtension
    {
        public ushort ExtensionType => 0xFF01; // renegotiation_info

        public byte[] RenegotiatedConnection { get; set; } = new byte[0];

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            if (length < 1)
                throw new ArgumentException("Renegotiation info length too small.");

            byte dataLength = buffer[offset + 4];
            if (dataLength + 1 != length)
                throw new InvalidOperationException("Invalid renegotiation info length.");

            RenegotiatedConnection = new byte[dataLength];
            if (dataLength > 0)
                Buffer.BlockCopy(buffer, offset + 5, RenegotiatedConnection, 0, dataLength);

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = 0xFF;
            buffer[offset + 1] = 0x01; // type = renegotiation_info

            int dataLen = RenegotiatedConnection?.Length ?? 0;
            int payloadLen = 1 + dataLen;

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)dataLen;

            if (dataLen > 0)
                Buffer.BlockCopy(RenegotiatedConnection, 0, buffer, offset + 5, dataLen);

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int dataLen = RenegotiatedConnection?.Length ?? 0;
            return 4 + 1 + dataLen;
        }
    }

    public class CookieExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x002c; // cookie (DTLS)

        public byte[] CookieValue { get; set; } = new byte[0];

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 1 > buffer.Length)
                throw new ArgumentException("Buffer truncated in cookie length.");

            byte cookieLen = buffer[pos++];
            if (pos + cookieLen > buffer.Length)
                throw new ArgumentException("Buffer truncated in cookie data.");

            CookieValue = new byte[cookieLen];
            if (cookieLen > 0)
                Buffer.BlockCopy(buffer, pos, CookieValue, 0, cookieLen);

            return pos + cookieLen - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int cookieLen = CookieValue?.Length ?? 0;
            int payloadLen = 1 + cookieLen;

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)cookieLen;

            if (cookieLen > 0)
                Buffer.BlockCopy(CookieValue, 0, buffer, offset + 5, cookieLen);

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int cookieLen = CookieValue?.Length ?? 0;
            return 4 + 1 + cookieLen;
        }
    }

    public class ApplicationLayerProtocolNegotiationExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0010; // application_layer_protocol_negotiation

        public List<string> ProtocolNames { get; set; } = new List<string>();

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            int pos = offset + 4;
            if (pos + 2 > buffer.Length)
                throw new ArgumentException("Buffer truncated in ALPN list length.");

            ushort listLength = (ushort)((buffer[pos] << 8) | buffer[pos + 1]);
            pos += 2;

            ProtocolNames = new List<string>();
            int listEnd = pos + listLength;

            while (pos < listEnd)
            {
                if (pos + 1 > buffer.Length)
                    throw new ArgumentException("Buffer truncated in ALPN protocol length.");

                byte protocolLen = buffer[pos++];
                if (pos + protocolLen > buffer.Length)
                    throw new ArgumentException("Buffer truncated in ALPN protocol name.");

                string protocol = System.Text.Encoding.ASCII.GetString(buffer, pos, protocolLen);
                ProtocolNames.Add(protocol);
                pos += protocolLen;
            }

            return pos - offset;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int protocolsDataLen = (ProtocolNames?.Sum(p => 1 + (p?.Length ?? 0)) ?? 0);
            int payloadLen = 2 + protocolsDataLen;

            buffer[offset + 2] = (byte)((payloadLen >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(payloadLen & 0xFF);

            buffer[offset + 4] = (byte)((protocolsDataLen >> 8) & 0xFF);
            buffer[offset + 5] = (byte)(protocolsDataLen & 0xFF);

            int pos = offset + 6;
            if (ProtocolNames != null)
            {
                foreach (var protocol in ProtocolNames)
                {
                    byte[] protocolBytes = System.Text.Encoding.ASCII.GetBytes(protocol ?? "");
                    buffer[pos++] = (byte)protocolBytes.Length;
                    if (protocolBytes.Length > 0)
                    {
                        Buffer.BlockCopy(protocolBytes, 0, buffer, pos, protocolBytes.Length);
                        pos += protocolBytes.Length;
                    }
                }
            }

            return 4 + payloadLen;
        }

        public int CalculateLength()
        {
            int protocolsDataLen = (ProtocolNames?.Sum(p => 1 + (p?.Length ?? 0)) ?? 0);
            return 4 + 2 + protocolsDataLen;
        }
    }

    public class PaddingExtension : ITlsExtension
    {
        public ushort ExtensionType => 0x0015; // padding

        public byte[] PaddingData { get; set; } = new byte[0];

        public int Read(int offset, byte[] buffer)
        {
            if (buffer == null || offset + 4 > buffer.Length)
                throw new ArgumentException("Buffer too small for extension header.");

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            ushort length = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (type != ExtensionType)
                throw new InvalidOperationException($"Expected extension type 0x{ExtensionType:X4}, got 0x{type:X4}");

            PaddingData = new byte[length];
            if (length > 0)
                Buffer.BlockCopy(buffer, offset + 4, PaddingData, 0, length);

            return 4 + length;
        }

        public int Write(int offset, byte[] buffer)
        {
            buffer[offset] = (byte)((ExtensionType >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(ExtensionType & 0xFF);

            int len = PaddingData?.Length ?? 0;
            buffer[offset + 2] = (byte)((len >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(len & 0xFF);

            if (len > 0)
                Buffer.BlockCopy(PaddingData, 0, buffer, offset + 4, len);

            return 4 + len;
        }

        public int CalculateLength()
        {
            int len = PaddingData?.Length ?? 0;
            return 4 + len;
        }
    }
}
