using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// TLS 1.3 Certificate message (RFC 8446 §4.4.2) with X.509 entries.
    /// </summary>
    internal class CertificateDatagram : IHandshakeDatagram
    {
        public int SequenceNumber { get; set; } = 2;
        public byte[] RequestContext { get; set; } = Array.Empty<byte>();

        /// <summary>DER certificates, end-entity first. Empty when the client has no certificate.</summary>
        public List<byte[]> CertificateChain { get; set; } = new List<byte[]>();

        /// <summary>The end-entity certificate, or an empty array when the chain is empty.</summary>
        public byte[] Certificate
        {
            get => CertificateChain.Count > 0 ? CertificateChain[0] : Array.Empty<byte>();
            set => CertificateChain = value == null || value.Length == 0 ? new List<byte[]>() : new List<byte[]> { value };
        }

        public byte[] Bytes { get; private set; }

        /// <summary>The OCSP response stapled to the end-entity certificate (status_request, RFC 8446 §4.4.2.1), or null.</summary>
        public byte[] OcspResponse { get; set; }

        private byte[] LeafExtensions()
        {
            if (OcspResponse == null)
                return Array.Empty<byte>();
            byte[] status = StatusRequestExtension.EncodeCertificateStatus(OcspResponse);
            return new TlsWriter().WriteUInt16(StatusRequestExtension.Type).WriteOpaque16(status).ToArray();
        }

        public CertificateDatagram()
        { }

        public CertificateDatagram(byte[] certificate)
        {
            Certificate = certificate;
        }

        public CertificateDatagram(IEnumerable<byte[]> certificateChain, byte[] requestContext = null)
        {
            CertificateChain = certificateChain.ToList();
            RequestContext = requestContext ?? Array.Empty<byte>();
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 4) throw new DtlsException(AlertDescription.DecodeError, "Buffer too small to be a valid Certificate message.");
            if (bytes[0] != 0x0b) throw new InvalidDataException("Not a Certificate handshake message.");

            Bytes = bytes.ToArray();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            int end = 12 + length;
            if (bytes.Length < end) throw new DtlsException(AlertDescription.DecodeError, "Truncated Certificate message.");

            int pos = 12;
            int contextLength = bytes[pos++];
            if (pos + contextLength + 3 > end) throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate_request_context.");
            RequestContext = bytes.AsSpan(pos, contextLength).ToArray();
            pos += contextLength;

            int listLength = (bytes[pos] << 16) | (bytes[pos + 1] << 8) | bytes[pos + 2];
            pos += 3;
            int listEnd = pos + listLength;
            if (listEnd != end) throw new DtlsException(AlertDescription.DecodeError, "Inconsistent certificate_list length.");

            CertificateChain = new List<byte[]>();
            while (pos < listEnd)
            {
                if (pos + 3 > listEnd) throw new DtlsException(AlertDescription.DecodeError, "Truncated certificate entry.");
                int certLength = (bytes[pos] << 16) | (bytes[pos + 1] << 8) | bytes[pos + 2];
                pos += 3;
                if (certLength == 0 || pos + certLength + 2 > listEnd) throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate entry.");
                CertificateChain.Add(bytes.AsSpan(pos, certLength).ToArray());
                pos += certLength;

                int extensionsLength = (bytes[pos] << 8) | bytes[pos + 1];
                pos += 2;
                if (pos + extensionsLength > listEnd) throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate entry extensions.");
                if (CertificateChain.Count == 1)
                    ReadLeafExtensions(bytes.AsSpan(pos, extensionsLength).ToArray());
                pos += extensionsLength; // other extensions (e.g. SCTs) and other entries' extensions are not interpreted
            }
        }

        private void ReadLeafExtensions(byte[] extensions)
        {
            var reader = new TlsReader(extensions);
            while (reader.Remaining > 0)
            {
                ushort type = reader.ReadUInt16();
                byte[] body = reader.ReadOpaque16();
                if (type == StatusRequestExtension.Type)
                    OcspResponse = StatusRequestExtension.DecodeCertificateStatus(body);
            }
        }

        public byte[] ToBytes()
        {
            byte[] leafExtensions = LeafExtensions();
            int listLength = CertificateChain.Sum(c => 3 + c.Length + 2) + leafExtensions.Length;
            int bodyLength = 1 + RequestContext.Length + 3 + listLength;
            byte[] data = new byte[12 + bodyLength + 1];

            data[0] = 0x0b; // handshake message type (certificate)
            data[1] = (byte)(bodyLength >> 16);
            data[2] = (byte)(bodyLength >> 8);
            data[3] = (byte)bodyLength;
            data[4] = (byte)(SequenceNumber >> 8);
            data[5] = (byte)SequenceNumber;
            // fragment_offset = 0
            data[9] = (byte)(bodyLength >> 16);
            data[10] = (byte)(bodyLength >> 8);
            data[11] = (byte)bodyLength;

            int pos = 12;
            data[pos++] = (byte)RequestContext.Length;
            Buffer.BlockCopy(RequestContext, 0, data, pos, RequestContext.Length);
            pos += RequestContext.Length;

            data[pos++] = (byte)(listLength >> 16);
            data[pos++] = (byte)(listLength >> 8);
            data[pos++] = (byte)listLength;

            for (int i = 0; i < CertificateChain.Count; i++)
            {
                byte[] cert = CertificateChain[i];
                data[pos++] = (byte)(cert.Length >> 16);
                data[pos++] = (byte)(cert.Length >> 8);
                data[pos++] = (byte)cert.Length;
                Buffer.BlockCopy(cert, 0, data, pos, cert.Length);
                pos += cert.Length;
                byte[] extensions = i == 0 ? leafExtensions : Array.Empty<byte>();
                data[pos++] = (byte)(extensions.Length >> 8);
                data[pos++] = (byte)extensions.Length;
                extensions.CopyTo(data, pos);
                pos += extensions.Length;
            }

            data[pos] = 0x16; // inner content type (handshake)

            Bytes = data;
            return Bytes;
        }
    }
}
