using System;
using System.IO;

namespace SharpDTLS.DTLS13.Messages
{
    /// <summary>
    /// TLS 1.3 CertificateRequest (RFC 8446 §4.3.2).
    /// </summary>
    public class CertificateRequestDatagram : IHandshakeDatagram
    {
        public byte HandshakeType { get; set; } = 0x0d; // CertificateRequest
        public int SequenceNumber { get; set; } = 0;
        public byte[] RequestContext { get; set; } = Array.Empty<byte>();

        /// <summary>Schemes accepted for the client's CertificateVerify (signature_algorithms, mandatory).</summary>
        public ushort[] SignatureAlgorithms { get; set; } = Dtls13Signatures.Supported;

        public byte[] Bytes { get; private set; }

        public CertificateRequestDatagram()
        {
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 1 + 2) throw new DtlsException(AlertDescription.DecodeError, "Buffer too small to be a valid CertificateRequest.");
            if (bytes[0] != HandshakeType) throw new InvalidDataException("Not a CertificateRequest handshake message.");

            Bytes = (byte[])bytes.Clone();

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            int end = 12 + length;
            if (bytes.Length < end) throw new DtlsException(AlertDescription.DecodeError, "Truncated CertificateRequest.");

            int pos = 12;
            int contextLength = bytes[pos++];
            if (pos + contextLength + 2 > end) throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate_request_context.");
            RequestContext = bytes.AsSpan(pos, contextLength).ToArray();
            pos += contextLength;

            int extensionsLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (pos + extensionsLength != end) throw new DtlsException(AlertDescription.DecodeError, "Inconsistent CertificateRequest extensions length.");

            SignatureAlgorithms = null;
            while (pos < end)
            {
                if (pos + 4 > end) throw new DtlsException(AlertDescription.DecodeError, "Truncated extension.");
                ushort type = (ushort)((bytes[pos] << 8) | bytes[pos + 1]);
                int extLength = (bytes[pos + 2] << 8) | bytes[pos + 3];
                if (pos + 4 + extLength > end) throw new DtlsException(AlertDescription.DecodeError, "Truncated extension.");

                if (type == 0x000d)
                {
                    var ext = new ClientSignatureAlgorithms();
                    ext.Read(pos, bytes);
                    SignatureAlgorithms = ext.SignatureAlgorithms;
                }

                pos += 4 + extLength;
            }

            if (SignatureAlgorithms == null)
                throw new DtlsException(AlertDescription.MissingExtension, "CertificateRequest has no signature_algorithms extension.");
        }

        public byte[] ToBytes()
        {
            var sigAlgs = new ClientSignatureAlgorithms(SignatureAlgorithms);
            int extensionsLength = sigAlgs.CalculateLength();
            int bodyLength = 1 + RequestContext.Length + 2 + extensionsLength;

            byte[] data = new byte[12 + bodyLength + 1];
            data[0] = HandshakeType;
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

            data[pos++] = (byte)(extensionsLength >> 8);
            data[pos++] = (byte)extensionsLength;
            pos += sigAlgs.Write(pos, data);

            data[pos] = 0x16; // inner content type (handshake)

            Bytes = data;
            return Bytes;
        }
    }
}
