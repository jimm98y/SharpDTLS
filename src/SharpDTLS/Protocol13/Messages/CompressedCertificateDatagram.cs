using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// CompressedCertificate (RFC 8879 §4): a Certificate message body, compressed. It takes the Certificate's place in the
    /// handshake and in the transcript.
    /// </summary>
    public class CompressedCertificateDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 25;

        public int SequenceNumber { get; set; }
        public ushort Algorithm { get; private set; }
        public int UncompressedLength { get; private set; }
        public byte[] CompressedCertificate { get; private set; }
        public byte[] Bytes { get; private set; }

        public CompressedCertificateDatagram() { }

        /// <summary>Compresses <paramref name="certificate"/> with <paramref name="algorithm"/>.</summary>
        public CompressedCertificateDatagram(ushort algorithm, CertificateDatagram certificate)
        {
            byte[] message = certificate.ToBytes();
            int length = (message[1] << 16) | (message[2] << 8) | message[3];
            Algorithm = algorithm;
            UncompressedLength = length;
            CompressedCertificate = CertificateCompression.Compress(algorithm, message.AsSpan(12, length).ToArray());
        }

        public void FromBytes(byte[] bytes)
        {
            Bytes = bytes.ToArray();
            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            if (bytes.Length < 12 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Truncated CompressedCertificate.");
            var reader = new TlsReader(bytes.AsSpan(12, length).ToArray());
            Algorithm = reader.ReadUInt16();
            UncompressedLength = reader.ReadUInt24();
            CompressedCertificate = reader.ReadOpaque24();
            reader.EnsureEnd();
            if (CompressedCertificate.Length == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Empty CompressedCertificate.");
        }

        public byte[] ToBytes()
        {
            byte[] body = new TlsWriter().WriteUInt16(Algorithm).WriteUInt24(UncompressedLength).WriteOpaque24(CompressedCertificate).ToArray();
            byte[] data = new byte[12 + body.Length + 1];
            data[0] = HandshakeType;
            data[1] = (byte)(body.Length >> 16);
            data[2] = (byte)(body.Length >> 8);
            data[3] = (byte)body.Length;
            data[4] = (byte)(SequenceNumber >> 8);
            data[5] = (byte)SequenceNumber;
            data[9] = data[1];
            data[10] = data[2];
            data[11] = data[3];
            body.CopyTo(data, 12);
            data[^1] = 0x16; // inner content type (handshake)
            Bytes = data;
            return data;
        }

        /// <summary>
        /// The Certificate inside, when compressed with one of <paramref name="offered"/>; another algorithm is
        /// illegal_parameter (RFC 8879 §4).
        /// </summary>
        public CertificateDatagram Decompress(IEnumerable<ushort> offered)
        {
            if (offered == null || !offered.Contains(Algorithm))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Certificate compressed with algorithm {Algorithm}, which was not offered.");
            byte[] body = CertificateCompression.Decompress(Algorithm, CompressedCertificate, UncompressedLength);
            byte[] message = new byte[12 + body.Length];
            message[0] = 0x0b;
            message[1] = (byte)(body.Length >> 16);
            message[2] = (byte)(body.Length >> 8);
            message[3] = (byte)body.Length;
            message[4] = (byte)(SequenceNumber >> 8);
            message[5] = (byte)SequenceNumber;
            message[9] = message[1];
            message[10] = message[2];
            message[11] = message[3];
            body.CopyTo(message, 12);
            var certificate = new CertificateDatagram();
            certificate.FromBytes(message);
            return certificate;
        }
    }
}
