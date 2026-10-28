using System;
using System.IO;

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// EndOfEarlyData (RFC 8446 §4.5): TLS 1.3 only (DTLS 1.3 removed it, RFC 9147 §5.6). The client sends it under the
    /// early traffic keys after the server's Finished when its 0-RTT data was accepted; it is part of the transcript.
    /// </summary>
    internal class EndOfEarlyDataDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 5;

        public int SequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes[0] != HandshakeType)
                throw new InvalidDataException("Not an EndOfEarlyData message.");
            if (((bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) != 0)
                throw new DtlsException(AlertDescription.DecodeError, "EndOfEarlyData has a body.");
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            Bytes = bytes;
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[12 + 1];
            data[0] = HandshakeType;
            data[4] = (byte)(SequenceNumber >> 8);
            data[5] = (byte)SequenceNumber;
            data[^1] = 0x16; // inner content type (handshake)
            Bytes = data;
            return data;
        }
    }
}
