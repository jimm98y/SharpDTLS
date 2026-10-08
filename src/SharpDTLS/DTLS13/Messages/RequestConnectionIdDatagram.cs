using System;

namespace SharpDTLS.DTLS13.Messages
{
    /// <summary>RequestConnectionId (RFC 9147 §9): asks the peer for num_cids spare CIDs. struct { uint8 num_cids; }</summary>
    public class RequestConnectionIdDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 9;

        public RequestConnectionIdDatagram() { }
        public RequestConnectionIdDatagram(byte count) => Count = count;

        public int SequenceNumber { get; set; }
        public byte Count { get; private set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            Bytes = bytes;
            int length = bytes.Length >= 4 ? (bytes[1] << 16) | (bytes[2] << 8) | bytes[3] : -1;
            if (bytes.Length < 13 || bytes[0] != HandshakeType || length != 1)
                throw new DtlsException(AlertDescription.DecodeError, "Not a RequestConnectionId message.");
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            Count = bytes[12];
        }

        public byte[] ToBytes() => Bytes = Dtls13HandshakeMessage.Encode(HandshakeType, SequenceNumber, new[] { Count });
    }
}
