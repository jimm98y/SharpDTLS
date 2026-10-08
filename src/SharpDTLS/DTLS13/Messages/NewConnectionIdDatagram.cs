using System;
using System.Collections.Generic;

namespace SharpDTLS.DTLS13.Messages
{
    /// <summary>
    /// NewConnectionId (RFC 9147 §9): CIDs the sender wants the peer to use, immediately (cid_immediate) or as spares
    /// (cid_spare). struct { ConnectionId cids&lt;0..2^16-1&gt;; ConnectionIdUsage usage; }
    /// </summary>
    public class NewConnectionIdDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 10;
        public const byte CidImmediate = 0;
        public const byte CidSpare = 1;

        public NewConnectionIdDatagram() { }

        public NewConnectionIdDatagram(IEnumerable<byte[]> connectionIds, byte usage)
        {
            ConnectionIds = new List<byte[]>(connectionIds);
            Usage = usage;
        }

        public int SequenceNumber { get; set; }
        public List<byte[]> ConnectionIds { get; private set; } = new();
        public byte Usage { get; private set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            Bytes = bytes;
            if (bytes.Length < 12 || bytes[0] != HandshakeType)
                throw new DtlsException(AlertDescription.DecodeError, "Not a NewConnectionId message.");
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            var r = new TlsReader(bytes.AsSpan(12, length).ToArray());
            var list = new TlsReader(r.ReadOpaque16());
            ConnectionIds = new List<byte[]>();
            while (list.Remaining > 0)
                ConnectionIds.Add(list.ReadOpaque8());
            Usage = r.ReadUInt8();
            r.EnsureEnd();
            if (Usage > CidSpare)
                throw new DtlsException(AlertDescription.IllegalParameter, "Unknown connection ID usage.");
        }

        public byte[] ToBytes()
        {
            var list = new TlsWriter();
            foreach (byte[] cid in ConnectionIds)
                list.WriteOpaque8(cid);
            byte[] body = new TlsWriter().WriteOpaque16(list.ToArray()).WriteUInt8(Usage).ToArray();
            return Bytes = Dtls13HandshakeMessage.Encode(HandshakeType, SequenceNumber, body);
        }
    }

    /// <summary>Encoding shared by the simple DTLS 1.3 handshake messages.</summary>
    internal static class Dtls13HandshakeMessage
    {
        /// <summary>DTLS handshake header (unfragmented) + body + the handshake content type of the inner plaintext.</summary>
        public static byte[] Encode(byte type, int messageSeq, byte[] body)
            => new TlsWriter()
                .WriteUInt8(type).WriteUInt24(body.Length).WriteUInt16(messageSeq)
                .WriteUInt24(0).WriteUInt24(body.Length)
                .WriteBytes(body)
                .WriteUInt8(0x16)
                .ToArray();
    }
}
