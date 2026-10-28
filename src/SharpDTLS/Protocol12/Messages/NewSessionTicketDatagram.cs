using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.Protocol12.Messages
{
    // RFC 5077 §3.3 — NewSessionTicket handshake message (type 0x04).
    // Wire format inside the DTLS 1.2 handshake header (12 bytes):
    //   ticket_lifetime_hint  uint32  (seconds)
    //   ticket                opaque<0..2^16-1>
    internal class NewSessionTicketDatagram : IDatagram
    {
        public uint   TicketLifetimeHint { get; set; }
        public byte[] Ticket             { get; set; } = Array.Empty<byte>();
        public ushort MessageSequenceNumber { get; set; }
        public ulong  RecordSequenceNumber  { get; set; }
        public byte[] Bytes { get; private set; }

        public NewSessionTicketDatagram() { }

        public NewSessionTicketDatagram(byte[] ticket, uint lifetimeHint = 7200)
        {
            Ticket              = ticket ?? Array.Empty<byte>();
            TicketLifetimeHint  = lifetimeHint;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 13 + 4 + 2) throw new ArgumentException("Buffer too small for NewSessionTicket.");
            if (bytes[0] != 0x04) throw new InvalidDataException("Not a NewSessionTicket handshake message.");

            Bytes = bytes.ToArray();

            MessageSequenceNumber = (ushort)((bytes[4] << 8) | bytes[5]);

            ulong seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber = seq;

            int pos = 13;
            TicketLifetimeHint = (uint)((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]);
            pos += 4;

            int ticketLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            Ticket = new byte[ticketLen];
            if (ticketLen > 0) Buffer.BlockCopy(bytes, pos, Ticket, 0, ticketLen);
        }

        public byte[] ToBytes()
        {
            int bodyLen = 4 + 2 + Ticket.Length;       // lifetime + ticket_len + ticket
            int hsLen   = bodyLen;
            byte[] buf  = new byte[13 + bodyLen];

            // Handshake header
            buf[0] = 0x04;
            buf[1] = (byte)((hsLen >> 16) & 0xFF);
            buf[2] = (byte)((hsLen >> 8)  & 0xFF);
            buf[3] = (byte)(hsLen & 0xFF);
            buf[4] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[5] = (byte)(MessageSequenceNumber & 0xFF);
            // fragment_offset = 0
            buf[9]  = (byte)((hsLen >> 16) & 0xFF);
            buf[10] = (byte)((hsLen >> 8)  & 0xFF);
            buf[11] = (byte)(hsLen & 0xFF);

            int pos = 13;
            buf[pos++] = (byte)((TicketLifetimeHint >> 24) & 0xFF);
            buf[pos++] = (byte)((TicketLifetimeHint >> 16) & 0xFF);
            buf[pos++] = (byte)((TicketLifetimeHint >> 8)  & 0xFF);
            buf[pos++] = (byte)(TicketLifetimeHint & 0xFF);
            buf[pos++] = (byte)((Ticket.Length >> 8) & 0xFF);
            buf[pos++] = (byte)(Ticket.Length & 0xFF);
            if (Ticket.Length > 0) Buffer.BlockCopy(Ticket, 0, buf, pos, Ticket.Length);

            Bytes = buf;
            return Bytes;
        }
    }
}
