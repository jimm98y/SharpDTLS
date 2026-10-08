using System;
using System.IO;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    public class NewSessionTicketDatagram : IHandshakeDatagram
    {
        public uint TicketLifetime { get; set; }
        public uint TicketAgeAdd { get; set; }
        public byte[] TicketNonce { get; set; } = new byte[0];
        public byte[] Ticket { get; set; } = new byte[0];
        public byte[] Bytes { get; private set; }

        public int SequenceNumber { get; set; } = 0;

        public NewSessionTicketDatagram()
        {
        }

        public NewSessionTicketDatagram(byte[] ticket, byte[] nonce, uint lifetime = 0, uint ageAdd = 0)
        {
            Ticket = ticket ?? new byte[0];
            TicketNonce = nonce ?? new byte[0];
            TicketLifetime = lifetime;
            TicketAgeAdd = ageAdd;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 12 + 4 + 4 + 1 + 2 + 1 + 2) throw new ArgumentException("Buffer too small to be a valid NewSessionTicket.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x04) throw new InvalidDataException("Not a NewSessionTicket handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

            SequenceNumber = (bytes[4] << 8) | bytes[5];

            // fragment offset and fragment length are bytes[6..11], ignored for now

            int pos = 12;

            if (bytes.Length < pos + 8) throw new ArgumentException("Buffer truncated before ticket lifetime/age_add.");
            TicketLifetime = (uint)((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]);
            pos += 4;
            TicketAgeAdd = (uint)((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]);
            pos += 4;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before nonce length.");
            int nonceLen = bytes[pos];
            pos += 1;
            if (bytes.Length < pos + nonceLen) throw new ArgumentException("Buffer truncated in nonce field.");
            TicketNonce = new byte[nonceLen];
            Buffer.BlockCopy(bytes, pos, TicketNonce, 0, nonceLen);
            pos += nonceLen;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before ticket length.");
            int ticketLen = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (bytes.Length < pos + ticketLen) throw new ArgumentException("Buffer truncated in ticket field.");
            Ticket = new byte[ticketLen];
            Buffer.BlockCopy(bytes, pos, Ticket, 0, ticketLen);
            pos += ticketLen;

            if (bytes.Length < pos + 2) throw new ArgumentException("Buffer truncated before extensions length.");
            int extensionsLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (bytes.Length < pos + extensionsLength) throw new ArgumentException("Buffer truncated in extensions area.");

            // For now we don't parse individual extensions; just skip
            pos += extensionsLength;

            // Optional: validate that parsed length matches handshake length field
            if (length != pos - 12)
            {
                // Some implementations may include or omit trailing record-type; be tolerant and don't throw here
            }
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[2048];

            data[0] = 0x04; // handshake message type (NewSessionTicket)

            // placeholder for 3-byte length
            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            // handshake reconstruction data
            data[4] = (byte)((this.SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(this.SequenceNumber & 0xFF);

            // fragment offset (3 bytes) and fragment length (3 bytes) - placeholders
            data[6] = 0;
            data[7] = 0;
            data[8] = 0;
            data[9] = 0;
            data[10] = 0;
            data[11] = 0;

            int pos = 12;

            // ticket_lifetime (4 bytes)
            data[pos++] = (byte)((this.TicketLifetime >> 24) & 0xFF);
            data[pos++] = (byte)((this.TicketLifetime >> 16) & 0xFF);
            data[pos++] = (byte)((this.TicketLifetime >> 8) & 0xFF);
            data[pos++] = (byte)(this.TicketLifetime & 0xFF);

            // ticket_age_add (4 bytes)
            data[pos++] = (byte)((this.TicketAgeAdd >> 24) & 0xFF);
            data[pos++] = (byte)((this.TicketAgeAdd >> 16) & 0xFF);
            data[pos++] = (byte)((this.TicketAgeAdd >> 8) & 0xFF);
            data[pos++] = (byte)(this.TicketAgeAdd & 0xFF);

            // ticket_nonce
            data[pos++] = (byte)(this.TicketNonce?.Length ?? 0);
            if ((this.TicketNonce?.Length ?? 0) > 0)
            {
                Buffer.BlockCopy(this.TicketNonce, 0, data, pos, this.TicketNonce.Length);
                pos += this.TicketNonce.Length;
            }

            // ticket
            int ticketLen = this.Ticket?.Length ?? 0;
            data[pos++] = (byte)((ticketLen >> 8) & 0xFF);
            data[pos++] = (byte)(ticketLen & 0xFF);
            if (ticketLen > 0)
            {
                Buffer.BlockCopy(this.Ticket, 0, data, pos, ticketLen);
                pos += ticketLen;
            }

            // extensions length (2 bytes) - none for now
            int extensionsLength = 0;
            data[pos++] = (byte)((extensionsLength >> 8) & 0xFF);
            data[pos++] = (byte)(extensionsLength & 0xFF);

            // record type
            data[pos++] = 0x16; // handshake record

            // fill in lengths
            length = pos - 13; // as other datagrams calculate
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
