using System;

namespace SharpDTLS
{
    /// <summary>
    /// renegotiation_info (RFC 5746). Renegotiation is not supported, so only the initial-handshake form
    /// with an empty renegotiated_connection is ever sent or accepted.
    /// </summary>
    public class RenegotiationInfoExtension : ITlsExtension
    {
        public const ushort Type = 0xff01;

        public byte[] RenegotiatedConnection { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 5 + RenegotiatedConnection.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 1 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid renegotiation_info extension.");
            RenegotiatedConnection = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0xff;
            destination[offset + 1] = 0x01;
            destination[offset + 2] = (byte)((1 + RenegotiatedConnection.Length) >> 8);
            destination[offset + 3] = (byte)(1 + RenegotiatedConnection.Length);
            destination[offset + 4] = (byte)RenegotiatedConnection.Length;
            Buffer.BlockCopy(RenegotiatedConnection, 0, destination, offset + 5, RenegotiatedConnection.Length);
            return 5 + RenegotiatedConnection.Length;
        }
    }

    /// <summary>An extension whose data is a single name&lt;1..2^8-1&gt;.</summary>
    public abstract class OpaqueNameExtension : ITlsExtension
    {
        private readonly ushort _type;

        protected OpaqueNameExtension(ushort type, byte[] name)
        {
            _type = type;
            if (name != null && name.Length is 0 or > 255)
                throw new ArgumentException("The name must be 1 to 255 bytes.", nameof(name));
            Name = name ?? Array.Empty<byte>();
        }

        protected byte[] Name { get; private set; }

        public int CalculateLength() => 5 + Name.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 2 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, $"Invalid extension 0x{_type:X4}.");
            Name = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = (byte)(_type >> 8);
            destination[offset + 1] = (byte)_type;
            destination[offset + 2] = (byte)((1 + Name.Length) >> 8);
            destination[offset + 3] = (byte)(1 + Name.Length);
            destination[offset + 4] = (byte)Name.Length;
            Buffer.BlockCopy(Name, 0, destination, offset + 5, Name.Length);
            return 5 + Name.Length;
        }
    }

    /// <summary>srp (RFC 5054 §2.8.1): the client's SRP username, srp_I&lt;1..2^8-1&gt;.</summary>
    public class SrpExtension : OpaqueNameExtension
    {
        public const ushort Type = 0x000c;

        public SrpExtension() : base(Type, null) { }
        public SrpExtension(byte[] identity) : base(Type, identity ?? throw new ArgumentNullException(nameof(identity))) { }

        public byte[] Identity => Name;
    }

    /// <summary>pwd_protect (RFC 8492 §4.3.1): C.x || SIV-encrypt(k, username), opaque to observers.</summary>
    public class PwdProtectExtension : OpaqueNameExtension
    {
        public const ushort Type = 0x001d;

        public PwdProtectExtension() : base(Type, null) { }
        public PwdProtectExtension(byte[] protectedName) : base(Type, protectedName ?? throw new ArgumentNullException(nameof(protectedName))) { }

        public byte[] ProtectedName => Name;
    }

    /// <summary>pwd_clear (RFC 8492 §4.4.3): the client's TLS-PWD username, unprotected, as UTF-8 OpaqueString.</summary>
    public class PwdClearExtension : OpaqueNameExtension
    {
        public const ushort Type = 0x001e;

        public PwdClearExtension() : base(Type, null) { }
        public PwdClearExtension(byte[] username) : base(Type, username ?? throw new ArgumentNullException(nameof(username))) { }

        public string Username => System.Text.Encoding.UTF8.GetString(Name);
    }

    /// <summary>
    /// SessionTicket (RFC 5077 §3.2): empty to advertise support (and, in ServerHello, to announce a
    /// NewSessionTicket), or a ticket to resume. The extension data is the ticket itself.
    /// </summary>
    public class SessionTicketExtension : ITlsExtension
    {
        public const ushort Type = 0x0023;

        public SessionTicketExtension() { }
        public SessionTicketExtension(byte[] ticket) => Ticket = ticket ?? Array.Empty<byte>();

        public byte[] Ticket { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 4 + Ticket.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid SessionTicket extension.");
            Ticket = source.AsSpan(offset + 4, length).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0x00;
            destination[offset + 1] = 0x23;
            destination[offset + 2] = (byte)(Ticket.Length >> 8);
            destination[offset + 3] = (byte)Ticket.Length;
            Buffer.BlockCopy(Ticket, 0, destination, offset + 4, Ticket.Length);
            return 4 + Ticket.Length;
        }
    }

    /// <summary>
    /// extended_master_secret (RFC 7627): binds the master secret to the handshake transcript.
    /// </summary>
    public class ExtendedMasterSecretExtension : ITlsExtension
    {
        public const ushort Type = 0x0017;

        public int CalculateLength() => 4;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length != 0)
                throw new DtlsException(AlertDescription.DecodeError, "extended_master_secret must be empty.");
            return 4;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0x00;
            destination[offset + 1] = 0x17;
            destination[offset + 2] = 0x00;
            destination[offset + 3] = 0x00;
            return 4;
        }
    }
}
