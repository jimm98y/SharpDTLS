using System;
using System.Collections.Generic;
using System.Linq;

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
    /// server_name (RFC 6066 §3): the client's host_name, or empty in a ServerHello / EncryptedExtensions to
    /// acknowledge that the server used it. Host names are ASCII (A-labels), without a trailing dot, and never
    /// IP address literals.
    /// </summary>
    public class ServerNameExtension : ITlsExtension
    {
        public const ushort Type = 0x0000;

        public ServerNameExtension() { }

        public ServerNameExtension(string hostName)
        {
            if (!IsValidHostName(hostName))
                throw new ArgumentException($"'{hostName}' is not a host name usable in server_name.", nameof(hostName));
            HostName = hostName;
        }

        /// <summary>The requested host name; null for the empty acknowledgement.</summary>
        public string HostName { get; private set; }

        public static bool IsValidHostName(string hostName)
            => !string.IsNullOrEmpty(hostName) && hostName.Length <= 253 && !hostName.EndsWith('.')
               && hostName.All(c => c < 0x80 && (char.IsLetterOrDigit(c) || c == '-' || c == '.'))
               && !System.Net.IPAddress.TryParse(hostName, out _);

        public int CalculateLength() => HostName == null ? 4 : 4 + 2 + 1 + 2 + HostName.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid server_name extension.");
            if (length == 0)
                return 4;

            var list = new TlsReader(new TlsReader(source.AsSpan(offset + 4, length).ToArray()).ReadOpaque16());
            while (list.Remaining > 0)
            {
                byte nameType = list.ReadUInt8();
                byte[] name = list.ReadOpaque16();
                if (nameType != 0)
                    continue; // only host_name is defined
                if (HostName != null)
                    throw new DtlsException(AlertDescription.IllegalParameter, "server_name lists two host names.");
                HostName = System.Text.Encoding.ASCII.GetString(name);
                if (!IsValidHostName(HostName))
                    throw new DtlsException(AlertDescription.IllegalParameter, "Invalid host name in server_name.");
            }
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x00;
            if (HostName == null)
            {
                destination[offset + 2] = 0;
                destination[offset + 3] = 0;
                return 4;
            }
            byte[] name = System.Text.Encoding.ASCII.GetBytes(HostName);
            byte[] body = new TlsWriter().WriteOpaque16(new TlsWriter().WriteUInt8(0).WriteOpaque16(name).ToArray()).ToArray();
            destination[offset + 2] = (byte)(body.Length >> 8);
            destination[offset + 3] = (byte)body.Length;
            body.CopyTo(destination, offset + 4);
            return 4 + body.Length;
        }
    }

    /// <summary>
    /// application_layer_protocol_negotiation (RFC 7301): the client's protocols in preference order, or the one the
    /// server selected.
    /// </summary>
    public class AlpnExtension : ITlsExtension
    {
        public const ushort Type = 0x0010;

        public AlpnExtension() { }

        public AlpnExtension(IEnumerable<string> protocols)
        {
            Protocols = protocols.ToList();
            if (Protocols.Count == 0 || Protocols.Any(p => string.IsNullOrEmpty(p) || System.Text.Encoding.UTF8.GetByteCount(p) > 255))
                throw new ArgumentException("ALPN protocol names must be 1 to 255 bytes.", nameof(protocols));
        }

        public List<string> Protocols { get; private set; } = new();

        private byte[] Body()
        {
            var list = new TlsWriter();
            foreach (string protocol in Protocols)
                list.WriteOpaque8(System.Text.Encoding.UTF8.GetBytes(protocol));
            return new TlsWriter().WriteOpaque16(list.ToArray()).ToArray();
        }

        public int CalculateLength() => 4 + Body().Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid ALPN extension.");
            var outer = new TlsReader(source.AsSpan(offset + 4, length).ToArray());
            var list = new TlsReader(outer.ReadOpaque16());
            outer.EnsureEnd();
            while (list.Remaining > 0)
            {
                byte[] name = list.ReadOpaque8();
                if (name.Length == 0)
                    throw new DtlsException(AlertDescription.DecodeError, "Empty ALPN protocol name.");
                Protocols.Add(System.Text.Encoding.UTF8.GetString(name));
            }
            if (Protocols.Count == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Empty ALPN protocol list.");
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            byte[] body = Body();
            destination[offset] = 0x00;
            destination[offset + 1] = 0x10;
            destination[offset + 2] = (byte)(body.Length >> 8);
            destination[offset + 3] = (byte)body.Length;
            body.CopyTo(destination, offset + 4);
            return 4 + body.Length;
        }

        /// <summary>
        /// The server's choice (RFC 7301 §3.2): its first protocol the client offers. Null when either side has no
        /// list; no common protocol aborts with no_application_protocol.
        /// </summary>
        public static string Select(IList<string> serverPreference, AlpnExtension offered)
        {
            if (offered == null || serverPreference == null || serverPreference.Count == 0)
                return null;
            return serverPreference.FirstOrDefault(offered.Protocols.Contains)
                ?? throw new DtlsException(AlertDescription.NoApplicationProtocol, "No application protocol in common.");
        }

        /// <summary>Checks the server's reply: exactly one protocol, one we offered (RFC 7301 §3.1).</summary>
        public static string Accept(IList<string> offered, AlpnExtension reply)
        {
            if (reply == null)
                return null;
            if (offered == null || reply.Protocols.Count != 1 || !offered.Contains(reply.Protocols[0]))
                throw new DtlsException(AlertDescription.IllegalParameter, "Server selected an application protocol that was not offered.");
            return reply.Protocols[0];
        }
    }

    /// <summary>
    /// connection_id (RFC 9146 §3, RFC 9147 §9): the CID the sender wants to receive; empty when it only supports
    /// sending CIDs.
    /// </summary>
    public class ConnectionIdExtension : ITlsExtension
    {
        public const ushort Type = 0x0036;

        public ConnectionIdExtension() { }

        public ConnectionIdExtension(byte[] connectionId)
        {
            if (connectionId == null || connectionId.Length > 255)
                throw new ArgumentException("A connection ID is 0 to 255 bytes.", nameof(connectionId));
            ConnectionId = connectionId;
        }

        public byte[] ConnectionId { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 5 + ConnectionId.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 1 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid connection_id extension.");
            ConnectionId = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x36;
            destination[offset + 2] = (byte)((1 + ConnectionId.Length) >> 8);
            destination[offset + 3] = (byte)(1 + ConnectionId.Length);
            destination[offset + 4] = (byte)ConnectionId.Length;
            ConnectionId.CopyTo(destination, offset + 5);
            return 5 + ConnectionId.Length;
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
