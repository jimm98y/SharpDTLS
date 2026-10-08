using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// A DTLS 1.3 session ticket received from a server (RFC 8446 §4.6.1), usable for PSK resumption.
    /// </summary>
    public sealed class Dtls13SessionTicket
    {
        internal Dtls13SessionTicket(byte[] ticket, uint lifetimeSeconds, uint ageAdd, ushort cipherSuite, byte[] psk, byte[] serverCertificate)
        {
            Ticket = ticket;
            LifetimeSeconds = lifetimeSeconds;
            AgeAdd = ageAdd;
            CipherSuite = cipherSuite;
            Psk = psk;
            ServerCertificate = serverCertificate;
            ReceivedUtc = DateTime.UtcNow;
        }

        /// <summary>The opaque ticket, sent back as the PSK identity.</summary>
        public byte[] Ticket { get; }

        public uint LifetimeSeconds { get; }

        /// <summary>The suite of the session that issued the ticket; resumption needs a suite with the same hash.</summary>
        public ushort CipherSuite { get; }

        /// <summary>The server's certificate (DER) from the full handshake.</summary>
        public byte[] ServerCertificate { get; }

        public DateTime ReceivedUtc { get; }

        public bool IsExpired => DateTime.UtcNow - ReceivedUtc >= TimeSpan.FromSeconds(LifetimeSeconds);

        internal uint AgeAdd { get; }
        internal byte[] Psk { get; }

        /// <summary>obfuscated_ticket_age = (milliseconds since the ticket arrived + ticket_age_add) mod 2^32.</summary>
        internal uint ObfuscatedAge => unchecked((uint)(DateTime.UtcNow - ReceivedUtc).TotalMilliseconds + AgeAdd);
    }

    /// <summary>What a DTLS 1.3 server seals into a ticket.</summary>
    internal sealed class Dtls13TicketState
    {
        private const byte StateVersion = 0x13;

        public ushort CipherSuite { get; init; }
        public byte[] Psk { get; init; }
        public uint AgeAdd { get; init; }
        public DateTime IssuedUtc { get; init; }
        public byte[] ClientCertificate { get; init; }

        public byte[] Seal(SessionTicketKeys keys)
            => keys.Seal(new TlsWriter()
                .WriteUInt8(StateVersion)
                .WriteUInt16(CipherSuite)
                .WriteUInt32(AgeAdd)
                .WriteUInt32((uint)(new DateTimeOffset(IssuedUtc).ToUnixTimeSeconds() >> 32)).WriteUInt32((uint)new DateTimeOffset(IssuedUtc).ToUnixTimeSeconds())
                .WriteOpaque8(Psk)
                .WriteOpaque24(ClientCertificate ?? Array.Empty<byte>())
                .ToArray());

        /// <summary>The state in a ticket, or null when it is unknown, forged, from DTLS 1.0/1.2 or expired.</summary>
        public static Dtls13TicketState Open(SessionTicketKeys keys, byte[] ticket)
        {
            byte[] state = keys.Open(ticket, out _);
            if (state == null || state.Length == 0 || state[0] != StateVersion)
                return null;
            try
            {
                var r = new TlsReader(state);
                r.ReadUInt8();
                ushort cipherSuite = r.ReadUInt16();
                uint ageAdd = r.ReadUInt32();
                var issuedUtc = DateTimeOffset.FromUnixTimeSeconds(((long)r.ReadUInt32() << 32) | r.ReadUInt32()).UtcDateTime;
                byte[] psk = r.ReadOpaque8();
                byte[] certificate = r.ReadOpaque24();
                r.EnsureEnd();
                if (DateTime.UtcNow - issuedUtc >= keys.Lifetime || !Dtls13CipherSuite.IsSupported(cipherSuite))
                    return null;
                return new Dtls13TicketState
                {
                    CipherSuite = cipherSuite, AgeAdd = ageAdd, IssuedUtc = issuedUtc, Psk = psk,
                    ClientCertificate = certificate.Length == 0 ? null : certificate,
                };
            }
            catch (DtlsException)
            {
                return null;
            }
        }
    }

    /// <summary>psk_key_exchange_modes (RFC 8446 §4.2.9): psk_ke(0), psk_dhe_ke(1).</summary>
    public class PskKeyExchangeModesExtension : ITlsExtension
    {
        public const ushort Type = 0x002d;
        public const byte PskKe = 0;
        public const byte PskDheKe = 1;

        public PskKeyExchangeModesExtension() { }
        public PskKeyExchangeModesExtension(params byte[] modes) => Modes = modes;

        public byte[] Modes { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 5 + Modes.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 2 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid psk_key_exchange_modes extension.");
            Modes = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x2d;
            destination[offset + 2] = (byte)((1 + Modes.Length) >> 8);
            destination[offset + 3] = (byte)(1 + Modes.Length);
            destination[offset + 4] = (byte)Modes.Length;
            Modes.CopyTo(destination, offset + 5);
            return 5 + Modes.Length;
        }
    }

    /// <summary>
    /// pre_shared_key in ClientHello (RFC 8446 §4.2.11): identities&lt;7..2^16-1&gt; (identity&lt;1..2^16-1&gt;,
    /// obfuscated_ticket_age) and binders&lt;33..2^16-1&gt;. It must be the last extension.
    /// </summary>
    public class ClientPreSharedKeyExtension : ITlsExtension
    {
        public const ushort Type = 0x0029;

        public List<(byte[] Identity, uint ObfuscatedAge)> Identities { get; } = new();
        public List<byte[]> Binders { get; } = new();

        /// <summary>Bytes the binders list occupies at the end of the ClientHello (excluded from the binder transcript).</summary>
        public int BindersLength => 2 + Binders.Sum(b => 1 + b.Length);

        public int CalculateLength() => 4 + 2 + Identities.Sum(i => 2 + i.Identity.Length + 4) + BindersLength;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid pre_shared_key extension.");
            var r = new TlsReader(source.AsSpan(offset + 4, length).ToArray());
            var identities = new TlsReader(r.ReadOpaque16());
            while (identities.Remaining > 0)
                Identities.Add((identities.ReadOpaque16(), identities.ReadUInt32()));
            var binders = new TlsReader(r.ReadOpaque16());
            while (binders.Remaining > 0)
                Binders.Add(binders.ReadOpaque8());
            r.EnsureEnd();
            if (Identities.Count == 0 || Identities.Count != Binders.Count || Identities.Any(i => i.Identity.Length == 0) || Binders.Any(b => b.Length < 32))
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid pre_shared_key identities or binders.");
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            var identities = new TlsWriter();
            foreach (var (identity, age) in Identities)
                identities.WriteOpaque16(identity).WriteUInt32(age);
            var binders = new TlsWriter();
            foreach (byte[] binder in Binders)
                binders.WriteOpaque8(binder);
            byte[] body = new TlsWriter().WriteOpaque16(identities.ToArray()).WriteOpaque16(binders.ToArray()).ToArray();

            destination[offset] = 0x00;
            destination[offset + 1] = 0x29;
            destination[offset + 2] = (byte)(body.Length >> 8);
            destination[offset + 3] = (byte)body.Length;
            body.CopyTo(destination, offset + 4);
            return 4 + body.Length;
        }
    }

    /// <summary>pre_shared_key in ServerHello: the selected identity index.</summary>
    public class ServerPreSharedKeyExtension : ITlsExtension
    {
        public ServerPreSharedKeyExtension() { }
        public ServerPreSharedKeyExtension(ushort selectedIdentity) => SelectedIdentity = selectedIdentity;

        public ushort SelectedIdentity { get; private set; }

        public int CalculateLength() => 6;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length != 2 || source.Length < offset + 6)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid pre_shared_key extension.");
            SelectedIdentity = (ushort)((source[offset + 4] << 8) | source[offset + 5]);
            return 6;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0x00;
            destination[offset + 1] = 0x29;
            destination[offset + 2] = 0x00;
            destination[offset + 3] = 0x02;
            destination[offset + 4] = (byte)(SelectedIdentity >> 8);
            destination[offset + 5] = (byte)SelectedIdentity;
            return 6;
        }
    }

    internal static class PskBinders
    {
        /// <summary>
        /// The ClientHello in TLS form (RFC 9147 §5.2: without message_seq and fragment fields) up to, but not
        /// including, the binders list; its handshake length still counts the binders (RFC 8446 §4.2.11.2).
        /// <paramref name="record"/> is the unfragmented ClientHello in a plaintext record.
        /// </summary>
        public static byte[] TruncatedClientHello(byte[] record, int bindersLength)
        {
            int length = (record[14] << 16) | (record[15] << 8) | record[16];
            byte[] tlsForm = new byte[4 + length - bindersLength];
            Buffer.BlockCopy(record, 13, tlsForm, 0, 4);
            Buffer.BlockCopy(record, 25, tlsForm, 4, length - bindersLength);
            return tlsForm;
        }
    }
}
