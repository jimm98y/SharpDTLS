// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using System;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// A DTLS 1.0/1.2 session that can be resumed with an abbreviated handshake (RFC 5246 §7.3). Only sessions
    /// with an extended master secret are resumable (RFC 7627 §5.3).
    /// </summary>
    internal sealed class Dtls12SessionState : TlsSession
    {
        internal Dtls12SessionState(byte[] sessionId, ushort version, ushort cipherSuite, byte[] masterSecret, bool encryptThenMac,
            byte[] peerCertificate, DateTime? createdUtc = null, byte[] ticket = null, uint ticketLifetimeHint = 0, string serverName = null)
        {
            ServerName = serverName;
            SessionId = sessionId;
            Version = version;
            CipherSuite = cipherSuite;
            MasterSecret = masterSecret;
            EncryptThenMac = encryptThenMac;
            PeerCertificate = peerCertificate;
            CreatedUtc = createdUtc ?? DateTime.UtcNow;
            Ticket = ticket;
            TicketLifetimeHint = ticketLifetimeHint;
        }

        /// <summary>The server-assigned session ID (RFC 5246 §7.4.1.3); empty for a ticket-only session.</summary>
        public byte[] SessionId { get; }

        /// <summary>The server's session ticket (RFC 5077), or null.</summary>
        public byte[] Ticket { get; }

        /// <summary>The server's ticket lifetime hint in seconds (0: unspecified).</summary>
        public uint TicketLifetimeHint { get; }

        public ushort Version { get; }
        public override ushort CipherSuite { get; }

        /// <summary>Whether the session uses encrypt-then-MAC (RFC 7366); resumption keeps the setting.</summary>
        public bool EncryptThenMac { get; }

        /// <summary>The peer's certificate (DER) from the full handshake, or null.</summary>
        public override byte[] PeerCertificate { get; }

        public override DateTime CreatedUtc { get; }

        /// <summary>The server_name of the full handshake; resumption requires the same name (RFC 6066 §3).</summary>
        public override string ServerName { get; }

        internal byte[] MasterSecret { get; }

        internal Dtls12SessionState WithTicket(byte[] ticket, uint lifetimeHint)
            => new(SessionId, Version, CipherSuite, MasterSecret, EncryptThenMac, PeerCertificate, CreatedUtc, ticket, lifetimeHint, ServerName);

        // The server-side state sealed into a ticket (the session ID is not part of it).
        internal byte[] Serialize()
            => new TlsWriter()
                .WriteUInt8(StateVersion)
                .WriteUInt16(Version).WriteUInt16(CipherSuite).WriteUInt8(EncryptThenMac ? (byte)1 : (byte)0)
                .WriteUInt32((uint)(new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds() >> 32)).WriteUInt32((uint)new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds())
                .WriteOpaque8(MasterSecret).WriteOpaque24(PeerCertificate ?? Array.Empty<byte>())
                .WriteOpaque16(System.Text.Encoding.ASCII.GetBytes(ServerName ?? ""))
                .ToArray();

        internal byte[] Seal(SessionTicketKeys keys) => keys.Seal(Serialize());

        /// <summary>The session in a ticket, or null when it is unknown, forged, from another protocol version or expired.</summary>
        internal static Dtls12SessionState Open(SessionTicketKeys keys, byte[] ticket, out bool renew)
        {
            byte[] state = keys.Open(ticket, out renew);
            if (state == null || state.Length == 0 || state[0] != StateVersion)
                return null;
            try
            {
                var session = Deserialize(state.AsSpan(1).ToArray());
                return DateTime.UtcNow - session.CreatedUtc <= keys.Lifetime ? session : null;
            }
            catch (DtlsException)
            {
                return null;
            }
        }

        // Distinguishes DTLS 1.0/1.2 ticket state from DTLS 1.3 state under the same keys.
        private const byte StateVersion = 0x12;

        internal static Dtls12SessionState Deserialize(byte[] data)
        {
            var r = new TlsReader(data);
            ushort version = r.ReadUInt16();
            ushort cipherSuite = r.ReadUInt16();
            bool encryptThenMac = r.ReadUInt8() == 1;
            long seconds = ((long)r.ReadUInt32() << 32) | r.ReadUInt32();
            byte[] masterSecret = r.ReadOpaque8();
            byte[] peerCertificate = r.ReadOpaque24();
            string serverName = System.Text.Encoding.ASCII.GetString(r.ReadOpaque16());
            r.EnsureEnd();
            return new Dtls12SessionState(Array.Empty<byte>(), version, cipherSuite, masterSecret, encryptThenMac,
                peerCertificate.Length == 0 ? null : peerCertificate, DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime,
                serverName: serverName.Length == 0 ? null : serverName);
        }
    }

}
