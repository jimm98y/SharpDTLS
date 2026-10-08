using System;
using System.Collections.Concurrent;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// A DTLS 1.0/1.2 session that can be resumed with an abbreviated handshake (RFC 5246 §7.3). Only sessions
    /// with an extended master secret are resumable (RFC 7627 §5.3).
    /// </summary>
    public sealed class Dtls12SessionState
    {
        internal Dtls12SessionState(byte[] sessionId, ushort version, ushort cipherSuite, byte[] masterSecret, bool encryptThenMac,
            byte[] peerCertificate, DateTime? createdUtc = null, byte[] ticket = null, uint ticketLifetimeHint = 0)
        {
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
        public ushort CipherSuite { get; }

        /// <summary>Whether the session uses encrypt-then-MAC (RFC 7366); resumption keeps the setting.</summary>
        public bool EncryptThenMac { get; }

        /// <summary>The peer's certificate (DER) from the full handshake, or null.</summary>
        public byte[] PeerCertificate { get; }

        public DateTime CreatedUtc { get; }

        internal byte[] MasterSecret { get; }

        internal Dtls12SessionState WithTicket(byte[] ticket, uint lifetimeHint)
            => new(SessionId, Version, CipherSuite, MasterSecret, EncryptThenMac, PeerCertificate, CreatedUtc, ticket, lifetimeHint);

        // The server-side state sealed into a ticket (the session ID is not part of it).
        internal byte[] Serialize()
            => new TlsWriter()
                .WriteUInt8(StateVersion)
                .WriteUInt16(Version).WriteUInt16(CipherSuite).WriteUInt8(EncryptThenMac ? (byte)1 : (byte)0)
                .WriteUInt32((uint)(new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds() >> 32)).WriteUInt32((uint)new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds())
                .WriteOpaque8(MasterSecret).WriteOpaque24(PeerCertificate ?? Array.Empty<byte>())
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
            r.EnsureEnd();
            return new Dtls12SessionState(Array.Empty<byte>(), version, cipherSuite, masterSecret, encryptThenMac,
                peerCertificate.Length == 0 ? null : peerCertificate, DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime);
        }
    }

    /// <summary>Server-side storage of resumable sessions, keyed by session ID.</summary>
    public interface IDtls12SessionCache
    {
        void Store(Dtls12SessionState session);

        /// <summary>The session with this ID, or null when unknown or expired.</summary>
        Dtls12SessionState Find(byte[] sessionId);

        void Remove(byte[] sessionId);
    }

    /// <summary>An in-memory session cache with a lifetime and a size bound (oldest sessions are evicted first).</summary>
    public sealed class Dtls12SessionCache : IDtls12SessionCache
    {
        private readonly ConcurrentDictionary<string, Dtls12SessionState> _sessions = new();

        /// <summary>How long a session can be resumed (RFC 5246 §F.1.4 suggests at most 24 hours).</summary>
        public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(2);

        public int Capacity { get; set; } = 10000;

        public int Count => _sessions.Count;

        public void Store(Dtls12SessionState session)
        {
            _sessions[Key(session.SessionId)] = session;
            if (_sessions.Count <= Capacity)
                return;

            var cutoff = DateTime.UtcNow - Lifetime;
            foreach (var entry in _sessions.Where(e => e.Value.CreatedUtc < cutoff).ToList())
                _sessions.TryRemove(entry);
            foreach (var entry in _sessions.OrderBy(e => e.Value.CreatedUtc).Take(_sessions.Count - Capacity).ToList())
                _sessions.TryRemove(entry);
        }

        public Dtls12SessionState Find(byte[] sessionId)
        {
            if (!_sessions.TryGetValue(Key(sessionId), out var session))
                return null;
            if (DateTime.UtcNow - session.CreatedUtc <= Lifetime)
                return session;
            _sessions.TryRemove(Key(sessionId), out _);
            return null;
        }

        public void Remove(byte[] sessionId) => _sessions.TryRemove(Key(sessionId), out _);

        private static string Key(byte[] sessionId) => Convert.ToHexString(sessionId);
    }
}
