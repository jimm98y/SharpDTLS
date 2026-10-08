using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;

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
                .WriteUInt16(Version).WriteUInt16(CipherSuite).WriteUInt8(EncryptThenMac ? (byte)1 : (byte)0)
                .WriteUInt32((uint)(new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds() >> 32)).WriteUInt32((uint)new DateTimeOffset(CreatedUtc).ToUnixTimeSeconds())
                .WriteOpaque8(MasterSecret).WriteOpaque24(PeerCertificate ?? Array.Empty<byte>())
                .ToArray();

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

    /// <summary>
    /// Keys that protect RFC 5077 session tickets: key_name(16) || nonce(12) || AES-256-GCM(state), with key_name
    /// as additional data. Servers that share keys can resume each other's sessions. <see cref="Rotate"/> starts a
    /// new key and keeps the previous one for decryption; tickets under it are renewed when used.
    /// </summary>
    public sealed class Dtls12TicketKeys
    {
        private readonly object _lock = new();
        private (byte[] Name, byte[] Key) _current = NewKey();
        private (byte[] Name, byte[] Key)? _previous;

        /// <summary>How long a session can be resumed with a ticket, from its full handshake; also the lifetime hint.</summary>
        public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(2);

        public void Rotate()
        {
            lock (_lock)
            {
                _previous = _current;
                _current = NewKey();
            }
        }

        private static (byte[], byte[]) NewKey() => (RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32));

        internal byte[] Seal(Dtls12SessionState session)
        {
            byte[] name, key;
            lock (_lock)
                (name, key) = _current;
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] state = session.Serialize();
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, name));
            byte[] sealedState = new byte[gcm.GetOutputSize(state.Length)];
            gcm.DoFinal(sealedState, gcm.ProcessBytes(state, 0, state.Length, sealedState, 0));
            CryptographicOperations.ZeroMemory(state);
            return name.Concat(nonce).Concat(sealedState).ToArray();
        }

        /// <summary>The session in a ticket, or null when it is unknown, forged or expired.</summary>
        internal Dtls12SessionState Open(byte[] ticket, out bool renew)
        {
            renew = false;
            if (ticket.Length < 16 + 12 + 16)
                return null;
            (byte[] Name, byte[] Key) current;
            (byte[] Name, byte[] Key)? previous;
            lock (_lock)
                (current, previous) = (_current, _previous);
            byte[] key;
            if (ticket.AsSpan(0, 16).SequenceEqual(current.Name))
                key = current.Key;
            else if (previous.HasValue && ticket.AsSpan(0, 16).SequenceEqual(previous.Value.Name))
                (key, renew) = (previous.Value.Key, true);
            else
                return null;

            try
            {
                var gcm = new GcmBlockCipher(new AesEngine());
                gcm.Init(false, new AeadParameters(new KeyParameter(key), 128, ticket.AsSpan(16, 12).ToArray(), ticket.AsSpan(0, 16).ToArray()));
                byte[] state = new byte[gcm.GetOutputSize(ticket.Length - 28)];
                gcm.DoFinal(state, gcm.ProcessBytes(ticket, 28, ticket.Length - 28, state, 0));
                var session = Dtls12SessionState.Deserialize(state);
                return DateTime.UtcNow - session.CreatedUtc <= Lifetime ? session : null;
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }
            catch (DtlsException)
            {
                return null;
            }
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
