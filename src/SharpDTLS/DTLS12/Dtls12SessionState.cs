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
            byte[] peerCertificate)
        {
            SessionId = sessionId;
            Version = version;
            CipherSuite = cipherSuite;
            MasterSecret = masterSecret;
            EncryptThenMac = encryptThenMac;
            PeerCertificate = peerCertificate;
            CreatedUtc = DateTime.UtcNow;
        }

        /// <summary>The server-assigned session ID (RFC 5246 §7.4.1.3).</summary>
        public byte[] SessionId { get; }

        public ushort Version { get; }
        public ushort CipherSuite { get; }

        /// <summary>Whether the session uses encrypt-then-MAC (RFC 7366); resumption keeps the setting.</summary>
        public bool EncryptThenMac { get; }

        /// <summary>The peer's certificate (DER) from the full handshake, or null.</summary>
        public byte[] PeerCertificate { get; }

        public DateTime CreatedUtc { get; }

        internal byte[] MasterSecret { get; }
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
