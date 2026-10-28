using System;
using System.Collections.Concurrent;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// A resumable session: a 1.0-1.2 session (session ID or RFC 5077 ticket) or a 1.3 session ticket (RFC 8446 §4.6.1).
    /// A client resumes it when it is set as the client's ResumptionSession.
    /// </summary>
    public abstract class TlsSession
    {
        private protected TlsSession() { }

        /// <summary>The cipher suite of the full handshake.</summary>
        public abstract ushort CipherSuite { get; }

        /// <summary>The server_name of the full handshake; the session is offered only for the same name (RFC 6066 §3).</summary>
        public abstract string ServerName { get; }

        /// <summary>The peer's certificate (DER) from the full handshake, or null.</summary>
        public abstract byte[] PeerCertificate { get; }

        /// <summary>When the session was established, or when its ticket arrived.</summary>
        public abstract DateTime CreatedUtc { get; }

        /// <summary>How much 0-RTT data the server accepts when resuming this session (TLS/DTLS 1.3 tickets only; 0: none).</summary>
        public virtual uint MaxEarlyDataSize => 0;
    }

    /// <summary>Server-side storage of resumable 1.0-1.2 sessions, keyed by session ID (1.3 resumes with tickets only).</summary>
    public interface ITlsSessionCache
    {
        void Store(byte[] sessionId, TlsSession session);

        /// <summary>The session with this ID, or null when unknown or expired.</summary>
        TlsSession Find(byte[] sessionId);

        void Remove(byte[] sessionId);
    }

    /// <summary>An in-memory session cache with a lifetime and a size bound (oldest sessions are evicted first).</summary>
    public sealed class TlsSessionCache : ITlsSessionCache
    {
        private readonly ConcurrentDictionary<string, TlsSession> _sessions = new();

        /// <summary>How long a session can be resumed (RFC 5246 §F.1.4 suggests at most 24 hours).</summary>
        public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(2);

        public int Capacity { get; set; } = 10000;

        public int Count => _sessions.Count;

        public void Store(byte[] sessionId, TlsSession session)
        {
            _sessions[Key(sessionId)] = session;
            if (_sessions.Count <= Capacity)
                return;

            var cutoff = DateTime.UtcNow - Lifetime;
            foreach (var entry in _sessions.Where(e => e.Value.CreatedUtc < cutoff).ToList())
                _sessions.TryRemove(entry);
            foreach (var entry in _sessions.OrderBy(e => e.Value.CreatedUtc).Take(_sessions.Count - Capacity).ToList())
                _sessions.TryRemove(entry);
        }

        public TlsSession Find(byte[] sessionId)
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
