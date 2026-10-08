using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS
{
    /// <summary>
    /// Keys that protect session tickets (RFC 5077 for DTLS 1.0/1.2, RFC 8446 §4.6.1 for DTLS 1.3):
    /// key_name(16) || nonce(12) || AES-256-GCM(state), with key_name as additional data. Servers that share keys can
    /// resume each other's sessions. <see cref="Rotate"/> starts a new key and keeps the previous one for decryption;
    /// DTLS 1.0/1.2 tickets under it are renewed when used.
    /// </summary>
    public sealed class SessionTicketKeys
    {
        private readonly object _lock = new();
        private (byte[] Name, byte[] Key) _current = NewKey();
        private (byte[] Name, byte[] Key)? _previous;

        /// <summary>
        /// How long a ticket can be used: from the full handshake for DTLS 1.0/1.2, from issue for DTLS 1.3 (at most
        /// 7 days, RFC 8446 §4.6.1). Also the lifetime sent with the ticket.
        /// </summary>
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

        internal byte[] Seal(byte[] state)
        {
            byte[] name, key;
            lock (_lock)
                (name, key) = _current;
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, name));
            byte[] sealedState = new byte[gcm.GetOutputSize(state.Length)];
            gcm.DoFinal(sealedState, gcm.ProcessBytes(state, 0, state.Length, sealedState, 0));
            CryptographicOperations.ZeroMemory(state);
            return name.Concat(nonce).Concat(sealedState).ToArray();
        }

        /// <summary>The state in a ticket, or null when the ticket is unknown or forged.</summary>
        internal byte[] Open(byte[] ticket, out bool renew)
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
                return state;
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }
        }
    }
}
