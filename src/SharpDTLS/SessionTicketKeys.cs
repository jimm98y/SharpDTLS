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
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS
{
    /// <summary>
    /// Keys that protect session tickets (RFC 5077 for DTLS 1.0/1.2, RFC 8446 §4.6.1 for DTLS 1.3):
    /// key_name(16) || nonce(12) || AES-256-GCM(state), with key_name as additional data. Servers that share keys can
    /// resume each other's sessions. <see cref="Rotate"/> starts a new key and keeps the previous one for decryption;
    /// DTLS 1.0/1.2 tickets under it are renewed when used. Keys rotate by themselves every <see cref="RotationInterval"/>.
    /// </summary>
    public sealed class SessionTicketKeys
    {
        private readonly object _lock = new();
        private (byte[] Name, byte[] Key) _current = NewKey();
        private (byte[] Name, byte[] Key)? _previous;
        private DateTime _currentSince = DateTime.UtcNow;

        /// <summary>
        /// How long a ticket can be used: from the full handshake for DTLS 1.0/1.2, from issue for DTLS 1.3 (at most
        /// 7 days, RFC 8446 §4.6.1). Also the lifetime sent with the ticket.
        /// </summary>
        public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(2);

        /// <summary>
        /// How long a key seals new tickets before <see cref="Rotate"/> runs by itself, so that one key disclosed opens
        /// the tickets of a bounded time; a ticket stays readable for one more interval. <see cref="Lifetime"/> when
        /// null (the default); <see cref="TimeSpan.Zero"/> to rotate only when Rotate is called, as servers that share
        /// keys do, rotating them together.
        /// </summary>
        public TimeSpan? RotationInterval { get; set; }

        public void Rotate()
        {
            lock (_lock)
                RotateLocked();
        }

        private void RotateLocked()
        {
            _previous = _current;
            _current = NewKey();
            _currentSince = DateTime.UtcNow;
        }

        private static (byte[], byte[]) NewKey() => (RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32));

        internal byte[] Seal(byte[] state)
        {
            byte[] name, key;
            lock (_lock)
            {
                TimeSpan interval = RotationInterval ?? Lifetime;
                if (interval > TimeSpan.Zero && DateTime.UtcNow - _currentSince >= interval)
                    RotateLocked();
                (name, key) = _current;
            }
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            var gcm = BouncyCastleTlsCrypto.Default.CreateAead(TlsAeadAlgorithm.AesGcm, key);
            byte[] sealedState = new byte[state.Length + gcm.TagLength];
            gcm.Seal(nonce, name, state, sealedState);
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

            var gcm = BouncyCastleTlsCrypto.Default.CreateAead(TlsAeadAlgorithm.AesGcm, key);
            byte[] state = new byte[ticket.Length - 28 - gcm.TagLength];
            return gcm.Open(ticket.AsSpan(16, 12), ticket.AsSpan(0, 16), ticket.AsSpan(28), state) ? state : null;
        }
    }
}
