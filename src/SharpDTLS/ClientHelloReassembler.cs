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
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// Reassembles fragmented ClientHello records for endpoints that have no association yet.
    /// A ClientHello larger than the path MTU (many extensions, large key shares) arrives in several
    /// records; servers must reassemble it before they can answer. Memory use is bounded: few pending
    /// endpoints, a size cap per message, and entries expire.
    /// </summary>
    internal sealed class ClientHelloReassembler
    {
        private const int MaxPendingEndpoints = 64;
        private const int MaxClientHelloLength = 16 * 1024;
        private static readonly TimeSpan Expiry = TimeSpan.FromSeconds(10);

        private readonly object _sync = new object();
        private readonly Dictionary<string, (HandshakeReassembler Reassembler, DateTime Created)> _pending = new();

        /// <summary>
        /// Adds an epoch-0 ClientHello record (possibly a fragment). Returns true with the complete,
        /// defragmented record once every fragment has arrived.
        /// </summary>
        public bool TryAdd(string endpoint, byte[] record, out byte[] complete)
        {
            complete = null;
            if (record.Length < 25 || record[0] != 0x16 || record[13] != 0x01)
                return false;

            int totalLength = (record[14] << 16) | (record[15] << 8) | record[16];
            int fragmentOffset = (record[19] << 16) | (record[20] << 8) | record[21];
            int fragmentLength = (record[22] << 16) | (record[23] << 8) | record[24];

            if (fragmentOffset == 0 && fragmentLength == totalLength)
            {
                lock (_sync) _pending.Remove(endpoint);
                complete = record;
                return true;
            }

            if (totalLength > MaxClientHelloLength)
                return false;

            lock (_sync)
            {
                DateTime now = DateTime.UtcNow;
                foreach (var stale in _pending.Where(p => now - p.Value.Created > Expiry).Select(p => p.Key).ToList())
                    _pending.Remove(stale);

                if (!_pending.TryGetValue(endpoint, out var entry))
                {
                    // Full: evict the oldest rather than refuse the newcomer. These entries exist before any cookie
                    // exchange, so spoofed sources can fill the table; refusing new endpoints would let a few spoofed
                    // fragments a second lock every real client with a fragmented ClientHello out. A real client sends
                    // its fragments back to back, so it completes long before a flood can evict it.
                    if (_pending.Count >= MaxPendingEndpoints)
                        _pending.Remove(_pending.OrderBy(p => p.Value.Created).First().Key);
                    entry = (new HandshakeReassembler(), now);
                    _pending[endpoint] = entry;
                }

                if (!entry.Reassembler.TryAddUnencryptedFragment(record, out complete))
                    return false;

                _pending.Remove(endpoint);
                return true;
            }
        }
    }
}
