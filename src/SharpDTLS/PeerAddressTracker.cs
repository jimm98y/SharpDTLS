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

using System.Net;

namespace SharpDTLS
{
    /// <summary>
    /// Follows a peer's address for connections with connection IDs (RFC 9146 §6, RFC 9147 §11). A new source
    /// address counts only for a record that carried our CID, authenticated, and is newer than any record
    /// before it; replayed or reordered records cannot move the connection. Whether replies follow at once or
    /// only after the application confirms the address is the caller's policy.
    /// </summary>
    internal sealed class PeerAddressTracker
    {
        private ulong _epoch;
        private ulong _sequence;
        private bool _any;

        public PeerAddressTracker(EndPoint initial) => Current = initial;

        /// <summary>Where replies go.</summary>
        public EndPoint Current { get; private set; }

        /// <summary>A newer address seen but not confirmed yet, or null.</summary>
        public EndPoint Pending { get; private set; }

        /// <summary>
        /// Records an authenticated record. Returns true when it reveals a new peer address; with
        /// <paramref name="follow"/> replies move there at once, otherwise it becomes <see cref="Pending"/>.
        /// </summary>
        public bool Observe(ulong epoch, ulong sequenceNumber, bool withConnectionId, EndPoint source, bool follow, out EndPoint previous)
        {
            previous = Current;
            bool newer = !_any || epoch > _epoch || (epoch == _epoch && sequenceNumber > _sequence);
            if (!newer)
                return false;
            _any = true;
            (_epoch, _sequence) = (epoch, sequenceNumber);

            if (!withConnectionId || source == null || source.Equals(Current) || source.Equals(Pending))
                return false;
            if (follow)
                Current = source;
            else
                Pending = source;
            return true;
        }

        /// <summary>Moves replies to <paramref name="address"/>, normally the pending address the application has verified.</summary>
        public void Confirm(EndPoint address)
        {
            Current = address;
            if (address.Equals(Pending))
                Pending = null;
        }
    }
}
