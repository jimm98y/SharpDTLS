namespace SharpDTLS
{
    /// <summary>
    /// Per-epoch receive state: anti-replay sliding window (RFC 6347 §4.1.2.6, RFC 9147 §4.5.1)
    /// and DTLS 1.3 sequence number reconstruction (RFC 9147 §4.2.2).
    /// </summary>
    public sealed class RecordWindow
    {
        public const int WindowSize = 64;

        private ulong _bitmap;   // bit i set => (Highest - i) has been received
        private bool _any;

        /// <summary>Highest sequence number successfully deprotected in this epoch.</summary>
        public ulong Highest { get; private set; }

        public bool IsDuplicate(ulong seq)
        {
            if (!_any || seq > Highest)
                return false;

            ulong diff = Highest - seq;
            if (diff >= WindowSize)
                return true; // too old to tell, treat as replay

            return (_bitmap & (1UL << (int)diff)) != 0;
        }

        /// <summary>Records <paramref name="seq"/> as received. Call only after the record authenticated.</summary>
        public void Mark(ulong seq)
        {
            if (!_any)
            {
                _any = true;
                Highest = seq;
                _bitmap = 1;
                return;
            }

            if (seq > Highest)
            {
                ulong shift = seq - Highest;
                _bitmap = shift >= WindowSize ? 1 : (_bitmap << (int)shift) | 1;
                Highest = seq;
            }
            else
            {
                ulong diff = Highest - seq;
                if (diff < WindowSize)
                    _bitmap |= 1UL << (int)diff;
            }
        }

        /// <summary>
        /// Reconstructs the full 48-bit sequence number from its low <paramref name="bits"/> bits,
        /// choosing the value numerically closest to one plus the highest deprotected sequence number.
        /// </summary>
        public ulong Reconstruct(ulong truncated, int bits)
        {
            ulong expected = _any ? Highest + 1 : 0;
            ulong range = 1UL << bits;
            ulong mask = range - 1;

            ulong candidate = (expected & ~mask) | (truncated & mask);
            ulong half = range / 2;

            if (candidate + half < expected && candidate + range <= 0xFFFFFFFFFFFFUL)
                candidate += range;
            else if (candidate > expected + half && candidate >= range)
                candidate -= range;

            return candidate;
        }
    }
}
