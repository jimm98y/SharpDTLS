using System;

namespace SharpDTLS
{
    /// <summary>
    /// (D)TLS 1.3 downgrade protection (RFC 8446 §4.1.3, RFC 9147 §5.3): the last 8 bytes of a lower version's
    /// ServerHello.random.
    /// </summary>
    internal static class Downgrade
    {
        private static readonly byte[] Tls12 = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 }; // "DOWNGRD" 01
        private static readonly byte[] Tls11OrBelow = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 }; // "DOWNGRD" 00

        public static void Mark(byte[] serverRandom, ushort negotiatedVersion)
            => (ProtocolVersions.Level(negotiatedVersion) == 3 ? Tls12 : Tls11OrBelow).CopyTo(serverRandom, 24);

        /// <summary>Whether a ServerHello.random of a (D)TLS 1.2-or-lower handshake carries either sentinel.</summary>
        public static bool IsMarked(byte[] serverRandom)
            => serverRandom.AsSpan(24).SequenceEqual(Tls12) || serverRandom.AsSpan(24).SequenceEqual(Tls11OrBelow);
    }
}
