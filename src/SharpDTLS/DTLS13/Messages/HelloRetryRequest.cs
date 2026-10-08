using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.DTLS13.Messages
{
    /// <summary>
    /// HelloRetryRequest: a ServerHello with the special random value (RFC 8446 §4.1.3).
    /// </summary>
    public class HelloRetryRequest : ServerHelloDatagram
    {
        public static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

        public HelloRetryRequest()
        { }

        /// <param name="selectedGroup">Group the client must send a key share for, or null when the client's share is acceptable.</param>
        public HelloRetryRequest(ushort cipherSuite, byte[] cookie, ushort? selectedGroup, byte[] legacySessionIdEcho)
        {
            ServerRandom = (byte[])HelloRetryRequestRandom.Clone();
            SelectedCipherSuite = cipherSuite;
            LegacySessionIdEcho = legacySessionIdEcho ?? Array.Empty<byte>();

            var extensions = new List<ITlsExtension> { new ServerSupportedVersions() };
            if (selectedGroup.HasValue)
                extensions.Add(new ServerKeyShareExtension(selectedGroup.Value, null));
            extensions.Add(new CookieExtension(cookie));
            Extensions = extensions;
        }

        public static bool IsHelloRetryRequest(ServerHelloDatagram serverHello)
            => serverHello.ServerRandom != null && serverHello.ServerRandom.AsSpan().SequenceEqual(HelloRetryRequestRandom);
    }
}
