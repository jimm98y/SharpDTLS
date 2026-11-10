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

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// HelloRetryRequest: a ServerHello with the special random value (RFC 8446 §4.1.3).
    /// </summary>
    internal class HelloRetryRequest : ServerHelloDatagram
    {
        public static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

        public HelloRetryRequest()
        { }

        /// <param name="selectedGroup">Group the client must send a key share for, or null when the client's share is acceptable.</param>
        public HelloRetryRequest(ushort cipherSuite, byte[] cookie, ushort? selectedGroup, byte[] legacySessionIdEcho, bool datagram = true)
        {
            Datagram = datagram;
            ServerRandom = (byte[])HelloRetryRequestRandom.Clone();
            SelectedCipherSuite = cipherSuite;
            LegacySessionIdEcho = legacySessionIdEcho ?? Array.Empty<byte>();

            var extensions = new List<ITlsExtension> { new ServerSupportedVersions(datagram ? (ushort)0xFEFC : (ushort)0x0304) };
            if (selectedGroup.HasValue)
                extensions.Add(new ServerKeyShareExtension(selectedGroup.Value, null));
            if (cookie != null)
                extensions.Add(new CookieExtension(cookie));
            Extensions = extensions;
        }

        public static bool IsHelloRetryRequest(ServerHelloDatagram serverHello)
            => serverHello.ServerRandom != null && serverHello.ServerRandom.AsSpan().SequenceEqual(HelloRetryRequestRandom);
    }
}
