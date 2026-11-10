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

using System.Collections.Generic;
using System.IO;

namespace SharpDTLS.Protocol13.TLS13
{
    /// <summary>
    /// TLS 1.3 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// shared 1.3 client handshake over TLS records (RFC 8446), so the same settings apply; DTLS-only ones (SRTP,
    /// connection IDs) are ignored. 0-RTT data (EarlyData, with a ResumptionTicket) ends with EndOfEarlyData.
    /// </summary>
    internal class Tls13Client : Tls13ClientConnection
    {
        // Shares for the post-quantum hybrid that servers such as OpenSSL 3.5+ prefer, and for x25519: either way no
        // HelloRetryRequest (which also costs 0-RTT). Over a stream the larger ClientHello is no problem.
        protected override IReadOnlyList<ushort> DefaultKeyShareGroups { get; } = new[] { Dtls13Groups.X25519MlKem768, Dtls13Groups.X25519 };

        private readonly Stream _stream;

        /// <summary>For <see cref="TlsClient"/>, which reads the stream and feeds the active engine.</summary>
        internal Tls13Client(System.Action<byte[]> send)
            : base(send, stream: true)
        {
        }

        public Tls13Client(Stream stream, bool leaveStreamOpen = false)
            : base(record => TlsStreamPump.Write(stream, record), stream: true)
        {
            _stream = stream;
            if (!leaveStreamOpen)
                Closed += (_, _) => TlsStreamPump.DisposeAfterLinger(_stream);
            TlsStreamPump.Start(stream, this, ownsStream: !leaveStreamOpen);
        }
    }
}
