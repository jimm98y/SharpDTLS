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

using System.IO;

namespace SharpDTLS.Protocol12.TLS12
{
    /// <summary>
    /// TLS 1.2 client over a stream (usually a connected <see cref="System.Net.Sockets.NetworkStream"/>). It is the
    /// DTLS 1.0/1.2 client's handshake over TLS framing, so the same settings apply; DTLS-only ones (SRTP, connection
    /// IDs) are ignored. Set <see cref="Tls12Connection.MinimumVersion"/> to also accept TLS 1.0 or 1.1 servers,
    /// and <see cref="Tls12Connection.MaximumVersion"/> to speak only those.
    /// </summary>
    internal class Tls12Client : Tls12ClientConnection
    {
        private readonly Stream _stream;

        /// <summary>For <see cref="SharpDTLS.TlsClient"/>, which reads the stream and feeds the active engine.</summary>
        internal Tls12Client(System.Action<byte[]> send)
            : base(send, stream: true)
        {
            MinimumVersion = TlsVersion.Tls12;
            MaximumVersion = TlsVersion.Tls12;
        }

        public Tls12Client(Stream stream, bool leaveStreamOpen = false)
            : base(record => TlsStreamPump.Write(stream, record), stream: true)
        {
            _stream = stream;
            MinimumVersion = TlsVersion.Tls12;
            MaximumVersion = TlsVersion.Tls12;
            if (!leaveStreamOpen)
                Closed += (_, _) => TlsStreamPump.DisposeAfterLinger(_stream);
            TlsStreamPump.Start(stream, this, ownsStream: !leaveStreamOpen);
        }
    }
}
