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

using SharpDTLS.UDP;

namespace SharpDTLS.Protocol13.DTLS13
{
    /// <summary>DTLS 1.3 client (RFC 9147) over a datagram transport.</summary>
    internal class Dtls13Client : Tls13ClientConnection
    {
        public IClientTransport ClientTransport { get; }

        public Dtls13Client(IClientTransport clientTransport)
            : this(clientTransport, receive: true)
        {
        }

        /// <param name="receive">False when the caller feeds received datagrams to <see cref="TlsConnectionBase.ProcessDatagram(byte[])"/>.</param>
        internal Dtls13Client(IClientTransport clientTransport, bool receive)
            : base(data => clientTransport.Send(data), stream: false)
        {
            ClientTransport = clientTransport;
            if (receive)
                ClientTransport.OnDataReceived += (_, data) => ProcessDatagram(data);
        }
    }
}
