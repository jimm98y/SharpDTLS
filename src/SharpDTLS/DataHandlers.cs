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
using System.Net;

namespace SharpDTLS
{
    /// <summary>
    /// Application data received on <paramref name="connection"/>. <paramref name="data"/> is valid only during the call:
    /// the buffer is reused afterwards, so copy what is kept (<c>data.ToArray()</c>).
    /// </summary>
    public delegate void TlsDataHandler(TlsConnectionBase connection, ReadOnlySpan<byte> data);

    /// <summary>Where a connection's records go: the datagram, or the stream bytes, valid only during the call.</summary>
    internal delegate void DatagramSink(ReadOnlySpan<byte> datagram);
}

namespace SharpDTLS.UDP
{
    /// <summary>
    /// A datagram received from <paramref name="remoteEndPoint"/> (the server, of a client transport; null when unknown). <paramref name="datagram"/>
    /// is valid only during the call: the transport reuses its buffer for the next one.
    /// </summary>
    public delegate void DatagramHandler(EndPoint remoteEndPoint, ReadOnlySpan<byte> datagram);
}
