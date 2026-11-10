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

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>RequestConnectionId (RFC 9147 §9): asks the peer for num_cids spare CIDs. struct { uint8 num_cids; }</summary>
    internal class RequestConnectionIdDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 9;

        public RequestConnectionIdDatagram() { }
        public RequestConnectionIdDatagram(byte count) => Count = count;

        public int SequenceNumber { get; set; }
        public byte Count { get; private set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            Bytes = bytes;
            int length = bytes.Length >= 4 ? (bytes[1] << 16) | (bytes[2] << 8) | bytes[3] : -1;
            if (bytes.Length < 13 || bytes[0] != HandshakeType || length != 1)
                throw new DtlsException(AlertDescription.DecodeError, "Not a RequestConnectionId message.");
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            Count = bytes[12];
        }

        public byte[] ToBytes() => Bytes = Dtls13HandshakeMessage.Encode(HandshakeType, SequenceNumber, new[] { Count });
    }
}
