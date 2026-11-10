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
using System.IO;

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// EndOfEarlyData (RFC 8446 §4.5): TLS 1.3 only (DTLS 1.3 removed it, RFC 9147 §5.6). The client sends it under the
    /// early traffic keys after the server's Finished when its 0-RTT data was accepted; it is part of the transcript.
    /// </summary>
    internal class EndOfEarlyDataDatagram : IHandshakeDatagram
    {
        public const byte HandshakeType = 5;

        public int SequenceNumber { get; set; }
        public byte[] Bytes { get; private set; }

        public void FromBytes(byte[] bytes)
        {
            if (bytes[0] != HandshakeType)
                throw new InvalidDataException("Not an EndOfEarlyData message.");
            if (((bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) != 0)
                throw new DtlsException(AlertDescription.DecodeError, "EndOfEarlyData has a body.");
            SequenceNumber = (bytes[4] << 8) | bytes[5];
            Bytes = bytes;
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[12 + 1];
            data[0] = HandshakeType;
            data[4] = (byte)(SequenceNumber >> 8);
            data[5] = (byte)SequenceNumber;
            data[^1] = 0x16; // inner content type (handshake)
            Bytes = data;
            return data;
        }
    }
}
