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
using System.Linq;

namespace SharpDTLS.Protocol13.Messages
{
    internal class KeyUpdateDatagram : IHandshakeDatagram
    {
        // Handshake type for KeyUpdate per TLS 1.3 post-handshake
        public byte HandshakeType { get; set; } = 0x18; // key_update(24)

        public int SequenceNumber { get; set; } = 0;
        public byte UpdateRequest { get; set; } = 0x00; // 0x00 = update_not_requested, 0x01 = update_requested

        public byte[] Bytes { get; private set; }

        public KeyUpdateDatagram()
        {
        }

        public KeyUpdateDatagram(byte updateRequest)
        {
            UpdateRequest = updateRequest;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 13 + 1) throw new ArgumentException("Buffer too small to be a KeyUpdate.");

            Bytes = bytes.ToArray();

            if (bytes[0] != HandshakeType) throw new InvalidDataException("Not a KeyUpdate handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;

            if (bytes.Length < pos + 1) throw new ArgumentException("Buffer truncated before update_request.");
            UpdateRequest = bytes[pos++];

            // optional trailing extensions or record type; be tolerant
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[64];

            data[0] = HandshakeType;
            int length = 0;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;
            data[pos++] = UpdateRequest;

            // no extensions, add a trailing record type for parity
            data[pos++] = 0x16;

            length = pos - 13;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            int fragmentOffset = 0;
            data[6] = (byte)((fragmentOffset >> 16) & 0xFF);
            data[7] = (byte)((fragmentOffset >> 8) & 0xFF);
            data[8] = (byte)(fragmentOffset & 0xFF);

            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
