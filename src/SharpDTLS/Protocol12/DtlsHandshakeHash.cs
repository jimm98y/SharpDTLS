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

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// Handshake transcript contributions for DTLS 1.0 and 1.2.
    /// </summary>
    internal static class DtlsHandshakeHash
    {
        /// <summary>
        /// Returns a handshake message as it is hashed in DTLS 1.0/1.2: the full 12-byte DTLS handshake
        /// header (including message_seq) followed by the body, as if the message had been sent in a single
        /// fragment (RFC 6347 §4.2.6). DTLS 1.3 differs and omits the DTLS-specific fields (RFC 9147 §5.2).
        /// </summary>
        public static byte[] Contribution(byte[] message, int offset)
        {
            int length = (message[offset + 1] << 16) | (message[offset + 2] << 8) | message[offset + 3];
            if (message.Length < offset + 12 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Truncated handshake message.");

            byte[] contribution = new byte[12 + length];
            Buffer.BlockCopy(message, offset, contribution, 0, 12 + length);

            // fragment_offset = 0, fragment_length = length
            contribution[6] = 0; contribution[7] = 0; contribution[8] = 0;
            contribution[9] = contribution[1]; contribution[10] = contribution[2]; contribution[11] = contribution[3];
            return contribution;
        }
    }
}
