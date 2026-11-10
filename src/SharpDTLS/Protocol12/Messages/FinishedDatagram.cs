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

namespace SharpDTLS.Protocol12.Messages
{
    // DTLS 1.2 Finished handshake message — 12-byte verify_data computed via PRF.
    // Sent encrypted inside a Dtls12*EncryptedDatagram after ChangeCipherSpec.
    // ToBytes / FromBytes operate on the handshake layer only (no DTLS record header).
    internal class FinishedDatagram : IDatagram
    {
        public ushort MessageSequenceNumber { get; set; }
        public byte[] VerifyData { get; set; } // 12 bytes

        public byte[] Bytes { get; private set; }

        public FinishedDatagram() { }

        public FinishedDatagram(byte[] verifyData, ushort msgSeq = 0)
        {
            VerifyData = verifyData;
            MessageSequenceNumber = msgSeq;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x14) throw new InvalidDataException("Not a Finished message.");

            Bytes = bytes.ToArray();
            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            MessageSequenceNumber = (ushort)((bytes[4] << 8) | bytes[5]);

            VerifyData = new byte[length];
            Buffer.BlockCopy(bytes, 12, VerifyData, 0, length);
        }

        // Returns the 24-byte handshake message (no DTLS record header).
        // msg_type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3) + verify_data(12)
        public byte[] ToBytes()
        {
            byte[] buf = new byte[12 + (VerifyData?.Length ?? 0)];

            buf[0] = 0x14; // Finished
            int len = VerifyData.Length;
            buf[1] = (byte)((len >> 16) & 0xFF);
            buf[2] = (byte)((len >> 8) & 0xFF);
            buf[3] = (byte)(len & 0xFF);
            buf[4] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[5] = (byte)(MessageSequenceNumber & 0xFF);
            buf[6] = 0x00; buf[7] = 0x00; buf[8] = 0x00; // frag_offset = 0
            buf[9]  = (byte)((len >> 16) & 0xFF);
            buf[10] = (byte)((len >> 8) & 0xFF);
            buf[11] = (byte)(len & 0xFF);
            Buffer.BlockCopy(VerifyData, 0, buf, 12, len);

            Bytes = buf;
            return Bytes;
        }
    }
}
