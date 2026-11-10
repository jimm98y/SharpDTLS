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
    internal class AlertDatagram : IDatagram
    {
        public ushort Alert { get; set; } = 0x0100; // close_notify
        public byte[] Bytes { get; private set; }

        public AlertDatagram()
        {  }

        public AlertDatagram(ushort alert)
        {
            this.Alert = alert;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes)); if (bytes.Length < 3) throw new ArgumentException("Buffer too small for AlertDatagram.");

            this.Bytes = bytes.ToArray();
            this.Alert = (ushort)((bytes[0] << 8) | bytes[1]);

            if (bytes[2] != 0x15) throw new InvalidDataException("Unexpected record type (expected 0x15).");
        }


        public byte[] ToBytes()
        {
            byte[] data = new byte[3];

            data[0] = (byte)((this.Alert >> 8) & 0xFF);
            data[1] = (byte)(this.Alert & 0xFF);                      
            data[2] = 0x15; // Alert

            this.Bytes = data;

            return data;
        }
    }
}
