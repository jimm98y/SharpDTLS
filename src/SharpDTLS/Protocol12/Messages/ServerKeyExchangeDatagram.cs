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
    // DTLS 1.2 ServerKeyExchange for ECDHE_RSA cipher suites.
    // Body: ECCurveType(1) + NamedCurve(2) + point_length(1) + point(N) + hash_alg(1) + sig_alg(1) + sig_length(2) + sig
    internal class ServerKeyExchangeDatagram : IDatagram
    {
        public ushort MessageSequenceNumber { get; set; } = 3;
        public int RecordSequenceNumber { get; set; }

        // EC parameters
        public byte   CurveType   { get; set; } = 0x03;   // named_curve
        public ushort NamedCurve  { get; set; } = 0x001D;  // x25519
        public byte[] PublicKey   { get; set; }

        // Signature
        public byte   HashAlgorithm { get; set; } = 0x04; // SHA256
        public byte   SigAlgorithm  { get; set; } = 0x01; // RSA
        public byte[] Signature     { get; set; }

        // The raw EC params bytes (CurveType + NamedCurve + point_length + point)
        // needed to verify/sign: ClientRandom + ServerRandom + ECParams
        public byte[] EcParamsBytes => BuildEcParams();

        public byte[] Bytes { get; private set; }

        public ServerKeyExchangeDatagram() { }

        public ServerKeyExchangeDatagram(byte[] publicKey, byte[] signature,
            byte hashAlg = 0x04, byte sigAlg = 0x01,
            ushort namedCurve = 0x001D)
        {
            PublicKey  = publicKey;
            Signature  = signature;
            HashAlgorithm = hashAlg;
            SigAlgorithm  = sigAlg;
            NamedCurve    = namedCurve;
        }

        private byte[] BuildEcParams()
        {
            byte[] result = new byte[1 + 2 + 1 + PublicKey.Length];
            result[0] = CurveType;
            result[1] = (byte)((NamedCurve >> 8) & 0xFF);
            result[2] = (byte)(NamedCurve & 0xFF);
            result[3] = (byte)PublicKey.Length;
            Buffer.BlockCopy(PublicKey, 0, result, 4, PublicKey.Length);
            return result;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes[0] != 0x16) throw new InvalidDataException("Not a handshake record.");
            if (bytes[13] != 0x0C) throw new InvalidDataException("Not a ServerKeyExchange.");

            Bytes = bytes.ToArray();
            long seq = 0;
            for (int i = 5; i <= 10; i++) seq = (seq << 8) | bytes[i];
            RecordSequenceNumber = (int)seq;
            MessageSequenceNumber = (ushort)((bytes[17] << 8) | bytes[18]);

            int p = 25; // body start
            CurveType  = bytes[p++];
            NamedCurve = (ushort)((bytes[p] << 8) | bytes[p + 1]); p += 2;
            byte pkLen = bytes[p++];
            PublicKey  = new byte[pkLen];
            Buffer.BlockCopy(bytes, p, PublicKey, 0, pkLen);
            p += pkLen;

            HashAlgorithm = bytes[p++];
            SigAlgorithm  = bytes[p++];
            ushort sigLen = (ushort)((bytes[p] << 8) | bytes[p + 1]); p += 2;
            Signature = new byte[sigLen];
            Buffer.BlockCopy(bytes, p, Signature, 0, sigLen);
        }

        public byte[] ToBytes()
        {
            int hsBodyLen = 1 + 2 + 1 + PublicKey.Length + 1 + 1 + 2 + Signature.Length;
            byte[] buf = new byte[13 + 12 + hsBodyLen];

            buf[0] = 0x16;
            buf[1] = 0xFE; buf[2] = 0xFD;
            buf[3] = 0x00; buf[4] = 0x00;
            buf[5]  = (byte)(((long)RecordSequenceNumber >> 40) & 0xFF);
            buf[6]  = (byte)(((long)RecordSequenceNumber >> 32) & 0xFF);
            buf[7]  = (byte)((RecordSequenceNumber >> 24) & 0xFF);
            buf[8]  = (byte)((RecordSequenceNumber >> 16) & 0xFF);
            buf[9]  = (byte)((RecordSequenceNumber >> 8) & 0xFF);
            buf[10] = (byte)(RecordSequenceNumber & 0xFF);
            int recordBodyLen = 12 + hsBodyLen;
            buf[11] = (byte)((recordBodyLen >> 8) & 0xFF);
            buf[12] = (byte)(recordBodyLen & 0xFF);

            buf[13] = 0x0C; // ServerKeyExchange
            buf[14] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[15] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[16] = (byte)(hsBodyLen & 0xFF);
            buf[17] = (byte)((MessageSequenceNumber >> 8) & 0xFF);
            buf[18] = (byte)(MessageSequenceNumber & 0xFF);
            buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00;
            buf[22] = (byte)((hsBodyLen >> 16) & 0xFF);
            buf[23] = (byte)((hsBodyLen >> 8) & 0xFF);
            buf[24] = (byte)(hsBodyLen & 0xFF);

            int p = 25;
            buf[p++] = CurveType;
            buf[p++] = (byte)((NamedCurve >> 8) & 0xFF);
            buf[p++] = (byte)(NamedCurve & 0xFF);
            buf[p++] = (byte)PublicKey.Length;
            Buffer.BlockCopy(PublicKey, 0, buf, p, PublicKey.Length); p += PublicKey.Length;
            buf[p++] = HashAlgorithm;
            buf[p++] = SigAlgorithm;
            buf[p++] = (byte)((Signature.Length >> 8) & 0xFF);
            buf[p++] = (byte)(Signature.Length & 0xFF);
            Buffer.BlockCopy(Signature, 0, buf, p, Signature.Length); p += Signature.Length;

            Bytes = buf.Take(p).ToArray();
            return Bytes;
        }
    }
}
