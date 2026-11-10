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

using System.Collections.Generic;

namespace SharpDTLS.Protocol12
{
    internal class Dtls12Session
    {
        public byte[] PrivateKey { get; set; }   // ECDHE private key
        public byte[] PublicKey { get; set; }    // ECDHE public key

        // Handshake messages included in the transcript hash (starting from ClientHello after cookie exchange)
        public List<IDatagram> HandshakeMessages { get; } = new List<IDatagram>();

        public Dtls12CryptoContext CryptoContext { get; internal set; }

        // DTLS record-layer sequence numbers (reset per epoch)
        public ushort RecordSequenceNumber { get; set; } = 0;

        // DTLS handshake message_seq counter (increases monotonically across the whole handshake)
        public ushort MessageSequenceNumber { get; set; } = 0;

        // Current epoch: 0 = unencrypted, 1 = encrypted (post-ChangeCipherSpec)
        public ushort Epoch { get; set; } = 0;

        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SrtpProtectionProfile { get; set; }

        /// <summary>The SRTP Master Key Identifier negotiated via use_srtp (empty for none), or null.</summary>
        public byte[] SrtpMki { get; set; }

        /// <summary>The negotiated ECDHE group.</summary>
        public ushort NamedGroup { get; set; } = EcdheGroups.X25519;

        /// <summary>Whether extended_master_secret (RFC 7627) was negotiated.</summary>
        public bool UseExtendedMasterSecret { get; set; }

        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public ushort CipherSuite { get; set; } = 0xC02F;
        public byte[] ClientCertificateBytes { get; set; }
    }
}
