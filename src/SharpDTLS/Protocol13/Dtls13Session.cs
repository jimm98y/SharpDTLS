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

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// Negotiated state of one DTLS 1.3 association.
    /// </summary>
    internal class Dtls13Session
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public Dtls13Transcript Transcript { get; } = new Dtls13Transcript();
        public Dtls13CipherSuite CipherSuite { get; internal set; }

        public Dtls13CryptoContext ServerHandshakeKeys { get; internal set; }
        public Dtls13CryptoContext ServerApplicationKeys { get; internal set; }

        /// <summary>resumption_master_secret (RFC 8446 §7.1), available once the client Finished is processed.</summary>
        internal byte[] ResumptionMasterSecret { get; set; }

        /// <summary>Exporter master secret (RFC 8446 §7.1), available once the server Finished is processed.</summary>
        public byte[] ExporterMasterSecret { get; internal set; }

        /// <summary>Keys used to protect outgoing records.</summary>
        public Dtls13CryptoContext WriteKeys { get; internal set; }

        /// <summary>Keys accepted for incoming records, oldest first (handshake epoch, then application epochs).</summary>
        public List<Dtls13CryptoContext> ReadKeys { get; } = new List<Dtls13CryptoContext>();

        // Client authentication state (server-side)
        public bool RequiresClientAuth { get; set; }
        public byte[] ClientCertificateBytes { get; set; }
        public bool ReceivedClientCertificate { get; set; }
        public bool ReceivedClientCertificateVerify { get; set; }

        /// <summary>The peer's end-entity certificate (DER).</summary>
        public byte[] PeerCertificate { get; internal set; }
    }
}
