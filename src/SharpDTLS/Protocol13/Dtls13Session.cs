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
