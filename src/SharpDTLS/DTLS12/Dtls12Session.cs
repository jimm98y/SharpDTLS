using System.Collections.Generic;

namespace SharpDTLS.DTLS12
{
    public class Dtls12Session
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

        // Server-side retransmission state: the last flight sent and its timer.
        internal List<System.Func<IEnumerable<byte[]>>> Flight { get; } = new List<System.Func<IEnumerable<byte[]>>>();
        internal RetransmitTimer RetransmitTimer { get; set; }

        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SrtpProtectionProfile { get; set; }

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
