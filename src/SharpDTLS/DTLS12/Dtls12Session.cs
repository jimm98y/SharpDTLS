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

        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public ushort CipherSuite { get; set; } = 0xC02F;
        public byte[] ClientCertificateBytes { get; set; }
    }
}
