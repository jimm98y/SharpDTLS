using System.Collections.Generic;

namespace SharpDTLS.DTLS10
{
    public class Dtls10Session
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey  { get; set; }
        public List<IDatagram> HandshakeMessages { get; } = new();
        public Dtls10CryptoContext CryptoContext { get; internal set; }
        public ushort RecordSequenceNumber  { get; set; } = 0;
        public ushort MessageSequenceNumber { get; set; } = 0;
        public ushort Epoch { get; set; } = 0;
        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SrtpProtectionProfile { get; set; }

        /// <summary>The negotiated ECDHE group.</summary>
        public ushort NamedGroup { get; set; } = EcdheGroups.X25519;

        /// <summary>Whether extended_master_secret (RFC 7627) was negotiated.</summary>
        public bool UseExtendedMasterSecret { get; set; }

        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public ushort CipherSuite { get; set; } = 0xC013;
        public byte[] ClientCertificateBytes { get; set; }
    }
}
