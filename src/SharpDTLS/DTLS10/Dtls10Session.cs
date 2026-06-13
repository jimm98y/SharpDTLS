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
        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public ushort CipherSuite { get; set; } = 0xC013;
    }
}
