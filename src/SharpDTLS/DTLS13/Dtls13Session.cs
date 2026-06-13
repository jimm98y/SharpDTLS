using System.Collections.Generic;

namespace SharpDTLS.DTLS13
{
    public class Dtls13Session
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public List<IDatagram> HandshakeMessages { get; } = new List<IDatagram>();
        public Dtls13CryptoContext ServerHandshakeKeys { get; internal set; }
        public Dtls13CryptoContext ServerApplicationKeys { get; internal set; }
        public ushort RecordNumber { get; set; }
        public int Epoch { get; set; } = 0;

        // Client authentication state (server-side)
        public bool RequiresClientAuth { get; set; }
        public byte[] ClientCertificateBytes { get; set; }
        public bool ReceivedClientCertificate { get; set; }
        public bool ReceivedClientCertificateVerify { get; set; }
    }
}
