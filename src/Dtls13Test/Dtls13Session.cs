using Dtls13Test.Messages;

namespace Dtls13Test
{
    public class Dtls13Session
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public List<IDatagram> HandshakeMessages { get; } = new List<IDatagram>();
    }
}
