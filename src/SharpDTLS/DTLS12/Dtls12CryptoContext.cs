using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace SharpDTLS.DTLS12
{
    public class Dtls12CryptoContext
    {
        public GcmBlockCipher AeadEncryptEngine { get; } = new GcmBlockCipher(new AesEngine());
        public GcmBlockCipher AeadDecryptEngine { get; } = new GcmBlockCipher(new AesEngine());

        public ulong ServerSequenceNumber { get; set; } = 0;
        public ulong ClientSequenceNumber { get; set; } = 0;

        public byte[] MasterSecret { get; }  // 48 bytes
        public byte[] ClientKey { get; }     // 16 bytes
        public byte[] ServerKey { get; }     // 16 bytes
        public byte[] ClientIv { get; }      // 4 bytes (implicit nonce)
        public byte[] ServerIv { get; }      // 4 bytes (implicit nonce)

        public Dtls12CryptoContext(byte[] masterSecret, byte[] clientKey, byte[] serverKey, byte[] clientIv, byte[] serverIv)
        {
            MasterSecret = masterSecret;
            ClientKey = clientKey;
            ServerKey = serverKey;
            ClientIv = clientIv;
            ServerIv = serverIv;
        }
    }
}
