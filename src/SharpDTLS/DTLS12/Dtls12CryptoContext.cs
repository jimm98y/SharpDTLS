using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace SharpDTLS.DTLS12
{
    public class Dtls12CryptoContext
    {
        public ushort CipherSuite { get; }

        // true for 0xC030 (AES_256_GCM_SHA384) and 0xC02C (ECDSA variant)
        public bool UseSha384 => CipherSuite == 0xC030 || CipherSuite == 0xC02C;

        // true for 0xCCA8 (RSA) and 0xCCA9 (ECDSA) ChaCha20-Poly1305 suites
        public bool IsChaCha20 => CipherSuite == 0xCCA8 || CipherSuite == 0xCCA9;

        // AES-GCM engines (null when IsChaCha20)
        public GcmBlockCipher AeadEncryptEngine { get; }
        public GcmBlockCipher AeadDecryptEngine { get; }

        // ChaCha20-Poly1305 engines (null when !IsChaCha20)
        public ChaCha20Poly1305 ChaChaEncryptEngine { get; }
        public ChaCha20Poly1305 ChaChaDecryptEngine { get; }

        public ulong ServerSequenceNumber { get; set; } = 0;
        public ulong ClientSequenceNumber { get; set; } = 0;

        public byte[] MasterSecret { get; }
        public byte[] ClientKey { get; }     // 16 bytes (AES-128) or 32 bytes (AES-256 / ChaCha20)
        public byte[] ServerKey { get; }
        public byte[] ClientIv { get; }      // 4 bytes (GCM implicit) or 12 bytes (ChaCha20)
        public byte[] ServerIv { get; }

        public Dtls12CryptoContext(byte[] masterSecret, byte[] clientKey, byte[] serverKey,
            byte[] clientIv, byte[] serverIv, ushort cipherSuite = 0xC02F)
        {
            CipherSuite  = cipherSuite;
            MasterSecret = masterSecret;
            ClientKey    = clientKey;
            ServerKey    = serverKey;
            ClientIv     = clientIv;
            ServerIv     = serverIv;

            if (IsChaCha20)
            {
                ChaChaEncryptEngine = new ChaCha20Poly1305();
                ChaChaDecryptEngine = new ChaCha20Poly1305();
            }
            else
            {
                AeadEncryptEngine = new GcmBlockCipher(new AesEngine());
                AeadDecryptEngine = new GcmBlockCipher(new AesEngine());
            }
        }
    }
}
