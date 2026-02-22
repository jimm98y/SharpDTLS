using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Dtls13Test
{
    public class Dtls13CryptoContext
    {
        public AesEngine AesEngine { get; } = new AesEngine();
        public GcmBlockCipher AeadEncryptEngine { get; } = new GcmBlockCipher(new AesEngine());
        public GcmBlockCipher AeadDecryptEngine { get; } = new GcmBlockCipher(new AesEngine());

        public int ServerKeyUseCounter { get; set; } = 0;
        public int ClientKeyUseCounter { get; set; } = 0;

        public Dtls13CryptoContext(string secret, string clientSecret, string serverSecret, string clientKey, string clientIv, string serverKey, string serverIv, string clientSnKey, string serverSnKey)
        {
            Secret = Convert.FromHexString(secret);
            ClientSecret = Convert.FromHexString(clientSecret);
            ServerSecret = Convert.FromHexString(serverSecret);
            ClientKey = Convert.FromHexString(clientKey);
            ClientIv = Convert.FromHexString(clientIv);
            ServerKey = Convert.FromHexString(serverKey);
            ServerIv = Convert.FromHexString(serverIv);
            ClientSnKey = Convert.FromHexString(clientSnKey);
            ServerSnKey = Convert.FromHexString(serverSnKey);
        }

        public Dtls13CryptoContext(byte[] secret, byte[] clientSecret, byte[] serverSecret, byte[] clientKey, byte[] clientIv, byte[] serverKey, byte[] serverIv, byte[] clientSnKey, byte[] serverSnKey)
        {
            Secret = secret;
            ClientSecret = clientSecret;
            ServerSecret = serverSecret;
            ClientKey = clientKey;
            ClientIv = clientIv;
            ServerKey = serverKey;
            ServerIv = serverIv;
            ClientSnKey = clientSnKey;
            ServerSnKey = serverSnKey;
        }

        public byte[] Secret { get; }
        public byte[] ClientSecret { get; }
        public byte[] ServerSecret { get; }
        public byte[] ClientKey { get; }
        public byte[] ClientIv { get; }
        public byte[] ServerKey { get; }
        public byte[] ServerIv { get; }
        public byte[] ClientSnKey { get; }
        public byte[] ServerSnKey { get; }
    }
}
