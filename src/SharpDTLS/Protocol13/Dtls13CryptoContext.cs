using System;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// Traffic keys for one DTLS 1.3 epoch, in both directions.
    /// </summary>
    internal class Dtls13CryptoContext
    {
        public Dtls13CipherSuite Suite { get; }

        /// <summary>Full epoch number (2 = handshake, 3 = first application epoch, +1 per KeyUpdate).</summary>
        public ulong Epoch { get; set; }

        // Number of records protected/deprotected with each key. The sender uses its own counter as the
        // next record sequence number (RFC 9147 §4.2.3: sequence numbers are per epoch and start at 0).
        public ulong ServerKeyUseCounter { get; set; } = 0;
        public ulong ClientKeyUseCounter { get; set; } = 0;

        /// <summary>Records received under these keys that failed authentication (RFC 9147 §4.5.3).</summary>
        public ulong FailedAuthentications { get; set; }

        // Receive state for records sent by each side (replay window + sequence number reconstruction).
        public RecordWindow ClientRecords { get; } = new RecordWindow();
        public RecordWindow ServerRecords { get; } = new RecordWindow();

        public Dtls13CryptoContext(string clientRandom, string secret, string clientSecret, string serverSecret, string clientKey, string clientIv, string serverKey, string serverIv, string clientSnKey, string serverSnKey)
            : this(Convert.FromHexString(clientRandom), Convert.FromHexString(secret), Convert.FromHexString(clientSecret), Convert.FromHexString(serverSecret),
                   Convert.FromHexString(clientKey), Convert.FromHexString(clientIv), Convert.FromHexString(serverKey), Convert.FromHexString(serverIv),
                   Convert.FromHexString(clientSnKey), Convert.FromHexString(serverSnKey))
        {
        }

        public Dtls13CryptoContext(byte[] clientRandom, byte[] secret, byte[] clientSecret, byte[] serverSecret, byte[] clientKey, byte[] clientIv, byte[] serverKey, byte[] serverIv, byte[] clientSnKey, byte[] serverSnKey,
            ushort cipherSuite = Dtls13CipherSuite.TLS_AES_128_GCM_SHA256, ulong epoch = 2)
            : this(clientRandom, secret, clientSecret, serverSecret, clientKey, clientIv, serverKey, serverIv, clientSnKey, serverSnKey, Dtls13CipherSuite.Get(cipherSuite), epoch)
        {
        }

        /// <summary>Keeps <paramref name="suite"/> itself, so a TLS suite's "tls13 " labels carry over to KeyUpdates.</summary>
        internal Dtls13CryptoContext(byte[] clientRandom, byte[] secret, byte[] clientSecret, byte[] serverSecret, byte[] clientKey, byte[] clientIv, byte[] serverKey, byte[] serverIv, byte[] clientSnKey, byte[] serverSnKey,
            Dtls13CipherSuite suite, ulong epoch)
        {
            Suite = suite;
            Epoch = epoch;
            ClientRandom = clientRandom;
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

        public byte[] ClientRandom { get; }
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
