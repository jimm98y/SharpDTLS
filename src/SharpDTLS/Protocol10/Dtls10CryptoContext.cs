namespace SharpDTLS.Protocol10
{
    // Key material for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013).
    // key_block = PRF(master, "key expansion", server_random+client_random, 72):
    //   clientMacKey(20) + serverMacKey(20) + clientKey(16) + serverKey(16)
    public class Dtls10CryptoContext
    {
        public byte[] MasterSecret { get; }   // 48 bytes
        public byte[] ClientMacKey { get; }   // 20 bytes (HMAC-SHA1)
        public byte[] ServerMacKey { get; }   // 20 bytes
        public byte[] ClientKey    { get; }   // 16 bytes (AES-128-CBC)
        public byte[] ServerKey    { get; }   // 16 bytes

        public ulong ClientSequenceNumber { get; set; } = 0;
        public ulong ServerSequenceNumber { get; set; } = 0;

        // Anti-replay windows for records sent by each side (RFC 6347 §4.1.2.6).
        public RecordWindow ClientRecords { get; } = new RecordWindow();
        public RecordWindow ServerRecords { get; } = new RecordWindow();

        public Dtls10CryptoContext(byte[] masterSecret,
            byte[] clientMacKey, byte[] serverMacKey,
            byte[] clientKey, byte[] serverKey)
        {
            MasterSecret = masterSecret;
            ClientMacKey = clientMacKey;
            ServerMacKey = serverMacKey;
            ClientKey    = clientKey;
            ServerKey    = serverKey;
        }
    }
}
