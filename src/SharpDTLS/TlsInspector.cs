using System;

namespace SharpDTLS
{
    /// <summary>
    /// Optional hook into every (D)TLS handshake of the process, for teaching and debugging tools: it sees each
    /// handshake message sent (and may replace it before it enters the transcript), each one received, the plaintext of
    /// protected records and the secrets of the key schedule. Nothing is set by default: the engines then only test
    /// <see cref="Current"/> for null, and no state or allocation exists for it.
    /// </summary>
    /// <remarks>
    /// Handshake messages are always in TLS form: msg_type (1), length (3), body; the DTLS-only message_seq and fragment
    /// fields are left out, as in the (D)TLS 1.3 transcript (RFC 9147 §5.2). <c>messageSeq</c> gives the DTLS message_seq
    /// (-1 for TLS): DTLS 1.0/1.2 hash it with the message (RFC 6347 §4.2.6). Callbacks run on the connection's thread under its lock:
    /// they must not call back into the connection. <c>connection</c> is null for what a DTLS server handles statelessly,
    /// before any connection exists: a ClientHello it answers with HelloVerifyRequest or HelloRetryRequest, and that answer.
    /// Secrets are passed as the engine holds them: never write to them.
    /// </remarks>
    public abstract class TlsInspector
    {
        /// <summary>The inspector of every connection in the process, or null (the default).</summary>
        public static TlsInspector Current { get; set; }

        /// <summary>
        /// A handshake message about to be sent, before it is added to the transcript: return it, or a replacement
        /// (TLS form) that is sent and hashed instead. From a replaced ClientHello or ServerHello the engine adopts what it
        /// chose itself and can follow: the random, the session ID, the offered or selected cipher suite (when it
        /// implements it) and, before (D)TLS 1.3, extended_master_secret and encrypt_then_mac. Anything else it computed
        /// (key shares, signatures, Finished) keeps its own value: the change then reaches only the transcript and the peer.
        /// </summary>
        public virtual byte[] OnHandshakeSending(TlsConnectionBase connection, bool isClient, int messageSeq, byte[] message) => message;

        /// <summary>A complete handshake message received (TLS form), before it is processed.</summary>
        public virtual void OnHandshakeReceived(TlsConnectionBase connection, bool isClient, int messageSeq, ReadOnlySpan<byte> message) { }

        /// <summary>
        /// An ephemeral key pair was generated for a key exchange: <paramref name="group"/> is its named group (for a
        /// hybrid group, each component is reported with its own group: ML-KEM then the curve, in the share's order; 0
        /// for TLS 1.2 DHE parameters that are no named group). The private key is the raw scalar (X25519/X448, the
        /// big-endian scalar for the NIST curves, x for finite-field DH) or the ML-KEM decapsulation key; the public key
        /// is the value sent.
        /// </summary>
        public virtual void OnKeyExchange(TlsConnectionBase connection, bool isClient, ushort group, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) { }

        /// <summary>
        /// The content of a protected record: <paramref name="sent"/> just before encryption, otherwise just after
        /// decryption. <paramref name="epoch"/> is the full epoch (1.3: 1 early, 2 handshake, 3+ application; 1.2: 1+).
        /// </summary>
        public virtual void OnProtectedRecord(TlsConnectionBase connection, bool isClient, bool sent, byte contentType, ulong epoch, ulong sequenceNumber,
            ReadOnlySpan<byte> content) { }

        /// <summary>A secret or key as it is derived; <paramref name="name"/> is one of the constants of this class.</summary>
        public virtual void OnSecret(TlsConnectionBase connection, bool isClient, string name, ReadOnlySpan<byte> value) { }

        // ── Secret names ─────────────────────────────────────────────────────────────────────

        /// <summary>The (EC)DHE or ML-KEM shared secret ((D)TLS 1.3 key_share).</summary>
        public const string SharedSecret = "shared_secret";
        /// <summary>The PSK of the handshake ((D)TLS 1.3, resumption or external).</summary>
        public const string Psk = "psk";
        /// <summary>Transcript-Hash(ClientHello..ServerHello) ((D)TLS 1.3).</summary>
        public const string HelloHash = "hello_hash";
        /// <summary>Transcript-Hash(ClientHello..server Finished) ((D)TLS 1.3).</summary>
        public const string HandshakeHash = "handshake_hash";
        public const string HandshakeSecret = "handshake_secret";
        public const string ClientHandshakeTrafficSecret = "client_handshake_traffic_secret";
        public const string ServerHandshakeTrafficSecret = "server_handshake_traffic_secret";
        public const string ClientHandshakeKey = "client_handshake_key";
        public const string ClientHandshakeIv = "client_handshake_iv";
        public const string ClientHandshakeSnKey = "client_handshake_sn_key";
        public const string ServerHandshakeKey = "server_handshake_key";
        public const string ServerHandshakeIv = "server_handshake_iv";
        public const string ServerHandshakeSnKey = "server_handshake_sn_key";
        /// <summary>The (D)TLS 1.3 master secret, or the 48-byte (D)TLS 1.0-1.2 master_secret.</summary>
        public const string MasterSecret = "master_secret";
        public const string ClientApplicationTrafficSecret = "client_application_traffic_secret_0";
        public const string ServerApplicationTrafficSecret = "server_application_traffic_secret_0";
        public const string ClientApplicationKey = "client_application_key";
        public const string ClientApplicationIv = "client_application_iv";
        public const string ClientApplicationSnKey = "client_application_sn_key";
        public const string ServerApplicationKey = "server_application_key";
        public const string ServerApplicationIv = "server_application_iv";
        public const string ServerApplicationSnKey = "server_application_sn_key";
        public const string ExporterMasterSecret = "exporter_master_secret";
        public const string ResumptionMasterSecret = "resumption_master_secret";
        public const string ClientEarlyTrafficSecret = "client_early_traffic_secret";
        /// <summary>(D)TLS 1.0-1.2 with extended_master_secret: session_hash, the transcript hash up to ClientKeyExchange (RFC 7627).</summary>
        public const string SessionHash = "session_hash";
        /// <summary>(D)TLS 1.0-1.2: the key exchange's pre_master_secret.</summary>
        public const string PreMasterSecret = "pre_master_secret";
        /// <summary>
        /// (D)TLS 1.0-1.2: PRF(master_secret, "key expansion", server_random || client_random): client and server MAC keys,
        /// then write keys, then IVs.
        /// </summary>
        public const string KeyBlock = "key_block";

        // ── Engine helpers (called only when Current is set) ─────────────────────────────────

        // The connection whose input or operation is being processed on this thread, so the static key generation
        // helpers can report to it. Written only while an inspector is set: nothing is stored otherwise.
        [ThreadStatic] private static TlsConnectionBase t_connection;
        [ThreadStatic] private static bool t_isClient;

        /// <summary>Marks <paramref name="connection"/> as the one running on this thread; returns the previous one.</summary>
        internal static (TlsConnectionBase Connection, bool IsClient) Enter(TlsConnectionBase connection, bool isClient)
        {
            var previous = (t_connection, t_isClient);
            (t_connection, t_isClient) = (connection, isClient);
            return previous;
        }

        internal static void Exit((TlsConnectionBase Connection, bool IsClient) previous) => (t_connection, t_isClient) = previous;

        /// <summary>Reports a generated key pair for the connection running on this thread.</summary>
        internal static void KeyExchange(TlsInspector inspector, ushort group, byte[] privateKey, byte[] publicKey)
            => inspector.OnKeyExchange(t_connection, t_isClient, group, privateKey, publicKey);

        /// <summary>The DTLS message_seq of a message with a 12-byte header at <paramref name="offset"/>, or -1 (TLS).</summary>
        private static int MessageSeq(byte[] message, int offset, int headerLength, bool datagram)
            => datagram && headerLength == 12 ? (message[offset + 4] << 8) | message[offset + 5] : -1;

        /// <summary>A message with a <paramref name="headerLength"/>-byte header (4 TLS, 12 DTLS) at <paramref name="offset"/>, in TLS form.</summary>
        internal static byte[] ToTlsForm(byte[] message, int offset, int headerLength)
        {
            int length = (message[offset + 1] << 16) | (message[offset + 2] << 8) | message[offset + 3];
            byte[] tls = new byte[4 + length];
            Buffer.BlockCopy(message, offset, tls, 0, 4);
            Buffer.BlockCopy(message, offset + headerLength, tls, 4, length);
            return tls;
        }

        /// <summary>
        /// Reports a received message with a 4- or 12-byte header at <paramref name="offset"/> (a TLS 1.3 engine keeps the
        /// 12-byte form internally: <paramref name="datagram"/> false then reports no message_seq).
        /// </summary>
        internal static void Received(TlsInspector inspector, TlsConnectionBase connection, bool isClient, byte[] message, int offset, int headerLength, bool datagram = true)
        {
            if (headerLength == 4)
            {
                int length = (message[offset + 1] << 16) | (message[offset + 2] << 8) | message[offset + 3];
                inspector.OnHandshakeReceived(connection, isClient, -1, message.AsSpan(offset, 4 + length));
                return;
            }
            inspector.OnHandshakeReceived(connection, isClient, MessageSeq(message, offset, headerLength, datagram), ToTlsForm(message, offset, headerLength));
        }

        /// <summary>
        /// Lets the inspector see and replace a message with a 4- or 12-byte header at <paramref name="offset"/> of
        /// <paramref name="buffer"/>; returns the buffer, or a copy carrying the replacement with the same prefix and
        /// header fields (record header and message_seq), lengths fixed up and <paramref name="trailer"/> bytes kept. A
        /// different array is returned exactly when the inspector changed the message.
        /// </summary>
        internal static byte[] Sending(TlsInspector inspector, TlsConnectionBase connection, bool isClient, byte[] buffer, int offset, int headerLength, int trailer = 0, bool datagram = true)
        {
            byte[] original = ToTlsForm(buffer, offset, headerLength);
            byte[] replaced = inspector.OnHandshakeSending(connection, isClient, MessageSeq(buffer, offset, headerLength, datagram), original);
            if (replaced == null || ReferenceEquals(replaced, original) || replaced.AsSpan().SequenceEqual(original))
                return buffer;

            int length = replaced.Length - 4;
            int oldLength = original.Length - 4;
            byte[] result = new byte[buffer.Length - oldLength + length];
            Buffer.BlockCopy(buffer, 0, result, 0, offset + headerLength);
            result[offset] = replaced[0];
            WriteUInt24(result, offset + 1, length);
            if (headerLength == 12)
            {
                WriteUInt24(result, offset + 6, 0);         // fragment_offset
                WriteUInt24(result, offset + 9, length);    // fragment_length
            }
            Buffer.BlockCopy(replaced, 4, result, offset + headerLength, length);
            Buffer.BlockCopy(buffer, buffer.Length - trailer, result, result.Length - trailer, trailer);

            // A record header in front (13 bytes DTLS, 5 bytes TLS) carries the record length.
            if (offset >= 5)
            {
                int recordLength = result.Length - offset;
                result[offset - 2] = (byte)(recordLength >> 8);
                result[offset - 1] = (byte)recordLength;
            }
            return result;
        }

        private static void WriteUInt24(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value >> 16);
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)value;
        }
    }
}
