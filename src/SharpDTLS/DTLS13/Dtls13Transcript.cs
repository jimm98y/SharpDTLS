using System;
using System.Collections.Generic;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// Handshake transcript. DTLS 1.3 hashes messages in TLS 1.3 form: the DTLS-only
    /// message_seq, fragment_offset and fragment_length fields are omitted (RFC 9147 §5.2).
    /// </summary>
    public sealed class Dtls13Transcript
    {
        private const int DtlsHandshakeHeaderLength = 12;
        private readonly List<byte[]> _messages = new();

        public int Count => _messages.Count;

        /// <summary>
        /// Adds a complete (unfragmented) DTLS handshake message starting at <paramref name="offset"/>.
        /// Trailing bytes after the message body (e.g. the inner content type) are ignored.
        /// </summary>
        public void AddHandshake(byte[] message, int offset = 0)
        {
            int length = (message[offset + 1] << 16) | (message[offset + 2] << 8) | message[offset + 3];
            if (message.Length < offset + DtlsHandshakeHeaderLength + length)
                throw new DtlsException(AlertDescription.DecodeError, "Truncated handshake message.");

            byte[] tlsForm = new byte[4 + length];
            Buffer.BlockCopy(message, offset, tlsForm, 0, 4); // msg_type + length
            Buffer.BlockCopy(message, offset + DtlsHandshakeHeaderLength, tlsForm, 4, length);
            _messages.Add(tlsForm);
        }

        /// <summary>Adds a handshake message carried in a plaintext DTLS record (13-byte record header).</summary>
        public void AddPlaintextRecord(byte[] record) => AddHandshake(record, 13);

        /// <summary>
        /// Replaces the transcript (ClientHello1) with the synthetic message_hash message used after a
        /// HelloRetryRequest (RFC 8446 §4.4.1).
        /// </summary>
        public void ReplaceWithMessageHash(Dtls13CipherSuite suite)
        {
            byte[] clientHelloHash = Hash(suite);
            _messages.Clear();
            AddMessageHash(clientHelloHash);
        }

        public void AddMessageHash(byte[] clientHelloHash)
        {
            byte[] messageHash = new byte[4 + clientHelloHash.Length];
            messageHash[0] = 254; // message_hash
            messageHash[3] = (byte)clientHelloHash.Length;
            Buffer.BlockCopy(clientHelloHash, 0, messageHash, 4, clientHelloHash.Length);
            _messages.Add(messageHash);
        }

        /// <summary>The hash of the transcript followed by one more message in TLS form (e.g. a truncated ClientHello).</summary>
        public byte[] HashWith(Dtls13CipherSuite suite, byte[] tlsMessage)
        {
            var digest = suite.CreateDigest();
            foreach (var message in _messages)
                digest.BlockUpdate(message, 0, message.Length);
            digest.BlockUpdate(tlsMessage, 0, tlsMessage.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        public byte[] Hash(Dtls13CipherSuite suite)
        {
            var digest = suite.CreateDigest();
            foreach (var message in _messages)
                digest.BlockUpdate(message, 0, message.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }
    }
}
