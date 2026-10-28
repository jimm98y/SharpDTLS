using System;

namespace SharpDTLS.Protocol13.Messages
{
    /// <summary>
    /// A DTLS 1.3 protected record (unified header) carrying one inner message.
    /// </summary>
    public abstract class Dtls13EncryptedDatagram : IDatagram
    {
        protected readonly Dtls13CryptoContext _cryptoContext;

        public IDatagram Datagram { get; set; }

        /// <summary>Full 48-bit record sequence number within the epoch.</summary>
        public ulong RecordNumber { get; set; }

        public int Epoch { get; set; }
        public byte[] Bytes { get; protected set; }

        /// <summary>True when the record was sent by the client (selects client keys).</summary>
        protected abstract bool FromClient { get; }

        protected Dtls13EncryptedDatagram(Dtls13CryptoContext cryptoContext)
        {
            _cryptoContext = cryptoContext ?? throw new ArgumentNullException(nameof(cryptoContext));
            Epoch = (int)cryptoContext.Epoch;
        }

        public void FromBytes(byte[] encrypted)
        {
            byte[] plaintext = Decrypt(encrypted);
            ParsePlaintext(plaintext);
        }

        /// <summary>
        /// Decrypts the record and returns the inner plaintext (last byte = content type) without parsing it.
        /// Also sets <see cref="Bytes"/>, <see cref="Epoch"/> and <see cref="RecordNumber"/>.
        /// </summary>
        public byte[] Decrypt(byte[] encrypted)
        {
            Bytes = (byte[])encrypted.Clone();
            var result = Dtls13RecordProtection.Unprotect(_cryptoContext, FromClient, encrypted);
            Epoch = result.EpochBits;
            RecordNumber = result.SequenceNumber;
            return result.InnerPlaintext;
        }

        /// <summary>
        /// Parses a decrypted (and optionally reassembled) inner plaintext and populates <see cref="Datagram"/>.
        /// </summary>
        public void ParsePlaintext(byte[] plaintext)
        {
            byte contentType = plaintext[plaintext.Length - 1];
            Datagram = contentType switch
            {
                0x16 => plaintext[0] switch
                {
                    0x04 => new NewSessionTicketDatagram(),
                    0x08 => new EncryptedExtensionsDatagram(),
                    0x0b => new CertificateDatagram(),
                    0x0d => new CertificateRequestDatagram(),
                    0x0f => new CertificateVerifyDatagram(),
                    0x14 => new FinishedDatagram(),
                    0x18 => new KeyUpdateDatagram(),
                    _ => throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message type 0x{plaintext[0]:X2}")
                },
                0x15 => new AlertDatagram(),
                0x17 => new ApplicationDataDatagram(),
                0x1a => new AcknowledgementDatagram(),
                _ => throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected content type 0x{contentType:X2}")
            };

            Datagram.FromBytes(plaintext);
        }

        public byte[] ToBytes()
        {
            Bytes = Dtls13RecordProtection.Protect(_cryptoContext, FromClient, Epoch, RecordNumber, Datagram.ToBytes());
            return Bytes;
        }

        /// <summary>
        /// Decodes the full record sequence number without decrypting. Returns false for malformed headers.
        /// </summary>
        public static bool TryPeekRecordNumber(byte[] data, Dtls13CryptoContext context, bool fromClient, out ulong recordNumber)
            => Dtls13RecordProtection.TryPeekSequenceNumber(context, fromClient, data, out recordNumber);
    }

    /// <summary>A protected record sent by the server.</summary>
    public class ServerEncryptedDatagram : Dtls13EncryptedDatagram
    {
        protected override bool FromClient => false;

        public ServerEncryptedDatagram(Dtls13CryptoContext cryptoContext) : base(cryptoContext) { }

        public ServerEncryptedDatagram(Dtls13CryptoContext cryptoContext, IDatagram datagram) : base(cryptoContext)
        {
            Datagram = datagram;
        }
    }

    /// <summary>A protected record sent by the client.</summary>
    public class ClientEncryptedDatagram : Dtls13EncryptedDatagram
    {
        protected override bool FromClient => true;

        public ClientEncryptedDatagram(Dtls13CryptoContext cryptoContext) : base(cryptoContext) { }

        public ClientEncryptedDatagram(Dtls13CryptoContext cryptoContext, IDatagram datagram) : base(cryptoContext)
        {
            Datagram = datagram;
        }
    }
}
