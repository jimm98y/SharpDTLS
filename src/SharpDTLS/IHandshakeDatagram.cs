namespace SharpDTLS
{
    /// <summary>
    /// A handshake message carrying a DTLS message_seq. The sender assigns the value when the message is sent.
    /// </summary>
    public interface IHandshakeDatagram : IDatagram
    {
        int SequenceNumber { get; set; }
    }
}
