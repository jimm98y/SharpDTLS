namespace SharpDTLS.Protocol13
{
    /// <summary>post_handshake_auth (RFC 8446 §4.2.6): the client accepts a CertificateRequest after the handshake.</summary>
    internal class PostHandshakeAuthExtension : ITlsExtension
    {
        public const ushort Type = 49;

        public int CalculateLength() => 4;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length != 0)
                throw new DtlsException(AlertDescription.DecodeError, "post_handshake_auth must be empty.");
            return 4;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset] = 0;
            destination[offset + 1] = (byte)Type;
            destination[offset + 2] = 0;
            destination[offset + 3] = 0;
            return 4;
        }
    }
}
