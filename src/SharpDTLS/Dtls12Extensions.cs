using System;

namespace SharpDTLS
{
    /// <summary>
    /// renegotiation_info (RFC 5746). Renegotiation is not supported, so only the initial-handshake form
    /// with an empty renegotiated_connection is ever sent or accepted.
    /// </summary>
    public class RenegotiationInfoExtension : ITlsExtension
    {
        public const ushort Type = 0xff01;

        public byte[] RenegotiatedConnection { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 5 + RenegotiatedConnection.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 1 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid renegotiation_info extension.");
            RenegotiatedConnection = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0xff;
            destination[offset + 1] = 0x01;
            destination[offset + 2] = (byte)((1 + RenegotiatedConnection.Length) >> 8);
            destination[offset + 3] = (byte)(1 + RenegotiatedConnection.Length);
            destination[offset + 4] = (byte)RenegotiatedConnection.Length;
            Buffer.BlockCopy(RenegotiatedConnection, 0, destination, offset + 5, RenegotiatedConnection.Length);
            return 5 + RenegotiatedConnection.Length;
        }
    }

    /// <summary>srp (RFC 5054 §2.8.1): the client's SRP username, srp_I&lt;1..2^8-1&gt;.</summary>
    public class SrpExtension : ITlsExtension
    {
        public const ushort Type = 0x000c;

        public SrpExtension() { }

        public SrpExtension(byte[] identity)
        {
            if (identity == null || identity.Length is 0 or > 255)
                throw new ArgumentException("The SRP identity must be 1 to 255 bytes.", nameof(identity));
            Identity = identity;
        }

        public byte[] Identity { get; private set; } = Array.Empty<byte>();

        public int CalculateLength() => 5 + Identity.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length < 2 || source.Length < offset + 4 + length || source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid srp extension.");
            Identity = source.AsSpan(offset + 5, length - 1).ToArray();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0x00;
            destination[offset + 1] = 0x0c;
            destination[offset + 2] = (byte)((1 + Identity.Length) >> 8);
            destination[offset + 3] = (byte)(1 + Identity.Length);
            destination[offset + 4] = (byte)Identity.Length;
            Buffer.BlockCopy(Identity, 0, destination, offset + 5, Identity.Length);
            return 5 + Identity.Length;
        }
    }

    /// <summary>
    /// extended_master_secret (RFC 7627): binds the master secret to the handshake transcript.
    /// </summary>
    public class ExtendedMasterSecretExtension : ITlsExtension
    {
        public const ushort Type = 0x0017;

        public int CalculateLength() => 4;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length != 0)
                throw new DtlsException(AlertDescription.DecodeError, "extended_master_secret must be empty.");
            return 4;
        }

        public int Write(int offset, byte[] destination)
        {
            destination[offset]     = 0x00;
            destination[offset + 1] = 0x17;
            destination[offset + 2] = 0x00;
            destination[offset + 3] = 0x00;
            return 4;
        }
    }
}
