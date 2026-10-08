using SharpDTLS.TLS12;
using System.IO;

namespace SharpDTLS.TLS10
{
    /// <summary>
    /// TLS 1.0 client (RFC 2246): the TLS 1.0-1.2 client restricted to TLS 1.0. Deprecated by RFC 8996; use it only
    /// for peers that cannot do better.
    /// </summary>
    public class Tls10Client : Tls12Client
    {
        public Tls10Client(Stream stream, bool leaveStreamOpen = false)
            : base(stream, leaveStreamOpen)
        {
            MinimumVersion = TlsVersion.Tls10;
            MaximumVersion = TlsVersion.Tls10;
        }
    }
}
