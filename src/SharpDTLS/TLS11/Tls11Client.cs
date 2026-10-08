using SharpDTLS.TLS12;
using System.IO;

namespace SharpDTLS.TLS11
{
    /// <summary>
    /// TLS 1.1 client (RFC 4346): the TLS 1.0-1.2 client restricted to TLS 1.1. Deprecated by RFC 8996; use it only
    /// for peers that cannot do better.
    /// </summary>
    public class Tls11Client : Tls12Client
    {
        public Tls11Client(Stream stream, bool leaveStreamOpen = false)
            : base(stream, leaveStreamOpen)
        {
            MinimumVersion = TlsVersion.Tls11;
            MaximumVersion = TlsVersion.Tls11;
        }
    }
}
