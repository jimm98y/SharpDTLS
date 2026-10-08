using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.TLS12;

namespace SharpDTLS.TLS10
{
    /// <summary>
    /// TLS 1.1 server (RFC 4346): the TLS 1.0-1.2 server restricted to TLS 1.1. Deprecated by RFC 8996; use it only
    /// for peers that cannot do better.
    /// </summary>
    public class Tls11Server : Tls12Server
    {
        public Tls11Server()
        {
            MinimumVersion = TlsVersion.Tls11;
            MaximumVersion = TlsVersion.Tls11;
        }

        public Tls11Server(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(keyPair, certificate)
        {
            MinimumVersion = TlsVersion.Tls11;
            MaximumVersion = TlsVersion.Tls11;
        }
    }
}
