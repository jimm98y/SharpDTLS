using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.TLS12;

namespace SharpDTLS.TLS10
{
    /// <summary>
    /// TLS 1.0 server (RFC 2246): the TLS 1.0-1.2 server restricted to TLS 1.0. Deprecated by RFC 8996; use it only
    /// for peers that cannot do better.
    /// </summary>
    public class Tls10Server : Tls12Server
    {
        public Tls10Server()
        {
            MinimumVersion = TlsVersion.Tls10;
            MaximumVersion = TlsVersion.Tls10;
        }

        public Tls10Server(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(keyPair, certificate)
        {
            MinimumVersion = TlsVersion.Tls10;
            MaximumVersion = TlsVersion.Tls10;
        }
    }
}
