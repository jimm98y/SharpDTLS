using Org.BouncyCastle.Tls;
using System.IO;

namespace SharpDTLS.Tests
{
    // BouncyCastle 2.7.0 servers expect a CertificateVerify after a fixed (EC)DH client certificate, which RFC 5246
    // §7.4.8 does not send, and so fail every static DH/ECDH handshake with client authentication with
    // unexpected_message. They drop the key exchange right after ClientKeyExchange (TlsServerProtocol's
    // ReceiveClientKeyExchangeMessage, DtlsServerProtocol's ServerHandshake), and then ExpectCertificateVerifyMessage
    // reads "null == keyExchange || keyExchange.RequiresCertificateVerify" as "expected"; 2.6.2 still asked
    // TlsDHKeyExchange / TlsECDHKeyExchange, whose RequiresCertificateVerify is false. These answer for them.

    /// <summary>A BouncyCastle DTLS server that does not expect CertificateVerify for static (EC)DH (see above).</summary>
    internal sealed class BcDtlsServerProtocol : DtlsServerProtocol
    {
        private readonly bool _staticKeyAgreement;

        public BcDtlsServerProtocol(bool staticKeyAgreement) => _staticKeyAgreement = staticKeyAgreement;

        protected override bool ExpectCertificateVerifyMessage(ServerHandshakeState state)
            => !_staticKeyAgreement && base.ExpectCertificateVerifyMessage(state);
    }

    /// <summary>A BouncyCastle TLS server that does not expect CertificateVerify for static (EC)DH (see above).</summary>
    internal sealed class BcTlsServerProtocol : TlsServerProtocol
    {
        private readonly bool _staticKeyAgreement;

        public BcTlsServerProtocol(Stream stream, bool staticKeyAgreement) : base(stream) => _staticKeyAgreement = staticKeyAgreement;

        protected override bool ExpectCertificateVerifyMessage()
            => !_staticKeyAgreement && base.ExpectCertificateVerifyMessage();
    }
}
