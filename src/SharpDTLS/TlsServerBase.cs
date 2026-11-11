// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// What <see cref="DtlsServer"/> and <see cref="TlsServer"/> share: the settings of a server for every version, where
    /// each client's ClientHello decides between 1.3 and 1.0-1.2. A setting applies to both, unless its remarks name one.
    /// </summary>
    public abstract class TlsServerBase
    {
        private IList<ushort> _cipherSuites;

        private protected TlsServerBase(Tls12ServerBase engine12, Tls13ServerBase engine13)
        {
            Engine12 = engine12;
            Engine13 = engine13;
        }

        /// <summary>The 1.0-1.2 engine.</summary>
        internal Tls12ServerBase Engine12 { get; }

        /// <summary>The 1.3 engine.</summary>
        internal Tls13ServerBase Engine13 { get; }

        /// <summary>
        /// Cipher suites in preference order, as one list for all versions: the 1.3 suites (0x13xx) apply to 1.3, the
        /// others to 1.0-1.2. A version without any suite in the list keeps its defaults; null (the default) keeps both.
        /// </summary>
        public IList<ushort> CipherSuites
        {
            get => _cipherSuites;
            set
            {
                TlsClientBase.SplitCipherSuites(value, out var suites12, out var suites13);
                Engine12.CipherSuites = suites12;
                Engine13.CipherSuites = suites13;
                _cipherSuites = value;
            }
        }

        /// <summary>Request a client certificate and abort with certificate_required if none is sent.</summary>
        public bool RequireClientCertificate
        {
            get => Engine13.RequireClientCertificate;
            set { Engine12.RequireClientCertificate = value; Engine13.RequireClientCertificate = value; }
        }

        /// <summary>
        /// Client certificate validation; return false to abort with bad_certificate. When null, the chain is validated
        /// against the platform's trust store for clientAuth; set (c, chain) => true to accept any certificate.
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator
        {
            get => Engine13.ClientCertificateValidator;
            set { Engine12.ClientCertificateValidator = value; Engine13.ClientCertificateValidator = value; }
        }

        /// <summary>Intermediate CA certificates sent after the server certificate, issuer of the previous one first.</summary>
        public IList<X509Certificate> IntermediateCertificates
        {
            get => Engine13.IntermediateCertificates;
            set { Engine12.IntermediateCertificates = value; Engine13.IntermediateCertificates = value; }
        }

        /// <summary>
        /// Chooses the credentials for the client's server_name (RFC 6066), which is null when the client sent none.
        /// Returning null uses the default certificate.
        /// </summary>
        public Func<string, ServerCredentials> CertificateSelector
        {
            get => Engine13.CertificateSelector;
            set { Engine12.CertificateSelector = value; Engine13.CertificateSelector = value; }
        }

        /// <summary>
        /// Chooses credentials from what the client said (server name, trusted CAs, signature schemes); returning null
        /// falls back to <see cref="CertificateSelector"/> and then the default certificate.
        /// </summary>
        public Func<CertificateSelectionContext, ServerCredentials> CredentialsSelector
        {
            get => Engine13.CredentialsSelector;
            set { Engine12.CredentialsSelector = value; Engine13.CredentialsSelector = value; }
        }

        /// <summary>Application protocols (ALPN, RFC 7301) in server preference order; null to ignore ALPN.</summary>
        public IList<string> ApplicationProtocols
        {
            get => Engine13.ApplicationProtocols;
            set { Engine12.ApplicationProtocols = value; Engine13.ApplicationProtocols = value; }
        }

        /// <summary>
        /// The most payload per record we accept (64 to 16384), sent in record_size_limit (RFC 8449) to clients that
        /// offer it; null for 16384. Clients' limits (and max_fragment_length requests) are always honoured.
        /// </summary>
        public int? RecordSizeLimit
        {
            get => Engine13.RecordSizeLimit;
            set { Engine12.RecordSizeLimit = value; Engine13.RecordSizeLimit = value; }
        }

        /// <summary>
        /// Certificate types we authenticate with, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> clients that support it get the key pair's SubjectPublicKeyInfo, so a
        /// server can do without a certificate.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes
        {
            get => Engine13.ServerCertificateTypes;
            set { Engine12.ServerCertificateTypes = value; Engine13.ServerCertificateTypes = value; }
        }

        /// <summary>Certificate types accepted from clients, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ClientCertificateTypes
        {
            get => Engine13.ClientCertificateTypes;
            set { Engine12.ClientCertificateTypes = value; Engine13.ClientCertificateTypes = value; }
        }

        /// <summary>CAs named in our CertificateRequests (certificate_authorities), to guide the client's choice; null names none.</summary>
        public IList<X509Certificate> ClientCertificateAuthorities
        {
            get => Engine13.ClientCertificateAuthorities;
            set { Engine12.ClientCertificateAuthorities = value; Engine13.ClientCertificateAuthorities = value; }
        }

        /// <summary>Checks a client's raw public key (DER SubjectPublicKeyInfo); false aborts with bad_certificate. When null, one is refused.</summary>
        public Func<byte[], bool> ClientRawPublicKeyValidator
        {
            get => Engine13.ClientRawPublicKeyValidator;
            set { Engine12.ClientRawPublicKeyValidator = value; Engine13.ClientRawPublicKeyValidator = value; }
        }

        /// <summary>
        /// A DER OCSP response for the server certificate to staple for clients that ask (RFC 8446 §4.4.2.1); null for
        /// none. Certificates from the CertificateSelector staple their own <see cref="ServerCredentials.OcspResponse"/>.
        /// </summary>
        public byte[] OcspResponse
        {
            get => Engine13.OcspResponse;
            set { Engine12.OcspResponse = value; Engine13.OcspResponse = value; }
        }

        /// <summary>
        /// Keys for session tickets (random per server by default); share them between servers to let them resume each
        /// other's sessions, or set null to disable tickets.
        /// </summary>
        public SessionTicketKeys TicketKeys
        {
            get => Engine13.TicketKeys;
            set { Engine12.TicketKeys = value; Engine13.TicketKeys = value; }
        }

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format), e.g. for Wireshark.</summary>
        public Action<string> KeyLogWriter
        {
            get => Engine13.KeyLogWriter;
            set { Engine12.KeyLogWriter = value; Engine13.KeyLogWriter = value; }
        }

        /// <summary>Optional psk_identity_hint sent to PSK clients (RFC 4279 §5.2).</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public byte[] PskIdentityHint { get => Engine12.PskIdentityHint; set => Engine12.PskIdentityHint = value; }

        /// <summary>Maps a client's PSK identity to its key (null for unknown identities); enables the PSK suites.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public Func<byte[], byte[]> PskIdentityResolver { get => Engine12.PskIdentityResolver; set => Engine12.PskIdentityResolver = value; }

        /// <summary>Maps an SRP username to its verifier (null for unknown users); enables the SRP suites.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get => Engine12.SrpVerifierProvider; set => Engine12.SrpVerifierProvider = value; }

        /// <summary>
        /// Maps a TLS-PWD username to its credential (null for unknown users, whose handshakes are simulated);
        /// enables the ECCPWD suites.
        /// </summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public Func<string, PwdCredential> PwdCredentialProvider { get => Engine12.PwdCredentialProvider; set => Engine12.PwdCredentialProvider = value; }

        /// <summary>Private key for recovering pwd_protect usernames (RFC 8492 §4.3.2); null accepts only pwd_clear.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters PwdProtectionKey { get => Engine12.PwdProtectionKey; set => Engine12.PwdProtectionKey = value; }

        /// <summary>Resumable sessions by session ID; null disables session ID resumption.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public ITlsSessionCache SessionCache { get => Engine12.SessionCache; set => Engine12.SessionCache = value; }

        /// <summary>
        /// Key exchange groups in server preference order (see <see cref="NamedGroups"/>). A group the client already
        /// sent a share for is preferred, to avoid a HelloRetryRequest; otherwise the server asks for its best group.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<ushort> SupportedGroups { get => Engine13.SupportedGroups; set => Engine13.SupportedGroups = value; }

        /// <summary>
        /// Certificate compression algorithms (RFC 8879) in server preference order: our Certificate is compressed with the
        /// first one the client offers, and clients may compress theirs with any of them. Null disables compression.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<ushort> CertificateCompressionAlgorithms { get => Engine13.CertificateCompressionAlgorithms; set => Engine13.CertificateCompressionAlgorithms = value; }

        /// <summary>Maps a client's PSK identity to its external PSK (null for unknown identities); enables external PSKs.</summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public Func<byte[], TlsExternalPsk> ExternalPskResolver { get => Engine13.ExternalPskResolver; set => Engine13.ExternalPskResolver = value; }

        /// <summary>
        /// Accept psk_ke, PSK handshakes without (EC)DHE (RFC 8446 §4.2.9), when the client offers it. Off by default:
        /// such handshakes have no forward secrecy. psk_dhe_ke is preferred when the client offers both.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public bool AllowPskOnlyKeyExchange { get => Engine13.AllowPskOnlyKeyExchange; set => Engine13.AllowPskOnlyKeyExchange = value; }

        /// <summary>
        /// Maximum 0-RTT data per connection advertised in tickets (RFC 8446 §4.2.10); 0 (the default) disables early
        /// data. Early data can be replayed by an attacker, so only enable it for idempotent requests. It is accepted
        /// only without a HelloRetryRequest (over DTLS, set <see cref="DtlsServer.RequireCookie"/> to false), for a fresh ticket
        /// (<see cref="EarlyDataFreshnessWindow"/>) whose ClientHello has not been seen before.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public uint MaxEarlyDataSize { get => Engine13.MaxEarlyDataSize; set => Engine13.MaxEarlyDataSize = value; }

        /// <summary>
        /// Anti-replay window (RFC 8446 §8.2): early data is accepted only when the client's ticket age is within this
        /// of the server's view, and each ClientHello is remembered for this long.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public TimeSpan EarlyDataFreshnessWindow { get => Engine13.EarlyDataFreshnessWindow; set => Engine13.EarlyDataFreshnessWindow = value; }
    }
}
