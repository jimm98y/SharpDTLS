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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol13;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// What <see cref="DtlsClient"/> and <see cref="TlsClient"/> share: the settings of a client for every version, whose
    /// ClientHello offers 1.3 and 1.0-1.2 at once. A setting applies to whichever version the server picks, unless its
    /// remarks name one.
    /// </summary>
    public abstract class TlsClientBase
    {
        private IList<ushort> _cipherSuites;
        private TlsSession _resumptionSession;

        private protected TlsClientBase(Tls12ClientConnection engine12, Tls13ClientConnection engine13)
        {
            Engine12 = engine12;
            Engine13 = engine13;
        }

        /// <summary>The 1.0-1.2 engine.</summary>
        internal Tls12ClientConnection Engine12 { get; }

        /// <summary>The 1.3 engine.</summary>
        internal Tls13ClientConnection Engine13 { get; }

        /// <summary>
        /// Cipher suites in preference order, as one list for all versions: the 1.3 suites (0x13xx) apply to 1.3, the
        /// others to 1.0-1.2. A version without any suite in the list keeps its defaults; null (the default) keeps both.
        /// </summary>
        public IList<ushort> CipherSuites
        {
            get => _cipherSuites;
            set
            {
                SplitCipherSuites(value, out var suites12, out var suites13);
                Engine12.CipherSuites = suites12;
                Engine13.CipherSuites = suites13;
                _cipherSuites = value;
            }
        }

        /// <summary>
        /// A session of an earlier connection to the same server to resume (<see cref="Session"/> or
        /// <see cref="SessionReceived"/>); it resumes only when the server picks the version that created it.
        /// </summary>
        public TlsSession ResumptionSession
        {
            get => _resumptionSession;
            set
            {
                Engine12.ResumptionSession = value as Dtls12SessionState;
                Engine13.ResumptionTicket = value as Dtls13SessionTicket;
                _resumptionSession = value;
            }
        }

        /// <summary>The newest resumable session of this connection, or null.</summary>
        public TlsSession Session => (TlsSession)Engine13.SessionTicket ?? Engine12.SessionState;

        /// <summary>A resumable session became available: after a 1.0-1.2 handshake, and with each 1.3 NewSessionTicket.</summary>
        public event EventHandler<TlsSession> SessionReceived;

        /// <summary>The server asked for our certificate after the handshake (1.3, see <see cref="AllowPostHandshakeAuthentication"/>).</summary>
        public event EventHandler PostHandshakeCertificateRequested;

        /// <summary>Called at the end of the derived constructor, so these events follow its HandshakeFinished.</summary>
        private protected void WireSessionEvents()
        {
            Engine12.HandshakeFinished += (_, _) =>
            {
                if (Engine12.SessionState != null)
                    SessionReceived?.Invoke(this, Engine12.SessionState);
            };
            Engine13.NewSessionTicketReceived += (_, _) => SessionReceived?.Invoke(this, Engine13.SessionTicket);
            Engine13.PostHandshakeCertificateRequested += (_, _) => PostHandshakeCertificateRequested?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>The server's host name, sent in server_name (RFC 6066 §3).</summary>
        public string ServerName
        {
            get => Engine13.ServerName;
            set { Engine12.ServerName = value; Engine13.ServerName = value; }
        }

        /// <summary>Application protocols to offer with ALPN (RFC 7301), in preference order; null to not offer any.</summary>
        public IList<string> ApplicationProtocols
        {
            get => Engine13.ApplicationProtocols;
            set { Engine12.ApplicationProtocols = value; Engine13.ApplicationProtocols = value; }
        }

        /// <summary>
        /// Optional server certificate validation. Return false to abort with bad_certificate.
        /// When null, any certificate is accepted (only proof of key possession is checked).
        /// </summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator
        {
            get => Engine13.ServerCertificateValidator;
            set { Engine12.ServerCertificateValidator = value; Engine13.ServerCertificateValidator = value; }
        }

        /// <summary>The key pair of <see cref="ClientCertificate"/>, or of the raw public key we authenticate with.</summary>
        public AsymmetricCipherKeyPair ClientCertificateKeyPair
        {
            get => Engine13.ClientCertificateKeyPair;
            set { Engine12.ClientCertificateKeyPair = value; Engine13.ClientCertificateKeyPair = value; }
        }

        /// <summary>The certificate we answer a CertificateRequest with; null to send none.</summary>
        public X509Certificate ClientCertificate
        {
            get => Engine13.ClientCertificate;
            set { Engine12.ClientCertificate = value; Engine13.ClientCertificate = value; }
        }

        /// <summary>Intermediate CA certificates sent after <see cref="ClientCertificate"/>.</summary>
        public IList<X509Certificate> ClientIntermediateCertificates
        {
            get => Engine13.ClientIntermediateCertificates;
            set { Engine12.ClientIntermediateCertificates = value; Engine13.ClientIntermediateCertificates = value; }
        }

        /// <summary>
        /// Chooses the client credentials for a CertificateRequest (the CAs and signature schemes the server accepts);
        /// returning null uses <see cref="ClientCertificate"/> and <see cref="ClientCertificateKeyPair"/>.
        /// </summary>
        public Func<CertificateSelectionContext, CertificateCredentials> ClientCredentialsSelector
        {
            get => Engine13.ClientCredentialsSelector;
            set { Engine12.ClientCredentialsSelector = value; Engine13.ClientCredentialsSelector = value; }
        }

        /// <summary>Signature schemes we accept in certificates (signature_algorithms_cert, RFC 8446 §4.2.3); null to not send it.</summary>
        public IList<ushort> SignatureAlgorithmsCert
        {
            get => Engine13.SignatureAlgorithmsCert;
            set { Engine12.SignatureAlgorithmsCert = value; Engine13.SignatureAlgorithmsCert = value; }
        }

        /// <summary>
        /// Certificate types we accept from the server, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> the server may authenticate with a bare public key, which
        /// <see cref="ServerRawPublicKeyValidator"/> must then vouch for.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes
        {
            get => Engine13.ServerCertificateTypes;
            set { Engine12.ServerCertificateTypes = value; Engine13.ServerCertificateTypes = value; }
        }

        /// <summary>
        /// Certificate types we can authenticate with, in preference order (RFC 7250); null for X.509 only. A raw public key
        /// needs only <see cref="ClientCertificateKeyPair"/>.
        /// </summary>
        public IList<CertificateType> ClientCertificateTypes
        {
            get => Engine13.ClientCertificateTypes;
            set { Engine12.ClientCertificateTypes = value; Engine13.ClientCertificateTypes = value; }
        }

        /// <summary>
        /// Checks the server's raw public key (DER SubjectPublicKeyInfo), e.g. against a pinned key; false aborts with
        /// bad_certificate. When null, any key is accepted (only proof of possession is checked).
        /// </summary>
        public Func<byte[], bool> ServerRawPublicKeyValidator
        {
            get => Engine13.ServerRawPublicKeyValidator;
            set { Engine12.ServerRawPublicKeyValidator = value; Engine13.ServerRawPublicKeyValidator = value; }
        }

        /// <summary>Ask the server to staple an OCSP response for its certificate (status_request, RFC 8446 §4.4.2.1).</summary>
        public bool RequestOcspStapling
        {
            get => Engine13.RequestOcspStapling;
            set { Engine12.RequestOcspStapling = value; Engine13.RequestOcspStapling = value; }
        }

        /// <summary>
        /// Checks the server's stapled OCSP response after its certificate: (DER response, or null when the server
        /// stapled none, and the server's chain as received). Returning false or throwing aborts the handshake;
        /// <see cref="OcspStapleValidator"/> provides one.
        /// </summary>
        public Func<byte[], IReadOnlyList<byte[]>, bool> ServerCertificateStatusValidator
        {
            get => Engine13.ServerCertificateStatusValidator;
            set { Engine12.ServerCertificateStatusValidator = value; Engine13.ServerCertificateStatusValidator = value; }
        }

        /// <summary>
        /// Offer record_size_limit (RFC 8449): the most payload per record we accept, 64 to 16384; null to not offer it.
        /// Lets a constrained endpoint keep the server's records small.
        /// </summary>
        public int? RecordSizeLimit
        {
            get => Engine13.RecordSizeLimit;
            set { Engine12.RecordSizeLimit = value; Engine13.RecordSizeLimit = value; }
        }

        /// <summary>
        /// Request max_fragment_length (RFC 6066 §4): 512, 1024, 2048 or 4096 bytes per record in both directions; null
        /// to not request it. A server that also supports record_size_limit uses that instead.
        /// </summary>
        public int? MaxFragmentLength
        {
            get => Engine13.MaxFragmentLength;
            set { Engine12.MaxFragmentLength = value; Engine13.MaxFragmentLength = value; }
        }

        /// <summary>Ask the server for session tickets (RFC 5077, RFC 8446 §4.6.1), and resume <see cref="ResumptionSession"/> with its ticket.</summary>
        public bool UseSessionTickets
        {
            get => Engine13.UseSessionTickets;
            set { Engine12.UseSessionTickets = value; Engine13.UseSessionTickets = value; }
        }

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format), e.g. for Wireshark.</summary>
        public Action<string> KeyLogWriter
        {
            get => Engine13.KeyLogWriter;
            set { Engine12.KeyLogWriter = value; Engine13.KeyLogWriter = value; }
        }

        /// <summary>PSK identity for the PSK cipher suites (RFC 4279); setting it enables those suites.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public byte[] PskIdentity { get => Engine12.PskIdentity; set => Engine12.PskIdentity = value; }

        /// <summary>The pre-shared key that goes with <see cref="PskIdentity"/>.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public byte[] PskKey { get => Engine12.PskKey; set => Engine12.PskKey = value; }

        /// <summary>
        /// Alternative to <see cref="PskIdentity"/>/<see cref="PskKey"/>: maps the server's identity hint
        /// (empty when none was sent) to an identity and key.
        /// </summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public Func<byte[], (byte[] Identity, byte[] Key)> PskProvider { get => Engine12.PskProvider; set => Engine12.PskProvider = value; }

        /// <summary>SRP username (RFC 5054); setting it with <see cref="SrpPassword"/> enables the SRP suites.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public byte[] SrpIdentity { get => Engine12.SrpIdentity; set => Engine12.SrpIdentity = value; }

        /// <summary>The SRP password that goes with <see cref="SrpIdentity"/>.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public byte[] SrpPassword { get => Engine12.SrpPassword; set => Engine12.SrpPassword = value; }

        /// <summary>TLS-PWD username (RFC 8492), sent in the clear; setting it with <see cref="PwdPassword"/> enables the ECCPWD suites.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public string PwdUsername { get => Engine12.PwdUsername; set => Engine12.PwdUsername = value; }

        /// <summary>The TLS-PWD password that goes with <see cref="PwdUsername"/>.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public string PwdPassword { get => Engine12.PwdPassword; set => Engine12.PwdPassword = value; }

        /// <summary>
        /// The server's username-protection public key (RFC 8492 §4.3). When set the username is sent
        /// encrypted in pwd_protect instead of in the clear.
        /// </summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public ECPublicKeyParameters PwdProtectionKey { get => Engine12.PwdProtectionKey; set => Engine12.PwdProtectionKey = value; }

        /// <summary>
        /// Set when this handshake is a retry at a lower version after a failed one: sends TLS_FALLBACK_SCSV
        /// so a server supporting a higher version detects the downgrade (RFC 7507 §4).
        /// </summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public bool IsFallback { get => Engine12.IsFallback; set => Engine12.IsFallback = value; }

        /// <summary>Smallest finite-field Diffie-Hellman prime, or SRP group modulus, accepted from a server.</summary>
        /// <remarks>Used when 1.0-1.2 is negotiated.</remarks>
        public int MinimumDhPrimeBits { get => Engine12.MinimumDhPrimeBits; set => Engine12.MinimumDhPrimeBits = value; }

        /// <summary>Groups offered in supported_groups, in preference order (see <see cref="NamedGroups"/>).</summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<ushort> SupportedGroups { get => Engine13.SupportedGroups; set => Engine13.SupportedGroups = value; }

        /// <summary>
        /// Groups to send key shares for in the first ClientHello, in preference order (each must be in
        /// <see cref="SupportedGroups"/>). More shares avoid a HelloRetryRequest but enlarge the ClientHello. Null (the
        /// default) sends shares for X25519 and the ML-KEM hybrid when supported, else for the first supported group.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<ushort> KeyShareGroups { get => Engine13.KeyShareGroups; set => Engine13.KeyShareGroups = value; }

        /// <summary>
        /// Certificate compression algorithms we accept (RFC 8879), in preference order, e.g.
        /// <see cref="SharpDTLS.CertificateCompressionAlgorithms"/>; null to not offer compression. Also used to compress our own
        /// certificate when the server's CertificateRequest allows it.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<ushort> CertificateCompressionAlgorithms { get => Engine13.CertificateCompressionAlgorithms; set => Engine13.CertificateCompressionAlgorithms = value; }

        /// <summary>CAs we trust, named in certificate_authorities (RFC 8446 §4.2.4) so the server can pick a matching chain.</summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public IList<X509Certificate> CertificateAuthorities { get => Engine13.CertificateAuthorities; set => Engine13.CertificateAuthorities = value; }

        /// <summary>
        /// Let the server ask for our certificate after the handshake (post_handshake_auth, RFC 8446 §4.6.2). Requests are
        /// answered with <see cref="ClientCertificate"/> (or a raw public key) and its key, or with no certificate.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public bool AllowPostHandshakeAuthentication { get => Engine13.AllowPostHandshakeAuthentication; set => Engine13.AllowPostHandshakeAuthentication = value; }

        /// <summary>
        /// An externally provisioned PSK to authenticate with (RFC 8446 §4.2.11), offered after any resumption ticket.
        /// The server is then not authenticated by a certificate.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public TlsExternalPsk ExternalPsk { get => Engine13.ExternalPsk; set => Engine13.ExternalPsk = value; }

        /// <summary>
        /// PSK key exchange modes to offer (RFC 8446 §4.2.9): 1 (psk_dhe_ke, the default) keeps forward secrecy; offering
        /// only 0 (psk_ke) drops the key share entirely, for peers that cannot afford (EC)DHE.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public byte[] PskKeyExchangeModes { get => Engine13.PskKeyExchangeModes; set => Engine13.PskKeyExchangeModes = value; }

        /// <summary>
        /// 0-RTT data to send right after the ClientHello when resuming with a ticket that allows it (RFC 8446 §2.3).
        /// It is sent at most once, may be replayed by an attacker, and is lost when the server declines it
        /// (<see cref="TlsConnectionBase.EarlyDataAccepted"/> false): send it again after the handshake in that case.
        /// </summary>
        /// <remarks>Used when 1.3 is negotiated.</remarks>
        public byte[] EarlyData { get => Engine13.EarlyData; set => Engine13.EarlyData = value; }

        /// <summary>
        /// Splits one suite list by version: 1.3 suites (0x13xx and the integrity-only ones) and the 1.0-1.2 suites. A version
        /// without any suite in the list keeps its defaults.
        /// </summary>
        internal static void SplitCipherSuites(IList<ushort> suites, out IList<ushort> suites12, out IList<ushort> suites13)
        {
            var only13 = suites?.Where(Dtls13CipherSuite.IsSupported).ToList();
            var only12 = suites?.Where(s => !Dtls13CipherSuite.IsSupported(s)).ToList();
            suites12 = only12 is { Count: > 0 } ? only12 : null;
            suites13 = only13 is { Count: > 0 } ? only13 : new List<ushort>(Dtls13CipherSuite.Supported);
        }
    }
}
