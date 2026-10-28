using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// The configuration shared by (D)TLS 1.0-1.2 servers: credentials, versions, cipher suites, client
    /// authentication, extensions and resumption. <see cref="Dtls12ServerBase"/> adds datagram transport, cookies,
    /// SRTP and connection IDs; <see cref="SharpDTLS.Protocol12.TLS12.Tls12Server"/> adds a TCP listener.
    /// </summary>
    public abstract class Tls12ServerBase
    {
        protected Tls12ServerBase(AsymmetricCipherKeyPair keyPair, X509Certificate certificate, ushort version)
        {
            if (certificate != null && keyPair == null)
                throw new ArgumentException("A certificate needs its key pair.");

            Settings = new Tls12ServerSettings
            {
                KeyPair = keyPair,
                Certificate = certificate,
                MinimumVersion = version,
                MaximumVersion = version,
            };
        }

        protected Tls12ServerSettings Settings { get; }

        public bool RequireClientCertificate { get => Settings.RequireClientCertificate; set => Settings.RequireClientCertificate = value; }

        public Action<string> KeyLogWriter { get => Settings.KeyLogWriter; set => Settings.KeyLogWriter = value; }

        public ushort MinimumVersion { get => Settings.MinimumVersion; set => Settings.MinimumVersion = value; }

        public ushort MaximumVersion { get => Settings.MaximumVersion; set => Settings.MaximumVersion = value; }

        /// <summary>Cipher suites in server preference order; null for all implemented suites.</summary>
        public IList<ushort> CipherSuites { get => Settings.CipherSuites; set => Settings.CipherSuites = value; }

        /// <summary>Intermediate CA certificates sent after the server certificate, issuer of the previous one first.</summary>
        public IList<X509Certificate> IntermediateCertificates { get => Settings.IntermediateCertificates; set => Settings.IntermediateCertificates = value; }

        /// <summary>
        /// Chooses the credentials for the client's server_name (RFC 6066), which is null when the client sent none.
        /// Returning null uses the default certificate.
        /// </summary>
        public Func<string, ServerCredentials> CertificateSelector { get => Settings.CertificateSelector; set => Settings.CertificateSelector = value; }

        /// <summary>Application protocols (ALPN, RFC 7301) in server preference order; null to ignore ALPN.</summary>
        public IList<string> ApplicationProtocols { get => Settings.ApplicationProtocols; set => Settings.ApplicationProtocols = value; }

        /// <summary>The most payload per record we accept, advertised with record_size_limit (RFC 8449); null for 16384.</summary>
        public int? RecordSizeLimit { get => Settings.RecordSizeLimit; set => Settings.RecordSizeLimit = value; }

        /// <summary>
        /// Certificate types we authenticate with, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> clients that support it get the key pair's SubjectPublicKeyInfo, so a
        /// server can do without a certificate.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes { get => Settings.ServerCertificateTypes; set => Settings.ServerCertificateTypes = value; }

        /// <summary>Certificate types accepted from clients, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ClientCertificateTypes { get => Settings.ClientCertificateTypes; set => Settings.ClientCertificateTypes = value; }

        /// <summary>
        /// Chooses credentials from what the client said (server name, signature schemes); returning null falls back to
        /// <see cref="CertificateSelector"/> and then the default certificate.
        /// </summary>
        public Func<CertificateSelectionContext, ServerCredentials> CredentialsSelector { get => Settings.CredentialsSelector; set => Settings.CredentialsSelector = value; }

        /// <summary>CAs whose names a CertificateRequest lists, to guide the client's choice; null lists none.</summary>
        public IList<X509Certificate> ClientCertificateAuthorities { get => Settings.ClientCertificateAuthorities; set => Settings.ClientCertificateAuthorities = value; }

        /// <summary>Checks a client's raw public key (DER SubjectPublicKeyInfo); false aborts with bad_certificate.</summary>
        public Func<byte[], bool> ClientRawPublicKeyValidator { get => Settings.ClientRawPublicKeyValidator; set => Settings.ClientRawPublicKeyValidator = value; }

        /// <summary>A DER OCSP response for the certificate, stapled for clients that ask (RFC 6066 §8); null for none.</summary>
        public byte[] OcspResponse { get => Settings.OcspResponse; set => Settings.OcspResponse = value; }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator
        {
            get => Settings.ClientCertificateValidator;
            set => Settings.ClientCertificateValidator = value;
        }

        /// <summary>Optional psk_identity_hint sent to PSK clients (RFC 4279 §5.2).</summary>
        public byte[] PskIdentityHint { get => Settings.PskIdentityHint; set => Settings.PskIdentityHint = value; }

        /// <summary>Maps a client's PSK identity to its key (null for unknown identities); enables the PSK suites.</summary>
        public Func<byte[], byte[]> PskIdentityResolver { get => Settings.PskIdentityResolver; set => Settings.PskIdentityResolver = value; }

        /// <summary>Maps an SRP username to its verifier (null for unknown users); enables the SRP suites.</summary>
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get => Settings.SrpVerifierProvider; set => Settings.SrpVerifierProvider = value; }

        /// <summary>
        /// Maps a TLS-PWD username to its credential (null for unknown users, whose handshakes are simulated);
        /// enables the ECCPWD suites.
        /// </summary>
        public Func<string, PwdCredential> PwdCredentialProvider { get => Settings.PwdCredentialProvider; set => Settings.PwdCredentialProvider = value; }

        /// <summary>Resumable sessions by session ID; null disables session ID resumption.</summary>
        public IDtls12SessionCache SessionCache { get => Settings.SessionCache; set => Settings.SessionCache = value; }

        /// <summary>
        /// Keys for RFC 5077 session tickets (random per server by default); share them between servers to let them
        /// resume each other's sessions, or set null to disable tickets.
        /// </summary>
        public SessionTicketKeys TicketKeys { get => Settings.TicketKeys; set => Settings.TicketKeys = value; }

        /// <summary>Private key for recovering pwd_protect usernames (RFC 8492 §4.3.2); null accepts only pwd_clear.</summary>
        public Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters PwdProtectionKey { get => Settings.PwdProtectionKey; set => Settings.PwdProtectionKey = value; }
    }
}
