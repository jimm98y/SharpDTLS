using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// A DTLS client for every version: one ClientHello offers DTLS 1.3 and DTLS 1.2 and below, and the server's choice
    /// decides which version continues. A DTLS 1.2 ServerHello carrying the RFC 9147 §5.3 downgrade sentinel is
    /// rejected.
    /// </summary>
    public sealed class DtlsClient
    {
        private volatile TlsConnectionBase _active;

        public DtlsClient(IClientTransport clientTransport)
        {
            ClientTransport = clientTransport;
            Dtls12 = new Dtls12Client(clientTransport, receive: false);
            Dtls13 = new Dtls13Client(clientTransport, receive: false);

            // Under the 1.3 engine's lock, so the next datagram already finds the 1.2 engine in charge.
            Dtls13.LegacyDatagramServerHello = handoff =>
            {
                Dtls12.AdoptHandoff(handoff);
                _active = Dtls12;
                foreach (byte[] record in handoff.Records)
                    Dtls12.ProcessDatagram(record);
            };
            clientTransport.OnDataReceived += (_, data) => _active?.ProcessDatagram(data);

            foreach (TlsConnectionBase engine in new TlsConnectionBase[] { Dtls12, Dtls13 })
            {
                engine.ApplicationDataReceived += (_, data) => ApplicationDataReceived?.Invoke(this, data);
                engine.Failed += (sender, ex) => { if (sender == _active) Failed?.Invoke(this, ex); };
                engine.Closed += (sender, _) => { if (sender == _active) Closed?.Invoke(this, EventArgs.Empty); };
                engine.AlertReceived += (_, alert) => AlertReceived?.Invoke(this, alert);
            }
            Dtls12.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
            Dtls13.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        public IClientTransport ClientTransport { get; }

        /// <summary>The DTLS 1.0-1.2 engine.</summary>
        internal Dtls12Client Dtls12 { get; }

        /// <summary>The DTLS 1.3 engine.</summary>
        internal Dtls13Client Dtls13 { get; }

        /// <summary>The oldest version offered; DTLS 1.2 by default (RFC 8996 deprecates DTLS 1.0).</summary>
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>The newest version offered; DTLS 1.3 by default.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls13;

        /// <summary>The engine carrying the connection: a <see cref="Dtls12Client"/> or a <see cref="Dtls13Client"/>.</summary>
        public TlsConnectionBase Connection => _active;

        /// <summary>The negotiated version once the handshake has completed, else 0.</summary>
        public ushort NegotiatedVersion => _active?.IsHandshakeComplete != true ? (ushort)0
            : _active == Dtls13 ? DtlsVersion.Dtls13 : Dtls12.NegotiatedVersion;

        public bool IsHandshakeComplete => _active?.IsHandshakeComplete == true;
        public string ApplicationProtocol => _active?.ApplicationProtocol;
        public ushort? SelectedSrtpProtectionProfile => _active?.SelectedSrtpProtectionProfile;
        public byte[] SelectedSrtpMki => _active?.SelectedSrtpMki;
        public int MaxApplicationDataSize => _active?.MaxApplicationDataSize ?? TlsConnectionBase.MaxRecordPayload;

        // ── Settings shared by both engines ──────────────────────────────────────────────────

        /// <summary>The server's host name, sent in server_name.</summary>
        public string ServerName
        {
            get => Dtls13.ServerName;
            set { Dtls12.ServerName = value; Dtls13.ServerName = value; }
        }

        public IList<string> ApplicationProtocols
        {
            get => Dtls13.ApplicationProtocols;
            set { Dtls12.ApplicationProtocols = value; Dtls13.ApplicationProtocols = value; }
        }

        /// <summary>SRTP protection profiles offered with use_srtp (RFC 5764); null or empty for none.</summary>
        public ushort[] SrtpProtectionProfiles
        {
            get => Dtls13.SrtpProtectionProfiles;
            set { Dtls12.SrtpProtectionProfiles = value; Dtls13.SrtpProtectionProfiles = value; }
        }

        /// <summary>SRTP Master Key Identifier offered with use_srtp (RFC 5764 §4.1.1); null or empty for none.</summary>
        public byte[] SrtpMasterKeyIdentifier
        {
            get => Dtls13.SrtpMasterKeyIdentifier;
            set { Dtls12.SrtpMasterKeyIdentifier = value; Dtls13.SrtpMasterKeyIdentifier = value; }
        }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator
        {
            get => Dtls13.ServerCertificateValidator;
            set { Dtls12.ServerCertificateValidator = value; Dtls13.ServerCertificateValidator = value; }
        }

        public AsymmetricCipherKeyPair ClientCertificateKeyPair
        {
            get => Dtls13.ClientCertificateKeyPair;
            set { Dtls12.ClientCertificateKeyPair = value; Dtls13.ClientCertificateKeyPair = value; }
        }

        public X509Certificate ClientCertificate
        {
            get => Dtls13.ClientCertificate;
            set { Dtls12.ClientCertificate = value; Dtls13.ClientCertificate = value; }
        }

        public IList<X509Certificate> ClientIntermediateCertificates
        {
            get => Dtls13.ClientIntermediateCertificates;
            set { Dtls12.ClientIntermediateCertificates = value; Dtls13.ClientIntermediateCertificates = value; }
        }

        /// <summary>Initial retransmission timeout; doubles on every retransmission.</summary>
        public TimeSpan InitialRetransmitTimeout
        {
            get => Dtls13.InitialRetransmitTimeout;
            set { Dtls12.InitialRetransmitTimeout = value; Dtls13.InitialRetransmitTimeout = value; }
        }

        public event EventHandler HandshakeFinished;
        public event EventHandler<byte[]> ApplicationDataReceived;
        public event EventHandler<Exception> Failed;
        public event EventHandler Closed;
        public event EventHandler<AlertDescription> AlertReceived;

        public void BeginHandshake()
        {
            if (_active != null)
                throw new InvalidOperationException("The handshake has already started.");
            if (!DtlsVersion.IsAtLeast(MaximumVersion, MinimumVersion))
                throw new InvalidOperationException("MaximumVersion is older than MinimumVersion.");

            bool dtls13 = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13);
            bool legacy = !DtlsVersion.IsAtLeast(MinimumVersion, DtlsVersion.Dtls13);
            Dtls12.MinimumVersion = MinimumVersion;
            Dtls12.MaximumVersion = dtls13 ? DtlsVersion.Dtls12 : MaximumVersion;

            // Before sending: the server's answer must find the engine that reads it.
            _active = dtls13 ? Dtls13 : Dtls12;
            if (!dtls13)
                Dtls12.BeginHandshake();
            else if (!legacy)
                Dtls13.BeginHandshake();
            else
                Dtls13.BeginMergedHandshake(Dtls12.PrepareClientHello(), MinimumVersion);
        }

        public void SendApplicationData(byte[] data) => (_active ?? throw new InvalidOperationException("The handshake has not started.")).SendApplicationData(data);

        public byte[] ExportKeyingMaterial(string label, byte[] context, int length) => _active.ExportKeyingMaterial(label, context, length);

        public void Close() => _active?.Close();
    }
}
