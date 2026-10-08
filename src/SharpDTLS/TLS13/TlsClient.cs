using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpDTLS.TLS12;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace SharpDTLS.TLS13
{
    /// <summary>
    /// A TLS client for every version: one ClientHello offers TLS 1.3 (<see cref="Tls13"/>) and TLS 1.2 and below
    /// (<see cref="Tls12"/>), and the server's choice decides which engine continues. Each engine's own settings are
    /// configured on it (the shared ones also through this class). A TLS 1.2 ServerHello carrying the RFC 8446 downgrade
    /// sentinel is rejected.
    /// </summary>
    public sealed class TlsClient
    {
        private readonly Stream _stream;
        private TlsConnectionBase _active;

        public TlsClient(Stream stream, bool leaveStreamOpen = false)
        {
            _stream = stream;
            Tls12 = new Tls12Client(record => TlsStreamPump.Write(stream, record));
            Tls13 = new Tls13Client(record => TlsStreamPump.Write(stream, record));
            Tls13.LegacyServerHello += pending =>
            {
                _active = Tls12;
                Tls12.ProcessStreamData(pending, 0, pending.Length);
            };
            foreach (TlsConnectionBase engine in new TlsConnectionBase[] { Tls12, Tls13 })
            {
                engine.ApplicationDataReceived += (_, data) => ApplicationDataReceived?.Invoke(this, data);
                engine.Failed += (sender, ex) => { if (sender == _active) Failed?.Invoke(this, ex); };
                engine.Closed += (sender, _) =>
                {
                    if (sender != _active)
                        return;
                    if (!leaveStreamOpen)
                        _stream.Dispose();
                    Closed?.Invoke(this, EventArgs.Empty);
                };
            }
            Tls12.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
            Tls13.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>The TLS 1.0-1.2 engine and its settings (suites, resumption, PSK/SRP...).</summary>
        public Tls12Client Tls12 { get; }

        /// <summary>The TLS 1.3 engine and its settings (suites, groups, tickets...).</summary>
        public Tls13Client Tls13 { get; }

        /// <summary>The oldest version offered; TLS 1.2 by default (RFC 8996 deprecates 1.0 and 1.1).</summary>
        public ushort MinimumVersion { get; set; } = TlsVersion.Tls12;

        /// <summary>The newest version offered; TLS 1.3 by default.</summary>
        public ushort MaximumVersion { get; set; } = TlsVersion.Tls13;

        /// <summary>The engine carrying the connection: a <see cref="Tls12Client"/> or a <see cref="Tls13Client"/>.</summary>
        public TlsConnectionBase Connection => _active;

        /// <summary>The negotiated version once the handshake has completed, else 0.</summary>
        public ushort NegotiatedVersion => _active?.IsHandshakeComplete != true ? (ushort)0
            : _active == Tls13 ? TlsVersion.Tls13 : Tls12.NegotiatedVersion;

        public bool IsHandshakeComplete => _active?.IsHandshakeComplete == true;
        public string ApplicationProtocol => _active?.ApplicationProtocol;
        public int MaxApplicationDataSize => _active?.MaxApplicationDataSize ?? TlsConnectionBase.MaxRecordPayload;

        // ── Settings shared by both engines ──────────────────────────────────────────────────

        /// <summary>The server's host name, sent in server_name.</summary>
        public string ServerName
        {
            get => Tls13.ServerName;
            set { Tls12.ServerName = value; Tls13.ServerName = value; }
        }

        public IList<string> ApplicationProtocols
        {
            get => Tls13.ApplicationProtocols;
            set { Tls12.ApplicationProtocols = value; Tls13.ApplicationProtocols = value; }
        }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ServerCertificateValidator
        {
            get => Tls13.ServerCertificateValidator;
            set { Tls12.ServerCertificateValidator = value; Tls13.ServerCertificateValidator = value; }
        }

        public AsymmetricCipherKeyPair ClientCertificateKeyPair
        {
            get => Tls13.ClientCertificateKeyPair;
            set { Tls12.ClientCertificateKeyPair = value; Tls13.ClientCertificateKeyPair = value; }
        }

        public X509Certificate ClientCertificate
        {
            get => Tls13.ClientCertificate;
            set { Tls12.ClientCertificate = value; Tls13.ClientCertificate = value; }
        }

        public IList<X509Certificate> ClientIntermediateCertificates
        {
            get => Tls13.ClientIntermediateCertificates;
            set { Tls12.ClientIntermediateCertificates = value; Tls13.ClientIntermediateCertificates = value; }
        }

        public event EventHandler HandshakeFinished;
        public event EventHandler<byte[]> ApplicationDataReceived;
        public event EventHandler<Exception> Failed;
        public event EventHandler Closed;

        public void BeginHandshake()
        {
            if (_active != null)
                throw new InvalidOperationException("The handshake has already started.");
            if (!ProtocolVersions.IsAtLeast(MaximumVersion, MinimumVersion))
                throw new InvalidOperationException("MaximumVersion is older than MinimumVersion.");

            bool tls13 = ProtocolVersions.IsAtLeast(MaximumVersion, TlsVersion.Tls13);
            bool legacy = !ProtocolVersions.IsAtLeast(MinimumVersion, TlsVersion.Tls13);
            Tls12.MinimumVersion = MinimumVersion;
            Tls12.MaximumVersion = tls13 ? TlsVersion.Tls12 : MaximumVersion;

            _active = tls13 ? Tls13 : Tls12;
            if (!tls13)
                Tls12.BeginHandshake();
            else if (!legacy)
                Tls13.BeginHandshake();
            else
                Tls12.AdoptClientHello(Tls13.BeginMergedHandshake(Tls12.PrepareClientHello(), MinimumVersion));
            // Only now: the server's answer must find both engines ready.
            _ = Pump();
        }

        public void SendApplicationData(byte[] data) => (_active ?? throw new InvalidOperationException("The handshake has not started.")).SendApplicationData(data);

        public byte[] ExportKeyingMaterial(string label, byte[] context, int length) => _active.ExportKeyingMaterial(label, context, length);

        public void Close() => _active?.Close();

        private Task Pump() => Task.Run(async () =>
        {
            byte[] buffer = new byte[16384 + 2048 + 5];
            try
            {
                int read;
                while (!_active.IsClosed && (read = await _stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
                {
                    if (_active is Tls12Connection tls12)
                        tls12.ProcessStreamData(buffer, 0, read);
                    else
                        ((Tls13Connection)_active).ProcessStreamData(buffer, 0, read);
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                Debug.WriteLine($"[TLS] Read failed: {ex.Message}");
            }
            if (_active is Tls12Connection c12)
                c12.OnTransportClosed();
            else
                ((Tls13Connection)_active).OnTransportClosed();
        });
    }
}
