using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.TLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace SharpDTLS
{
    /// <summary>
    /// A TLS client for every version: one ClientHello offers TLS 1.3 and TLS 1.2 and below, and the server's choice
    /// decides which version continues. A TLS 1.2 ServerHello carrying the RFC 8446 downgrade sentinel is rejected.
    /// </summary>
    public sealed class TlsClient : TlsClientBase
    {
        private readonly Stream _stream;
        private readonly bool _leaveStreamOpen;
        private TlsConnectionBase _active;

        public TlsClient(Stream stream, bool leaveStreamOpen = false)
            : base(new Tls12Client(record => TlsStreamPump.Write(stream, record)), new Tls13Client(record => TlsStreamPump.Write(stream, record)))
        {
            _stream = stream;
            _leaveStreamOpen = leaveStreamOpen;
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
                        TlsStreamPump.DisposeAfterLinger(_stream);
                    Closed?.Invoke(this, EventArgs.Empty);
                };
                engine.AlertReceived += (_, alert) => AlertReceived?.Invoke(this, alert);
            }
            Tls12.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
            Tls13.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, EventArgs.Empty);
            WireSessionEvents();
        }

        /// <summary>The TLS 1.0-1.2 engine.</summary>
        internal Tls12Client Tls12 => (Tls12Client)Engine12;

        /// <summary>The TLS 1.3 engine.</summary>
        internal Tls13Client Tls13 => (Tls13Client)Engine13;

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

        public event EventHandler HandshakeFinished;
        public event EventHandler<byte[]> ApplicationDataReceived;
        public event EventHandler<Exception> Failed;
        public event EventHandler Closed;
        public event EventHandler<AlertDescription> AlertReceived;

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

        private Task Pump() => TlsStreamPump.Run(_stream, () => _active, (buffer, read) =>
        {
            if (_active is Tls12Connection tls12)
                tls12.ProcessStreamData(buffer, 0, read);
            else
                ((Tls13Connection)_active).ProcessStreamData(buffer, 0, read);
        }, () =>
        {
            if (_active is Tls12Connection c12)
                c12.OnTransportClosed();
            else
                ((Tls13Connection)_active).OnTransportClosed();
        }, ownsStream: !_leaveStreamOpen);
    }
}
