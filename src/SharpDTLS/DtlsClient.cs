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

using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
using System;

namespace SharpDTLS
{
    /// <summary>
    /// A DTLS client for every version: one ClientHello offers DTLS 1.3 and DTLS 1.2 and below, and the server's choice
    /// decides which version continues. A DTLS 1.2 ServerHello carrying the RFC 9147 §5.3 downgrade sentinel is
    /// rejected.
    /// </summary>
    public sealed class DtlsClient : TlsClientBase
    {
        private volatile TlsConnectionBase _active;

        public DtlsClient(IClientTransport clientTransport)
            : base(new Dtls12Client(clientTransport, receive: false), new Dtls13Client(clientTransport, receive: false))
        {
            ClientTransport = clientTransport;

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
            WireSessionEvents();
        }

        public IClientTransport ClientTransport { get; }

        /// <summary>The DTLS 1.0-1.2 engine.</summary>
        internal Dtls12Client Dtls12 => (Dtls12Client)Engine12;

        /// <summary>The DTLS 1.3 engine.</summary>
        internal Dtls13Client Dtls13 => (Dtls13Client)Engine13;

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

        // ── DTLS settings ────────────────────────────────────────────────────────────────────

        /// <summary>SRTP protection profiles offered in use_srtp (RFC 5764); null to not offer DTLS-SRTP.</summary>
        public ushort[] SrtpProtectionProfiles
        {
            get => Dtls13.SrtpProtectionProfiles;
            set { Dtls12.SrtpProtectionProfiles = value; Dtls13.SrtpProtectionProfiles = value; }
        }

        /// <summary>SRTP Master Key Identifier offered in use_srtp (RFC 5764 §4.1.1); null or empty for none, at most 255 bytes.</summary>
        public byte[] SrtpMasterKeyIdentifier
        {
            get => Dtls13.SrtpMasterKeyIdentifier;
            set { Dtls12.SrtpMasterKeyIdentifier = value; Dtls13.SrtpMasterKeyIdentifier = value; }
        }

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1, RFC 9147 §5.8).</summary>
        public TimeSpan InitialRetransmitTimeout
        {
            get => Dtls13.InitialRetransmitTimeout;
            set { Dtls12.InitialRetransmitTimeout = value; Dtls13.InitialRetransmitTimeout = value; }
        }

        /// <summary>
        /// Offer connection IDs (RFC 9147 §9) so the association survives our address changing: a server that agrees
        /// gives us a CID to send in every record.
        /// </summary>
        public bool UseConnectionId
        {
            get => Dtls13.UseConnectionId;
            set { Dtls12.UseConnectionId = value; Dtls13.UseConnectionId = value; }
        }

        /// <summary>Length of the CID we ask the server to send us; 0 (the default) when only our address may change.</summary>
        public int ConnectionIdLength
        {
            get => Dtls13.ConnectionIdLength;
            set { Dtls12.ConnectionIdLength = value; Dtls13.ConnectionIdLength = value; }
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
