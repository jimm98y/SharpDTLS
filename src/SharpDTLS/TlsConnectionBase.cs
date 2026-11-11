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
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;

namespace SharpDTLS
{
    /// <summary>
    /// Version-independent machinery of one (D)TLS connection: serialized processing under a lock, an outbox
    /// flushed outside the lock (so synchronous transports cannot deadlock and event handlers never observe
    /// half-finished state), handshake flights (retransmitted over datagrams), alerts and closure.
    /// </summary>
    public abstract class TlsConnectionBase
    {
        private readonly object _sync = new object();
        private readonly object _sendOrder = new object();
        private readonly Queue<object> _outbox = new Queue<object>(); // byte[] datagrams and Action events, in order
        private readonly Action<byte[]> _send;
        private readonly string _protocolName;
        private readonly RetransmitTimer _retransmitTimer;

        // Last flight sent. Each entry rebuilds its records on every transmission, because a
        // retransmitted record needs a fresh record sequence number.
        private readonly List<Func<IEnumerable<byte[]>>> _flight = new List<Func<IEnumerable<byte[]>>>();

        private protected TlsConnectionBase(bool isClient, Action<byte[]> send, string protocolName)
        {
            IsClient = isClient;
            _send = send ?? throw new ArgumentNullException(nameof(send));
            _protocolName = protocolName;
            _retransmitTimer = new RetransmitTimer(
                () => Run(() => { if (!IsClosed) RetransmitFlight(); }),
                () => Run(() => Fail(new TimeoutException("DTLS handshake timed out."))));
        }

        protected bool IsClient { get; }
        protected string LogPrefix => $"[{_protocolName} {(IsClient ? "Client" : "Server")}]";

        public bool IsHandshakeComplete { get; protected set; }
        public bool IsClosed { get; private set; }

        /// <summary>
        /// Whether the peer ended the connection with close_notify. A stream that ends without it (a TCP FIN or reset)
        /// reads as closed all the same, as with SslStream, but may have been cut short by anyone on the path: a protocol
        /// whose messages end where the connection does should check this.
        /// </summary>
        public bool CloseNotifyReceived { get; private set; }

        /// <summary>Awaited by a stream's reader before each read: completes once the application has room for more data.</summary>
        internal Func<Task> ReceiveGate { get; set; }

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1, RFC 9147 §5.8).</summary>
        internal TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format), e.g. for Wireshark.</summary>
        internal Action<string> KeyLogWriter { get; set; }

        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SelectedSrtpProtectionProfile { get; protected set; }

        /// <summary>
        /// The SRTP Master Key Identifier both sides use (RFC 5764 §4.1.1): empty when no MKI is in use,
        /// null when use_srtp was not negotiated.
        /// </summary>
        public byte[] SelectedSrtpMki { get; protected set; }

        // ── Negotiated parameters, the same for every version ───────────────────────────────

        /// <summary>The negotiated protocol version (e.g. <see cref="DtlsVersion.Dtls12"/>), or 0 before ServerHello.</summary>
        public ushort NegotiatedVersion { get; protected set; }

        /// <summary>The negotiated cipher suite id, or 0 before ServerHello.</summary>
        public abstract ushort NegotiatedCipherSuite { get; }

        /// <summary>ClientHello.random, or null before ClientHello.</summary>
        public byte[] ClientRandom { get; protected set; }

        /// <summary>ServerHello.random, or null before ServerHello.</summary>
        public byte[] ServerRandom { get; protected set; }

        /// <summary>
        /// Whether the session keys are bound to the handshake transcript: extended_master_secret (RFC 7627) before
        /// (D)TLS 1.3, always for (D)TLS 1.3 (RFC 8446 §7.1).
        /// </summary>
        public virtual bool IsExtendedMasterSecret => true;

        /// <summary>Whether the handshake resumed an earlier session.</summary>
        public abstract bool IsResumed { get; }

        /// <summary>The X.509 certificate this side authenticated with, or null.</summary>
        public X509Certificate LocalCertificate { get; protected set; }

        /// <summary>The X.509 certificate the peer authenticated with (or the one of a resumed session), or null.</summary>
        public abstract X509Certificate PeerCertificate { get; }

        /// <summary>The application protocol negotiated with ALPN (RFC 7301), or null.</summary>
        public string ApplicationProtocol { get; protected set; }

        /// <summary>
        /// Client: the host name it sent in server_name. Server: the host name the client asked for (RFC 6066 §3), or null.
        /// </summary>
        public string ServerName { get; internal set; }

        /// <summary>The (EC)DHE or ML-KEM group of the key exchange, or 0 when there was none.</summary>
        public virtual ushort NegotiatedGroup { get; private protected set; }

        /// <summary>The certificate type the server authenticated with (RFC 7250).</summary>
        public virtual CertificateType ServerCertificateType { get; private protected set; }

        /// <summary>The peer's raw public key (DER SubjectPublicKeyInfo, RFC 7250) when it authenticated with one, else null.</summary>
        public virtual byte[] PeerRawPublicKey => null;

        /// <summary>Client: the OCSP response the server stapled (RFC 6066 §8, RFC 8446 §4.4.2.1), or null.</summary>
        public byte[] OcspResponse { get; private protected set; }

        /// <summary>Whether the records use encrypt-then-MAC (RFC 7366; CBC suites before (D)TLS 1.3).</summary>
        public virtual bool IsEncryptThenMac => false;

        /// <summary>The algorithm the peer compressed its certificate with (RFC 8879, (D)TLS 1.3), or null when it was not compressed.</summary>
        public ushort? CertificateCompressionAlgorithm { get; private protected set; }

        /// <summary>Whether the handshake was authenticated with an external PSK ((D)TLS 1.3, RFC 8446 §2.2).</summary>
        public virtual bool IsExternalPsk { get; private protected set; }

        /// <summary>Server: the identity of the external PSK the client authenticated with, or null.</summary>
        public byte[] ExternalPskIdentity { get; private protected set; }

        /// <summary>Server: whether a PSK handshake used psk_ke (no (EC)DHE, no forward secrecy; RFC 8446 §4.2.9).</summary>
        public virtual bool IsPskOnlyKeyExchange => false;

        /// <summary>Whether the server accepted the client's 0-RTT data ((D)TLS 1.3, RFC 8446 §4.2.10).</summary>
        public virtual bool EarlyDataAccepted { get; private protected set; }

        /// <summary>Our connection ID (RFC 9146, RFC 9147 §9): the peer sends it in its records. Null when not negotiated.</summary>
        public abstract byte[] ConnectionId { get; }

        /// <summary>The peer's connection ID, sent in our records. Null when not negotiated.</summary>
        public abstract byte[] PeerConnectionId { get; }

        // ── Server connections ───────────────────────────────────────────────────────────────

        /// <summary>Server: where this connection sends, the client's address, which can move with connection IDs.</summary>
        public virtual EndPoint RemoteEndPoint => null;

        /// <summary>Server: a newer client address awaiting <see cref="ConfirmPeerAddress"/> (when not following automatically).</summary>
        public virtual EndPoint PendingPeerAddress => null;

        /// <summary>
        /// Server: the client appeared at a new address (RFC 9146 §6): a record carrying our CID authenticated, was newer
        /// than any before and came from elsewhere. With AutoUpdatePeerAddress replies already go there; otherwise the
        /// address is pending until <see cref="ConfirmPeerAddress"/>.
        /// </summary>
        public event EventHandler<(EndPoint Old, EndPoint New)> PeerAddressChanged;

        /// <summary>Server: sends to <paramref name="address"/> from now on, after the application has checked it can be reached.</summary>
        public virtual void ConfirmPeerAddress(EndPoint address) => throw new NotSupportedException("Only server connections follow the client's address.");

        private protected void RaisePeerAddressChanged((EndPoint Old, EndPoint New) change) => RaiseEvent(() => PeerAddressChanged?.Invoke(this, change));

        /// <summary>The largest record payload without any negotiated limit (RFC 5246 §6.2.1, RFC 8446 §5.1).</summary>
        public const int MaxRecordPayload = 16384;

        /// <summary>
        /// The most data one SendApplicationData call can carry: 2^14 bytes, or less when the peer asked for smaller
        /// records with record_size_limit (RFC 8449) or max_fragment_length (RFC 6066). Data is never split, as that
        /// would change the datagram boundaries the peer sees.
        /// </summary>
        public virtual int MaxApplicationDataSize => PeerRecordLimit;

        /// <summary>The most payload (content without the DTLS 1.3 content type) the peer accepts per record.</summary>
        protected int PeerRecordLimit { get; set; } = MaxRecordPayload;

        /// <summary>The most payload per protected record we accept; larger records are a record_overflow.</summary>
        protected int ReceiveRecordLimit { get; set; } = MaxRecordPayload;

        /// <summary>Throws record_overflow for a protected record payload over <see cref="ReceiveRecordLimit"/>.</summary>
        protected void CheckReceivedRecordSize(int payloadLength)
        {
            if (payloadLength > ReceiveRecordLimit)
                throw new DtlsException(AlertDescription.RecordOverflow, $"Record of {payloadLength} bytes exceeds the limit of {ReceiveRecordLimit}.");
        }

        public event EventHandler<byte[]> ApplicationDataReceived;
        public event EventHandler<AlertDescription> AlertReceived;
        public event EventHandler<Exception> Failed;
        public event EventHandler Closed;

        // ── (D)TLS 1.3 post-handshake operations ─────────────────────────────────────────────

        /// <summary>The peer updated its write keys with a KeyUpdate ((D)TLS 1.3, RFC 8446 §4.6.3).</summary>
        public event EventHandler KeyUpdateReceived;

        /// <summary>
        /// Sends a KeyUpdate ((D)TLS 1.3): the new write keys take effect once the peer ACKs it (RFC 9147 §8);
        /// <paramref name="requestUpdate"/> asks the peer to update its keys too.
        /// </summary>
        public virtual void SendKeyUpdate(bool requestUpdate = false) => throw Requires13();

        /// <summary>Spare CIDs the peer gave us for sending, e.g. when moving to a new path (DTLS 1.3).</summary>
        public virtual int SpareConnectionIdCount => 0;

        /// <summary>
        /// Asks the peer for <paramref name="count"/> spare CIDs to send with (DTLS 1.3, RFC 9147 §9). Needs a negotiated
        /// non-empty peer CID; only one request may be outstanding.
        /// </summary>
        public virtual void RequestConnectionIds(byte count) => throw Requires13();

        /// <summary>
        /// Gives the peer <paramref name="count"/> new CIDs to send to us with (DTLS 1.3): spares, or with
        /// <paramref name="immediate"/> to be used at once (RFC 9147 §9).
        /// </summary>
        public virtual void IssueConnectionIds(int count, bool immediate = false) => throw Requires13();

        /// <summary>Switches to the next spare CID for sending (DTLS 1.3); false when there is none.</summary>
        public virtual bool UseSpareConnectionId() => throw Requires13();

        /// <summary>Server: sends another session ticket ((D)TLS 1.3, RFC 8446 §4.6.1); one is sent automatically after the handshake.</summary>
        public virtual void SendNewSessionTicket() => throw Requires13();

        /// <summary>Server: whether the client offered post_handshake_auth, so <see cref="RequestClientCertificate"/> may be used.</summary>
        public virtual bool AllowsPostHandshakeAuthentication => false;

        /// <summary>
        /// Server: asks the client for its certificate after the handshake ((D)TLS 1.3, RFC 8446 §4.6.2). The answer is
        /// checked like one in the handshake; with <paramref name="required"/> an answer without a certificate is a
        /// certificate_required alert.
        /// </summary>
        public virtual void RequestClientCertificate(bool required = true) => throw Requires13();

        /// <summary>
        /// Server: the client answered <see cref="RequestClientCertificate"/>: <see cref="PeerCertificate"/> (or
        /// <see cref="PeerRawPublicKey"/>) is then the authenticated client, or unchanged when it sent none.
        /// </summary>
        public event EventHandler PostHandshakeAuthenticationCompleted;

        private protected void RaiseKeyUpdateReceived() => RaiseEvent(() => KeyUpdateReceived?.Invoke(this, EventArgs.Empty));

        private protected void RaisePostHandshakeAuthenticationCompleted() => RaiseEvent(() => PostHandshakeAuthenticationCompleted?.Invoke(this, EventArgs.Empty));

        private NotSupportedException Requires13() => new NotSupportedException($"Not available on a {(IsClient ? "client" : "server")} connection of this version.");

        // ── Public operations ────────────────────────────────────────────────────────────────

        /// <summary>Processes one received UDP datagram (which may contain several records).</summary>
        internal void ProcessDatagram(byte[] datagram) => ProcessDatagram(datagram, null);

        /// <summary>The source address of the datagram being processed, when the transport reports it.</summary>
        protected EndPoint DatagramSource { get; private set; }

        /// <summary>The datagram being processed (for handing it to another engine).</summary>
        protected byte[] CurrentDatagram { get; private set; }

        /// <summary>Another engine took the connection over: no more input is read.</summary>
        protected bool InputDetached { get; set; }

        /// <summary>Processes a datagram from <paramref name="source"/> (for connection-ID address updates).</summary>
        internal void ProcessDatagram(byte[] datagram, EndPoint source) => Run(() =>
        {
            if (IsClosed || InputDetached)
                return;
            DatagramSource = source;
            CurrentDatagram = datagram;

            foreach (var record in DtlsRecordSplitter.Split(datagram, ReceiveConnectionIdLength))
            {
                try
                {
                    ProcessRecord(record);
                }
                catch (DtlsRecordDiscardedException ex)
                {
                    Debug.WriteLine($"{LogPrefix} Discarded record: {ex.Message}");
                }

                if (IsClosed || InputDetached)
                    break;
            }
        });

        public void SendApplicationData(byte[] data) => Locked(() =>
        {
            if (!IsHandshakeComplete || IsClosed)
                throw new InvalidOperationException("The handshake has not completed.");
            if (data.Length > MaxApplicationDataSize)
                throw new ArgumentException($"At most {MaxApplicationDataSize} bytes fit in one record.", nameof(data));
            WriteApplicationData(data);
        });

        /// <summary>Keying material exporter (RFC 5705 for DTLS 1.0/1.2, RFC 8446 §7.5 for DTLS 1.3).</summary>
        public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
        {
            lock (_sync)
            {
                if (!IsHandshakeComplete)
                    throw new InvalidOperationException("The handshake has not completed.");
                // RFC 7627 §5.4: without the extended master secret, two connections can share a master secret (the
                // triple handshake), and so their exported keys.
                if (!IsExtendedMasterSecret)
                    throw new InvalidOperationException("Keying material is not exported from a TLS 1.2 session without the extended master secret (RFC 7627).");
                return ExportKeyingMaterialCore(label, context, length);
            }
        }

        /// <summary>SRTP master keys and salts (RFC 5764 §4.2), or null when use_srtp was not negotiated.</summary>
        public DtlsSrtpKeys GetSrtpKeys()
        {
            if (SelectedSrtpProtectionProfile == null)
                return null;
            ushort profile = SelectedSrtpProtectionProfile.Value;
            return DtlsSrtp.Split(profile, ExportKeyingMaterial(DtlsSrtp.ExporterLabel, null, DtlsSrtp.KeyingMaterialLength(profile)), SelectedSrtpMki);
        }

        /// <summary>Sends close_notify and closes the connection.</summary>
        public void Close() => Locked(() =>
        {
            if (IsClosed)
                return;
            SendAlert(AlertDescription.CloseNotify, fatal: false);
            CloseInternal();
        });

        // ── Version-specific hooks ───────────────────────────────────────────────────────────

        protected abstract void ProcessRecord(byte[] record);

        /// <summary>Length of the connection ID in records sent to us (0 without connection IDs).</summary>
        protected virtual int ReceiveConnectionIdLength => 0;
        protected abstract void WriteApplicationData(byte[] data);
        protected abstract byte[] ExportKeyingMaterialCore(string label, byte[] context, int length);
        protected abstract void SendAlert(AlertDescription description, bool fatal);

        /// <summary>Whether a received alert terminates the connection (RFC 5246 §7.2 vs RFC 8446 §6).</summary>
        protected virtual bool IsAlertFatal(byte level, AlertDescription description) => level == 2;

        /// <summary>
        /// Whether the transport is reliable and ordered (TLS over TCP): nothing is retransmitted, and records leave in
        /// exactly the order they were queued.
        /// </summary>
        protected virtual bool IsReliableTransport => false;

        /// <summary>Called when a new flight starts (before any of its records are built).</summary>
        protected virtual void OnFlightStarted() { }

        // ── Flights and retransmission ───────────────────────────────────────────────────────

        protected void BeginFlight()
        {
            StopRetransmission();
            _flight.Clear();
            OnFlightStarted();
        }

        /// <summary>Adds a message to the current flight and sends it now.</summary>
        protected void SendInFlight(Func<IEnumerable<byte[]>> build)
        {
            _flight.Add(build);
            foreach (var datagram in build())
                Enqueue(datagram);
        }

        protected void RetransmitFlight()
        {
            if (_flight.Count == 0 || IsReliableTransport)
                return;
            Debug.WriteLine($"{LogPrefix} Retransmitting flight ({_flight.Count} messages)");
            foreach (var build in _flight)
                foreach (var datagram in build())
                    Enqueue(datagram);
        }

        protected bool HasFlight => _flight.Count > 0;
        protected bool IsRetransmissionArmed => _retransmitTimer.IsRunning;
        protected void ArmRetransmission()
        {
            if (!IsReliableTransport)
                _retransmitTimer.Start(InitialRetransmitTimeout);
        }
        protected void StopRetransmission() => _retransmitTimer.Stop();

        // ── Alerts and failure ───────────────────────────────────────────────────────────────

        protected void OnAlertReceived(byte level, AlertDescription description)
        {
            Debug.WriteLine($"{LogPrefix} Received alert {description} (level {level})");
            RaiseEvent(() => AlertReceived?.Invoke(this, description));

            if (description == AlertDescription.CloseNotify)
            {
                CloseNotifyReceived = true;
                // Respond with our own close_notify (RFC 5246 §7.2.1, RFC 8446 §6.1).
                SendAlert(AlertDescription.CloseNotify, fatal: false);
                CloseInternal();
            }
            else if (IsAlertFatal(level, description))
            {
                var error = new DtlsException(description, $"Peer sent fatal alert {description}");
                CloseInternal();
                RaiseEvent(() => Failed?.Invoke(this, error));
            }
            else
            {
                CountEmptyRecord();
            }
        }

        protected void Fail(Exception ex)
        {
            if (IsClosed)
                return;

            var alert = ex switch
            {
                DtlsException dtls => dtls.Alert,
                DtlsRecordAuthenticationException => AlertDescription.BadRecordMac,
                TimeoutException => (AlertDescription?)null,
                InvalidDataException or ArgumentException or IndexOutOfRangeException or NotSupportedException => AlertDescription.DecodeError,
                _ => AlertDescription.InternalError,
            };

            Debug.WriteLine($"{LogPrefix} Connection failed: {ex.Message}");
            if (alert.HasValue)
            {
                try { SendAlert(alert.Value, fatal: true); }
                catch (Exception sendError) { Debug.WriteLine($"{LogPrefix} Failed to send alert: {sendError.Message}"); }
            }
            CloseInternal();
            RaiseEvent(() => Failed?.Invoke(this, ex));
        }

        protected void CloseInternal()
        {
            if (IsClosed)
                return;
            IsClosed = true;
            StopRetransmission();
            OnClosed();
            RaiseEvent(() => Closed?.Invoke(this, EventArgs.Empty));
        }

        protected virtual void OnClosed() { }

        // ── Output and events ────────────────────────────────────────────────────────────────

        protected void Enqueue(byte[] datagram) => _outbox.Enqueue(datagram);

        /// <summary>Queues an event to be raised after the connection lock is released.</summary>
        protected void RaiseEvent(Action raise) => _outbox.Enqueue(raise);

        protected void RaiseApplicationData(byte[] data)
        {
            // On a stream an empty record carries nothing: a peer may send a few, not an endless run of them.
            if (data.Length == 0 && IsReliableTransport)
            {
                CountEmptyRecord();
                return;
            }
            _emptyRecords = 0;
            RaiseEvent(() => ApplicationDataReceived?.Invoke(this, data));
        }

        private int _emptyRecords;
        private const int MaxConsecutiveEmptyRecords = 32;

        /// <summary>
        /// Counts a record of no effect (empty application data, a warning alert) on a stream, where every record is the
        /// peer's: past a few in a row the connection fails, as each costs a decryption and nothing to send.
        /// </summary>
        protected void CountEmptyRecord()
        {
            if (!IsReliableTransport)
                return;
            if (++_emptyRecords > MaxConsecutiveEmptyRecords)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"More than {MaxConsecutiveEmptyRecords} records in a row of no content.");
        }

        /// <summary>Runs <paramref name="action"/> under the lock; any exception fails the connection.</summary>
        protected void Run(Action action)
        {
            lock (_sync)
            {
                var inspected = TlsInspector.Current != null ? TlsInspector.Enter(this, IsClient) : default;
                try
                {
                    action();
                }
                catch (Exception ex)
                {
                    Fail(ex);
                }
                finally
                {
                    if (TlsInspector.Current != null)
                        TlsInspector.Exit(inspected);
                }
            }
            Flush();
        }

        /// <summary>Runs <paramref name="action"/> under the lock; exceptions propagate to the caller.</summary>
        protected void Locked(Action action)
        {
            try
            {
                lock (_sync)
                {
                    var inspected = TlsInspector.Current != null ? TlsInspector.Enter(this, IsClient) : default;
                    try
                    {
                        action();
                    }
                    finally
                    {
                        if (TlsInspector.Current != null)
                            TlsInspector.Exit(inspected);
                    }
                }
            }
            finally
            {
                Flush();
            }
        }

        private void Flush()
        {
            if (Monitor.IsEntered(_sync))
                return; // the outermost caller flushes once the lock is released

            if (!IsReliableTransport)
            {
                FlushOutbox();
                return;
            }
            // A stream must see the records in sequence-number order, so flushes do not overlap.
            lock (_sendOrder)
                FlushOutbox();
        }

        private void FlushOutbox()
        {
            while (true)
            {
                object next;
                lock (_sync)
                {
                    if (_outbox.Count == 0)
                        return;
                    next = _outbox.Dequeue();
                }

                try
                {
                    if (next is byte[] datagram)
                        _send(datagram);
                    else
                        ((Action)next)();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"{LogPrefix} {(next is byte[] ? "Send" : "Event handler")} failed: {ex.Message}");
                    // A stream that failed a write has lost part of the record stream: the connection is over. (A
                    // datagram lost is retransmitted or not, as any other.)
                    if (next is byte[] && IsReliableTransport)
                    {
                        lock (_sync)
                        {
                            if (!IsClosed)
                            {
                                CloseInternal();
                                RaiseEvent(() => Failed?.Invoke(this, ex));
                            }
                        }
                    }
                }
            }
        }
    }
}
