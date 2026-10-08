using System;
using System.Net;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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

        protected TlsConnectionBase(bool isClient, Action<byte[]> send, string protocolName)
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

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 6347 §4.2.4.1, RFC 9147 §5.8).</summary>
        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format), e.g. for Wireshark.</summary>
        public Action<string> KeyLogWriter { get; set; }

        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SelectedSrtpProtectionProfile { get; protected set; }

        /// <summary>The application protocol negotiated with ALPN (RFC 7301), or null.</summary>
        public string ApplicationProtocol { get; protected set; }

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

        // ── Public operations ────────────────────────────────────────────────────────────────

        /// <summary>Processes one received UDP datagram (which may contain several records).</summary>
        public void ProcessDatagram(byte[] datagram) => ProcessDatagram(datagram, null);

        /// <summary>The source address of the datagram being processed, when the transport reports it.</summary>
        protected EndPoint DatagramSource { get; private set; }

        /// <summary>Processes a datagram from <paramref name="source"/> (for connection-ID address updates).</summary>
        public void ProcessDatagram(byte[] datagram, EndPoint source) => Run(() =>
        {
            if (IsClosed)
                return;
            DatagramSource = source;

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

                if (IsClosed)
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
                return ExportKeyingMaterialCore(label, context, length);
            }
        }

        /// <summary>SRTP master keys and salts (RFC 5764 §4.2), or null when use_srtp was not negotiated.</summary>
        public DtlsSrtpKeys GetSrtpKeys()
        {
            if (SelectedSrtpProtectionProfile == null)
                return null;
            ushort profile = SelectedSrtpProtectionProfile.Value;
            return DtlsSrtp.Split(profile, ExportKeyingMaterial(DtlsSrtp.ExporterLabel, null, DtlsSrtp.KeyingMaterialLength(profile)));
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
        }

        protected void Fail(Exception ex)
        {
            if (IsClosed)
                return;

            var alert = ex switch
            {
                DtlsException dtls => dtls.Alert,
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

        protected void RaiseApplicationData(byte[] data) => RaiseEvent(() => ApplicationDataReceived?.Invoke(this, data));

        /// <summary>Runs <paramref name="action"/> under the lock; any exception fails the connection.</summary>
        protected void Run(Action action)
        {
            lock (_sync)
            {
                try
                {
                    action();
                }
                catch (Exception ex)
                {
                    Fail(ex);
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
                    action();
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
                }
            }
        }
    }
}
