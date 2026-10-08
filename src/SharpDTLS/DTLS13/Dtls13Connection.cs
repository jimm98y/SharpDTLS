using SharpDTLS.DTLS13.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// Per-association DTLS 1.3 machinery shared by client and server: record layer, handshake
    /// message ordering and reassembly, retransmission, ACKs (RFC 9147 §7), KeyUpdate (§8) and alerts.
    /// Subclasses implement the handshake state machine.
    /// </summary>
    public abstract class Dtls13Connection
    {
        // Maximum handshake body bytes per protected record; keeps datagrams under ~1200 bytes
        // (5 B header + 16 B tag + 12 B handshake header + 1 B content type + body).
        protected const int MaxHandshakeBodyPerRecord = 1160;
        private const int MaxBufferedMessages = 16;
        private const int MaxRetransmissions = 8;

        private readonly object _sync = new object();
        private readonly Queue<object> _outbox = new Queue<object>(); // byte[] datagrams and Action events, in order
        private readonly HandshakeReassembler _reassembler = new HandshakeReassembler();
        private readonly SortedDictionary<int, byte[]> _bufferedMessages = new SortedDictionary<int, byte[]>();
        private readonly Action<byte[]> _send;

        // Records that carried handshake messages of the peer's current flight, to be ACKed.
        private readonly List<(ulong Epoch, ulong SequenceNumber)> _receivedHandshakeRecords = new();

        // Last flight we sent, for retransmission. Protected messages are re-protected with fresh
        // record numbers on every transmission (RFC 9147 §5.8).
        private List<FlightEntry> _flight;
        private readonly List<(ulong Epoch, ulong SequenceNumber)> _flightRecords = new();
        private Timer _retransmitTimer;
        private int _retransmitCount;
        private TimeSpan _currentTimeout;

        // KeyUpdate we sent and are waiting to be ACKed before switching write keys.
        private List<(ulong Epoch, ulong SequenceNumber)> _pendingKeyUpdateRecords;
        private AcknowledgementDatagram _lastAck;
        private ushort _plaintextRecordSequence;

        protected bool IsClient { get; }
        protected int NextSendMessageSeq { get; set; }
        protected int NextReceiveMessageSeq { get; set; }

        public Dtls13Session Session { get; } = new Dtls13Session();
        public bool IsHandshakeComplete { get; protected set; }
        public bool IsClosed { get; private set; }

        /// <summary>Initial retransmission timeout; doubles on every retransmission (RFC 9147 §5.8.2 recommends 1 s).</summary>
        public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>The SRTP protection profile negotiated via use_srtp (RFC 5764), or null.</summary>
        public ushort? SelectedSrtpProtectionProfile { get; protected set; }

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format), e.g. for Wireshark.</summary>
        public Action<string> KeyLogWriter { get; set; }

        public event EventHandler<byte[]> ApplicationDataReceived;
        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;
        public event EventHandler<AlertDescription> AlertReceived;
        public event EventHandler<Exception> Failed;
        public event EventHandler Closed;

        private sealed class FlightEntry
        {
            public byte[] Plaintext;           // epoch-0 record (ClientHello/ServerHello) or handshake message + content type
            public bool IsPlaintextRecord;
            public Dtls13CryptoContext Keys;
        }

        protected Dtls13Connection(bool isClient, Action<byte[]> send)
        {
            IsClient = isClient;
            _send = send ?? throw new ArgumentNullException(nameof(send));
        }

        // ── Entry points ─────────────────────────────────────────────────────────────────────

        /// <summary>Processes one received UDP datagram (which may contain several records).</summary>
        public void ProcessDatagram(byte[] datagram)
        {
            lock (_sync)
            {
                if (IsClosed)
                    return;

                try
                {
                    foreach (var record in DtlsRecordSplitter.Split(datagram))
                    {
                        try
                        {
                            ProcessRecord(record);
                        }
                        catch (DtlsRecordDiscardedException ex)
                        {
                            Debug.WriteLine($"[DTLS13 {Role}] Discarded record: {ex.Message}");
                        }

                        if (IsClosed)
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Fail(ex);
                }
            }

            Flush();
        }

        public void SendApplicationData(byte[] data)
        {
            lock (_sync)
            {
                if (!IsHandshakeComplete || IsClosed)
                    throw new InvalidOperationException("The handshake has not completed.");
                SendProtected(Session.WriteKeys, new ApplicationDataDatagram(data).ToBytes());
            }
            Flush();
        }

        /// <summary>
        /// Sends a KeyUpdate. The new write keys take effect once the peer ACKs it (RFC 9147 §8).
        /// </summary>
        public void SendKeyUpdate(bool requestUpdate = false)
        {
            lock (_sync)
            {
                if (!IsHandshakeComplete || IsClosed)
                    throw new InvalidOperationException("The handshake has not completed.");
                if (_pendingKeyUpdateRecords != null)
                    throw new InvalidOperationException("A KeyUpdate is already in progress.");
                StartKeyUpdate(requestUpdate);
            }
            Flush();
        }

        /// <summary>RFC 8446 §7.5 keying material exporter.</summary>
        public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
        {
            lock (_sync)
            {
                if (!IsHandshakeComplete || Session.ExporterMasterSecret == null)
                    throw new InvalidOperationException("The handshake has not completed.");
                return Dtls13CryptoUtils.ExportKeyingMaterial(Session.ExporterMasterSecret, label, context, length, Session.CipherSuite);
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
        public void Close()
        {
            lock (_sync)
            {
                if (IsClosed)
                    return;
                SendAlert(AlertDescription.CloseNotify, fatal: false);
                CloseInternal();
            }
            Flush();
        }

        protected string Role => IsClient ? "Client" : "Server";

        // ── Handshake hooks for subclasses ───────────────────────────────────────────────────

        /// <summary>Handles a complete epoch-0 handshake record (ClientHello, ServerHello, HelloRetryRequest).</summary>
        protected abstract void OnPlaintextHandshake(byte[] record);

        /// <summary>Handles the next in-order protected handshake message (12-byte DTLS header + body + content type).</summary>
        protected abstract void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed);

        /// <summary>Called for a retransmitted epoch-0 handshake record while the handshake is in progress.</summary>
        protected virtual void OnDuplicatePlaintextHandshake(byte[] record) => RetransmitFlight();

        // ── Record layer ─────────────────────────────────────────────────────────────────────

        private void ProcessRecord(byte[] record)
        {
            if ((record[0] & 0xE0) == 0x20)
            {
                ProcessProtectedRecord(record);
                return;
            }

            byte contentType = record[0];
            int epoch = (record[3] << 8) | record[4];
            if (epoch != 0 || record.Length < 13)
                throw new DtlsRecordDiscardedException("Plaintext record outside epoch 0");

            switch (contentType)
            {
                case 0x16:
                    if (record.Length < 25)
                        throw new DtlsRecordDiscardedException("Truncated handshake record");
                    if (_reassembler.TryAddUnencryptedFragment(record, out byte[] complete))
                        OnPlaintextHandshake(complete);
                    break;

                case 0x15:
                    // Unprotected alerts are accepted only before keys are established.
                    if (Session.ServerHandshakeKeys == null && record.Length >= 15)
                        OnAlert(record[13], (AlertDescription)record[14]);
                    break;

                default:
                    throw new DtlsRecordDiscardedException($"Unexpected plaintext content type 0x{contentType:X2}");
            }
        }

        private void ProcessProtectedRecord(byte[] record)
        {
            int epochBits = record[0] & 0x03;

            // Newest epoch whose low bits match (RFC 9147 §4.2.2).
            Dtls13CryptoContext keys = null;
            for (int i = Session.ReadKeys.Count - 1; i >= 0; i--)
            {
                if ((int)(Session.ReadKeys[i].Epoch & 0x03) == epochBits)
                {
                    keys = Session.ReadKeys[i];
                    break;
                }
            }

            if (keys == null)
                throw new DtlsRecordDiscardedException($"No keys for epoch bits {epochBits}");

            var unprotected = Dtls13RecordProtection.Unprotect(keys, fromClient: !IsClient, record);
            byte[] inner = unprotected.InnerPlaintext;
            byte contentType = inner[inner.Length - 1];

            switch (contentType)
            {
                case 0x16:
                    _receivedHandshakeRecords.Add((keys.Epoch, unprotected.SequenceNumber));
                    ProcessHandshakeRecord(inner, keys);
                    break;

                case 0x17:
                    if (keys.Epoch < 3)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Application data in handshake epoch");
                    if (!IsHandshakeComplete)
                        throw new DtlsRecordDiscardedException("Application data before handshake completion");
                    OnApplicationDataReceived(inner);
                    break;

                case 0x15:
                    if (inner.Length != 3)
                        throw new DtlsException(AlertDescription.DecodeError, "Invalid alert");
                    OnAlert(inner[0], (AlertDescription)inner[1]);
                    break;

                case 0x1a:
                    var ack = new AcknowledgementDatagram();
                    ack.FromBytes(inner);
                    OnAck(ack, keys);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected content type 0x{contentType:X2}");
            }
        }

        private void ProcessHandshakeRecord(byte[] inner, Dtls13CryptoContext keys)
        {
            // A record may carry several handshake messages or fragments.
            int pos = 0;
            int end = inner.Length - 1; // exclude content type
            while (pos < end)
            {
                if (pos + 12 > end)
                    throw new DtlsException(AlertDescription.DecodeError, "Truncated handshake header");

                int fragmentLength = (inner[pos + 9] << 16) | (inner[pos + 10] << 8) | inner[pos + 11];
                if (pos + 12 + fragmentLength > end)
                    throw new DtlsException(AlertDescription.DecodeError, "Truncated handshake fragment");

                byte[] fragment = new byte[12 + fragmentLength + 1];
                Buffer.BlockCopy(inner, pos, fragment, 0, 12 + fragmentLength);
                fragment[fragment.Length - 1] = 0x16;
                pos += 12 + fragmentLength;

                int messageSeq = (fragment[4] << 8) | fragment[5];
                if (messageSeq < NextReceiveMessageSeq)
                {
                    OnDuplicateHandshake(messageSeq);
                    continue;
                }

                if (!_reassembler.TryAddFragment(fragment, out byte[] complete))
                    continue;

                if (messageSeq > NextReceiveMessageSeq)
                {
                    if (_bufferedMessages.Count < MaxBufferedMessages)
                        _bufferedMessages[messageSeq] = complete;
                    continue;
                }

                DeliverHandshake(complete);
                while (!IsClosed && _bufferedMessages.TryGetValue(NextReceiveMessageSeq, out var buffered))
                {
                    _bufferedMessages.Remove(NextReceiveMessageSeq);
                    DeliverHandshake(buffered);
                }
            }
        }

        private void DeliverHandshake(byte[] message)
        {
            NextReceiveMessageSeq++;

            var parsed = ParseHandshake(message);
            if (IsHandshakeComplete)
                OnPostHandshakeMessage(message, parsed);
            else
                OnHandshakeMessage(message, parsed);
        }

        private static IHandshakeDatagram ParseHandshake(byte[] message)
        {
            IHandshakeDatagram datagram = message[0] switch
            {
                0x04 => new NewSessionTicketDatagram(),
                0x08 => new EncryptedExtensionsDatagram(),
                0x0b => new CertificateDatagram(),
                0x0d => new CertificateRequestDatagram(),
                0x0f => new CertificateVerifyDatagram(),
                0x14 => new FinishedDatagram(),
                0x18 => new KeyUpdateDatagram(),
                _ => throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message type 0x{message[0]:X2}")
            };
            datagram.FromBytes(message);
            return datagram;
        }

        private void OnDuplicateHandshake(int messageSeq)
        {
            // The peer retransmitted a flight we already processed, so our response was probably lost:
            // resend our outstanding flight, or the ACK that completed the peer's flight.
            if (_retransmitTimer != null)
                RetransmitFlight();
            else if (_lastAck != null && Session.WriteKeys != null)
                SendProtected(Session.WriteKeys, _lastAck.ToBytes());
        }

        // ── Post-handshake messages ──────────────────────────────────────────────────────────

        private void OnPostHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            switch (parsed)
            {
                case NewSessionTicketDatagram nst when IsClient:
                    SendAck();
                    RaiseEvent(() => NewSessionTicketReceived?.Invoke(this, nst));
                    break;

                case KeyUpdateDatagram keyUpdate:
                    if (keyUpdate.UpdateRequest > 1)
                        throw new DtlsException(AlertDescription.IllegalParameter, "Invalid KeyUpdate request value");

                    // ACK with the current keys, then expect the peer's next epoch.
                    SendAck();
                    var latest = Session.ReadKeys[Session.ReadKeys.Count - 1];
                    var updated = IsClient
                        ? Dtls13CryptoUtils.UpdateServerTrafficSecret(latest)
                        : Dtls13CryptoUtils.UpdateClientTrafficSecret(latest);
                    AddReadKeys(updated);

                    RaiseEvent(() => KeyUpdateReceived?.Invoke(this, keyUpdate));
                    if (keyUpdate.UpdateRequest == 1 && _pendingKeyUpdateRecords == null)
                        StartKeyUpdate(requestUpdate: false);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected post-handshake message 0x{message[0]:X2}");
            }
        }

        private void StartKeyUpdate(bool requestUpdate)
        {
            var keyUpdate = new KeyUpdateDatagram(requestUpdate ? (byte)0x01 : (byte)0x00);
            _pendingKeyUpdateRecords = new List<(ulong, ulong)>();
            keyUpdate.SequenceNumber = NextSendMessageSeq++;
            var records = SendProtected(Session.WriteKeys, keyUpdate.ToBytes());
            _pendingKeyUpdateRecords.AddRange(records);
        }

        private void OnAck(AcknowledgementDatagram ack, Dtls13CryptoContext keys)
        {
            // Any ACK for our last flight completes it; partial ACKs are treated as complete flights
            // are always retransmitted in full.
            if (_flight != null && ack.Records.Any(r => _flightRecords.Contains(r)))
                StopRetransmission();

            if (_pendingKeyUpdateRecords != null && ack.Records.Any(r => _pendingKeyUpdateRecords.Contains(r)))
            {
                _pendingKeyUpdateRecords = null;
                Session.WriteKeys = IsClient
                    ? Dtls13CryptoUtils.UpdateClientTrafficSecret(Session.WriteKeys)
                    : Dtls13CryptoUtils.UpdateServerTrafficSecret(Session.WriteKeys);
                Debug.WriteLine($"[DTLS13 {Role}] KeyUpdate acknowledged, now writing epoch {Session.WriteKeys.Epoch}");
            }
        }

        // ── Sending ──────────────────────────────────────────────────────────────────────────

        /// <summary>Begins a new outgoing flight; subsequent Send* calls add to it.</summary>
        protected void BeginFlight()
        {
            StopRetransmission();
            _flight = new List<FlightEntry>();
            _flightRecords.Clear();
        }

        /// <summary>Sends an epoch-0 handshake message (ClientHello/ServerHello) as part of the current flight.</summary>
        protected byte[] SendPlaintextHandshake(ServerHelloDatagram serverHello)
        {
            serverHello.SequenceNumber = NextSendMessageSeq++;
            return SendPlaintextRecord(serverHello.ToBytes());
        }

        protected byte[] SendPlaintextHandshake(ClientHelloDatagram clientHello)
        {
            clientHello.SequenceNumber = NextSendMessageSeq++;
            return SendPlaintextRecord(clientHello.ToBytes());
        }

        /// <summary>Epoch-0 record sequence numbers continue from here (a stateless server starts after the HelloRetryRequest).</summary>
        protected void SetPlaintextRecordSequence(int next) => _plaintextRecordSequence = (ushort)next;

        private byte[] SendPlaintextRecord(byte[] record)
        {
            _flight?.Add(new FlightEntry { Plaintext = record, IsPlaintextRecord = true });
            int seq = _plaintextRecordSequence;
            foreach (var fragment in HandshakeFragmenter.FragmentUnencryptedRecord((byte[])record.Clone(), 1200, ref seq))
                _outbox.Enqueue(fragment);
            _plaintextRecordSequence = (ushort)seq;
            return record;
        }

        /// <summary>
        /// Assigns the next message_seq, adds the message to the transcript, and sends it protected with
        /// <paramref name="keys"/> as part of the current flight. Returns the serialized message.
        /// </summary>
        protected byte[] SendHandshake(IHandshakeDatagram message, Dtls13CryptoContext keys, bool addToTranscript = true)
        {
            message.SequenceNumber = NextSendMessageSeq++;
            byte[] plaintext = message.ToBytes();
            if (addToTranscript)
                Session.Transcript.AddHandshake(plaintext);

            _flight?.Add(new FlightEntry { Plaintext = plaintext, Keys = keys });
            _flightRecords.AddRange(SendFragments(plaintext, keys));
            return plaintext;
        }

        private List<(ulong, ulong)> SendFragments(byte[] plaintext, Dtls13CryptoContext keys)
        {
            var records = new List<(ulong, ulong)>();
            foreach (var fragment in HandshakeFragmenter.FragmentHandshakePlaintext(plaintext, MaxHandshakeBodyPerRecord))
                records.AddRange(SendProtected(keys, fragment));
            return records;
        }

        /// <summary>Protects and queues one record. Returns its record number.</summary>
        protected List<(ulong Epoch, ulong SequenceNumber)> SendProtected(Dtls13CryptoContext keys, byte[] innerPlaintext)
        {
            ulong seq = IsClient ? keys.ClientKeyUseCounter++ : keys.ServerKeyUseCounter++;
            if (seq >= (1UL << 48) - 1)
                throw new DtlsException(AlertDescription.InternalError, "Record sequence number space exhausted; a KeyUpdate is required");

            _outbox.Enqueue(Dtls13RecordProtection.Protect(keys, IsClient, (int)keys.Epoch, seq, innerPlaintext));
            return new List<(ulong, ulong)> { (keys.Epoch, seq) };
        }

        /// <summary>ACKs the handshake records received since the last ACK.</summary>
        protected void SendAck()
        {
            if (_receivedHandshakeRecords.Count == 0 || Session.WriteKeys == null)
                return;

            _lastAck = new AcknowledgementDatagram(_receivedHandshakeRecords);
            _receivedHandshakeRecords.Clear();
            SendProtected(Session.WriteKeys, _lastAck.ToBytes());
        }

        protected void ClearReceivedHandshakeRecords() => _receivedHandshakeRecords.Clear();

        protected void AddReadKeys(Dtls13CryptoContext keys)
        {
            Session.ReadKeys.Add(keys);
            // Keep the handshake epoch (for retransmitted handshake records) and the two newest application epochs.
            while (Session.ReadKeys.Count > 3)
                Session.ReadKeys.RemoveAt(Session.ReadKeys[0].Epoch == 2 ? 1 : 0);
        }

        // ── Retransmission (RFC 9147 §5.8) ───────────────────────────────────────────────────

        /// <summary>Arms the retransmission timer for the current flight.</summary>
        protected void ArmRetransmission()
        {
            _retransmitCount = 0;
            _currentTimeout = InitialRetransmitTimeout;
            _retransmitTimer?.Dispose();
            _retransmitTimer = new Timer(OnRetransmitTimer, null, _currentTimeout, Timeout.InfiniteTimeSpan);
        }

        protected void StopRetransmission()
        {
            _retransmitTimer?.Dispose();
            _retransmitTimer = null;
        }

        private void OnRetransmitTimer(object state)
        {
            lock (_sync)
            {
                if (IsClosed || _retransmitTimer == null)
                    return;

                if (++_retransmitCount > MaxRetransmissions)
                {
                    Fail(new TimeoutException("DTLS handshake timed out."));
                }
                else
                {
                    RetransmitFlight();
                    _currentTimeout = TimeSpan.FromTicks(Math.Min(_currentTimeout.Ticks * 2, TimeSpan.FromSeconds(60).Ticks));
                    _retransmitTimer?.Change(_currentTimeout, Timeout.InfiniteTimeSpan);
                }
            }
            Flush();
        }

        protected void RetransmitFlight()
        {
            if (_flight == null)
                return;

            Debug.WriteLine($"[DTLS13 {Role}] Retransmitting flight ({_flight.Count} messages)");
            foreach (var entry in _flight)
            {
                if (entry.IsPlaintextRecord)
                {
                    int seq = _plaintextRecordSequence;
                    foreach (var fragment in HandshakeFragmenter.FragmentUnencryptedRecord((byte[])entry.Plaintext.Clone(), 1200, ref seq))
                        _outbox.Enqueue(fragment);
                    _plaintextRecordSequence = (ushort)seq;
                }
                else
                {
                    _flightRecords.AddRange(SendFragments(entry.Plaintext, entry.Keys));
                }
            }
        }

        // ── Alerts and failure ───────────────────────────────────────────────────────────────

        private void OnAlert(byte level, AlertDescription description)
        {
            Debug.WriteLine($"[DTLS13 {Role}] Received alert {description} (level {level})");
            RaiseEvent(() => AlertReceived?.Invoke(this, description));

            if (description == AlertDescription.CloseNotify)
            {
                // RFC 8446 §6.1: respond with our own close_notify.
                SendAlert(AlertDescription.CloseNotify, fatal: false);
                CloseInternal();
            }
            else if (level == 2 || description != AlertDescription.UserCanceled)
            {
                // In TLS 1.3 all alerts except close_notify and user_canceled are fatal.
                var error = new DtlsException(description, $"Peer sent fatal alert {description}");
                RaiseEvent(() => Failed?.Invoke(this, error));
                CloseInternal();
            }
        }

        protected void Fail(Exception ex)
        {
            var alert = ex switch
            {
                DtlsException dtls => dtls.Alert,
                TimeoutException => (AlertDescription?)null,
                InvalidDataException or ArgumentException or IndexOutOfRangeException or NotSupportedException => AlertDescription.DecodeError,
                _ => AlertDescription.InternalError,
            };

            Debug.WriteLine($"[DTLS13 {Role}] Connection failed: {ex.Message}");
            if (alert.HasValue)
                SendAlert(alert.Value, fatal: true);
            CloseInternal();
            RaiseEvent(() => Failed?.Invoke(this, ex));
        }

        private void SendAlert(AlertDescription description, bool fatal)
        {
            byte level = fatal ? (byte)2 : (byte)1;
            try
            {
                if (Session.WriteKeys != null)
                {
                    SendProtected(Session.WriteKeys, new byte[] { level, (byte)description, 0x15 });
                }
                else
                {
                    int seq = _plaintextRecordSequence++;
                    byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, (byte)(seq >> 40), (byte)(seq >> 32), (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq, 0, 2, level, (byte)description };
                    _outbox.Enqueue(record);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DTLS13 {Role}] Failed to send alert: {ex.Message}");
            }
        }

        private void CloseInternal()
        {
            if (IsClosed)
                return;
            IsClosed = true;
            StopRetransmission();
            RaiseEvent(() => Closed?.Invoke(this, EventArgs.Empty));
        }

        // ── Events and output ────────────────────────────────────────────────────────────────

        private void OnApplicationDataReceived(byte[] inner)
        {
            byte[] data = new byte[inner.Length - 1];
            Buffer.BlockCopy(inner, 0, data, 0, data.Length);
            RaiseEvent(() => ApplicationDataReceived?.Invoke(this, data));
        }

        protected void WriteKeyLog(string clientRandomHex, Dtls13CryptoContext handshakeKeys, Dtls13CryptoContext applicationKeys)
        {
            var writer = KeyLogWriter;
            if (writer == null)
                return;

            string random = clientRandomHex.ToLowerInvariant();
            writer($"CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {Convert.ToHexString(handshakeKeys.ClientSecret).ToLowerInvariant()}");
            writer($"SERVER_HANDSHAKE_TRAFFIC_SECRET {random} {Convert.ToHexString(handshakeKeys.ServerSecret).ToLowerInvariant()}");
            writer($"CLIENT_TRAFFIC_SECRET_0 {random} {Convert.ToHexString(applicationKeys.ClientSecret).ToLowerInvariant()}");
            writer($"SERVER_TRAFFIC_SECRET_0 {random} {Convert.ToHexString(applicationKeys.ServerSecret).ToLowerInvariant()}");
        }

        /// <summary>Queues an event to be raised after the connection lock is released.</summary>
        protected void RaiseEvent(Action raise) => _outbox.Enqueue(raise);

        /// <summary>
        /// Sends queued datagrams and raises queued events outside the lock, so synchronous transports
        /// cannot deadlock and event handlers never observe a half-finished state transition.
        /// </summary>
        protected void Flush()
        {
            if (Monitor.IsEntered(_sync))
                return; // the outermost caller flushes once the lock is released

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
                    Debug.WriteLine($"[DTLS13 {Role}] {(next is byte[] ? "Send" : "Event handler")} failed: {ex.Message}");
                }
            }
        }

        /// <summary>Runs <paramref name="action"/> under the connection lock with failure handling, then flushes.</summary>
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
    }
}
