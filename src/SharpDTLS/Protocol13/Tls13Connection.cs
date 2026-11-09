using SharpDTLS.Protocol13.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// Per-connection (D)TLS 1.3 machinery shared by client and server: the DTLS 1.3 record layer with ACKs
    /// (RFC 9147 §7) or TLS 1.3 records over a stream (RFC 8446 §5), handshake message ordering and reassembly,
    /// and KeyUpdate. Subclasses implement the handshake state machine.
    /// </summary>
    internal abstract class Tls13Connection : TlsConnectionBase
    {
        // Maximum handshake body bytes per protected record; keeps datagrams under ~1200 bytes
        // (5 B header + 16 B tag + 12 B handshake header + 1 B content type + body).
        protected const int MaxHandshakeBodyPerRecord = 1160;
        private const int MaxBufferedMessages = 16;

        private readonly HandshakeReassembler _reassembler = new HandshakeReassembler();
        private readonly SortedDictionary<int, byte[]> _bufferedMessages = new SortedDictionary<int, byte[]>();

        // Records that carried handshake messages of the peer's current flight, to be ACKed.
        private readonly List<(ulong Epoch, ulong SequenceNumber)> _receivedHandshakeRecords = new();

        // Record numbers of every transmission of the current flight, to match ACKs.
        private readonly List<(ulong Epoch, ulong SequenceNumber)> _flightRecords = new();

        // KeyUpdate we sent and are waiting to be ACKed before switching write keys.
        private List<(ulong Epoch, ulong SequenceNumber)> _pendingKeyUpdateRecords;
        // A KeyUpdate asked for while one was pending: sent once that one is ACKed (null when none).
        private bool? _queuedKeyUpdateRequest;
        // We sent update_requested and the peer's KeyUpdate has not arrived yet: we must not request another (RFC 9846 §4.7.3).
        private bool _peerKeyUpdateRequested;
        // The largest epoch a KeyUpdate may move to (RFC 9846 §4.7.3).
        private const ulong MaxEpoch = (1UL << 48) - 1;
        private AcknowledgementDatagram _lastAck;
        private ushort _plaintextRecordSequence;

        protected int NextSendMessageSeq { get; set; }
        protected int NextReceiveMessageSeq { get; set; }

        public Dtls13Session Session { get; } = new Dtls13Session();

        public override ushort NegotiatedCipherSuite => Session.CipherSuite?.Id ?? 0;

        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;
        internal event EventHandler<KeyUpdateDatagram> KeyUpdateMessageReceived;

        /// <summary>The CID the peer puts in records it sends us (RFC 9147 §9), or null / empty for none.</summary>
        protected byte[] ReadConnectionId { get; set; }

        /// <summary>The CID we put in records we send (the peer's choice), or null / empty for none.</summary>
        protected byte[] WriteConnectionId { get; set; }

        /// <summary>Our connection ID: the peer sends it in every record from the handshake epoch on. Null when not negotiated.</summary>
        public override byte[] ConnectionId => ReadConnectionId is { Length: > 0 } ? ReadConnectionId : null;

        /// <summary>The peer's connection ID, sent in our records. Null when not negotiated.</summary>
        public override byte[] PeerConnectionId => WriteConnectionId is { Length: > 0 } ? WriteConnectionId : null;

        protected override int ReceiveConnectionIdLength => ReadConnectionId?.Length ?? 0;

        // CID updates (RFC 9147 §9): every CID we issued stays valid for receiving; the peer's spares wait in order.
        private readonly HashSet<string> _issuedReadConnectionIds = new();
        private readonly Queue<byte[]> _spareWriteConnectionIds = new();
        private bool _connectionIdRequestOutstanding;
        private const int MaxConnectionIds = 16;

        /// <summary>Spare CIDs the peer gave us for sending, e.g. when moving to a new path.</summary>
        public override int SpareConnectionIdCount => _spareWriteConnectionIds.Count;

        /// <summary>A CID we issued for receiving (the server registers it for routing).</summary>
        protected virtual void OnConnectionIdIssued(byte[] connectionId) { }

        private bool IsOurConnectionId(byte[] cid)
            => cid != null && (cid.AsSpan().SequenceEqual(ReadConnectionId) || _issuedReadConnectionIds.Contains(Convert.ToHexString(cid)));

        /// <summary>
        /// Asks the peer for <paramref name="count"/> spare CIDs to send with (RFC 9147 §9). Needs a negotiated
        /// non-empty peer CID; only one request may be outstanding.
        /// </summary>
        public override void RequestConnectionIds(byte count) => Locked(() =>
        {
            if (!IsHandshakeComplete || PeerConnectionId == null)
                throw new InvalidOperationException("No connection ID was negotiated for sending.");
            if (_connectionIdRequestOutstanding)
                throw new InvalidOperationException("A RequestConnectionId is still unanswered.");
            _connectionIdRequestOutstanding = true;
            SendPostHandshakeFlight(() => SendHandshake(new RequestConnectionIdDatagram(count), Session.WriteKeys, addToTranscript: false));
        });

        /// <summary>
        /// Gives the peer <paramref name="count"/> new CIDs to send to us with: spares, or with
        /// <paramref name="immediate"/> to be used at once (RFC 9147 §9).
        /// </summary>
        public override void IssueConnectionIds(int count, bool immediate = false) => Locked(() =>
        {
            if (!IsHandshakeComplete || ConnectionId == null)
                throw new InvalidOperationException("No connection ID was negotiated for receiving.");
            SendNewConnectionIds(count, immediate);
        });

        /// <summary>Switches to the next spare CID for sending; false when there is none.</summary>
        public override bool UseSpareConnectionId()
        {
            bool switched = false;
            Locked(() =>
            {
                if (_spareWriteConnectionIds.Count == 0)
                    return;
                WriteConnectionId = _spareWriteConnectionIds.Dequeue();
                switched = true;
            });
            return switched;
        }

        private void SendNewConnectionIds(int count, bool immediate)
        {
            count = Math.Min(count, MaxConnectionIds - _issuedReadConnectionIds.Count);
            if (count <= 0 && immediate)
                throw new InvalidOperationException("Too many connection IDs issued.");
            var cids = new List<byte[]>();
            for (int i = 0; i < Math.Max(count, 0); i++)
            {
                byte[] cid = Dtls13CryptoUtils.GenerateRandom(ReadConnectionId.Length);
                _issuedReadConnectionIds.Add(Convert.ToHexString(cid));
                OnConnectionIdIssued(cid);
                cids.Add(cid);
            }
            byte usage = immediate ? NewConnectionIdDatagram.CidImmediate : NewConnectionIdDatagram.CidSpare;
            SendPostHandshakeFlight(() => SendHandshake(new NewConnectionIdDatagram(cids, usage), Session.WriteKeys, addToTranscript: false));
        }

        // Post-handshake messages that need an ACK go out one flight at a time, so a coarse ACK of one flight
        // cannot end the retransmission of another (RFC 9147 §5.8).
        private readonly Queue<Action> _postHandshakeFlights = new();

        protected void SendPostHandshakeFlight(Action send)
        {
            if (IsRetransmissionArmed)
            {
                _postHandshakeFlights.Enqueue(send);
                return;
            }
            BeginFlight();
            send();
            ArmRetransmission();
        }

        /// <summary>A protected record authenticated and passed the replay window (for peer address updates).</summary>
        protected virtual void OnRecordAuthenticated(ulong epoch, ulong sequenceNumber, bool withConnectionId) { }

        protected Tls13Connection(bool isClient, Action<byte[]> send)
            : this(isClient, send, stream: false)
        {
        }

        /// <param name="stream">TLS 1.3 over a reliable byte stream (RFC 8446) instead of DTLS 1.3 over datagrams.</param>
        protected Tls13Connection(bool isClient, Action<byte[]> send, bool stream)
            : base(isClient, send, stream ? "TLS13" : "DTLS13")
        {
            IsDatagram = !stream;
        }

        /// <summary>DTLS 1.3 over datagrams, or TLS 1.3 over a stream.</summary>
        protected bool IsDatagram { get; }

        protected override bool IsReliableTransport => !IsDatagram;

        /// <summary>The cipher suite with this protocol's key schedule labels ("dtls13" or "tls13 ").</summary>
        protected Dtls13CipherSuite SuiteFor(ushort id) => IsDatagram ? Dtls13CipherSuite.Get(id) : Dtls13CipherSuite.Get(id).ForTls();

        /// <summary>
        /// Sends a KeyUpdate. The new write keys take effect once the peer ACKs it (RFC 9147 §8).
        /// While an earlier KeyUpdate (possibly one answering the peer's) awaits its ACK, this one is sent after it.
        /// </summary>
        public override void SendKeyUpdate(bool requestUpdate = false) => Locked(() =>
        {
            if (!IsHandshakeComplete || IsClosed)
                throw new InvalidOperationException("The handshake has not completed.");
            if (!CanUpdateWriteKeys)
                throw new InvalidOperationException("The write keys have reached the last epoch.");
            QueueKeyUpdate(requestUpdate);
        });

        private void QueueKeyUpdate(bool requestUpdate)
        {
            if (_pendingKeyUpdateRecords != null)
                _queuedKeyUpdateRequest = (_queuedKeyUpdateRequest ?? false) || requestUpdate;
            else
                StartKeyUpdate(requestUpdate);
        }

        // Another KeyUpdate (sent or still awaiting its ACK) must not move the write epoch past MaxEpoch.
        private bool CanUpdateWriteKeys => Session.WriteKeys.Epoch + (_pendingKeyUpdateRecords != null ? 1UL : 0UL) < MaxEpoch;

        protected override void WriteApplicationData(byte[] data)
        {
            // Rekey well before the AEAD's limit on records per key (RFC 9846 §5.5); Protect closes the connection at the limit.
            var keys = Session.WriteKeys;
            ulong used = IsClient ? keys.ClientKeyUseCounter : keys.ServerKeyUseCounter;
            if (used >= keys.Suite.RekeyThreshold && _pendingKeyUpdateRecords == null && _queuedKeyUpdateRequest == null && CanUpdateWriteKeys)
                StartKeyUpdate(requestUpdate: false);
            SendProtected(Session.WriteKeys, new ApplicationDataDatagram(data).ToBytes());
        }

        protected override byte[] ExportKeyingMaterialCore(string label, byte[] context, int length)
        {
            if (Session.ExporterMasterSecret == null)
                throw new InvalidOperationException("The handshake has not completed.");
            return Dtls13CryptoUtils.ExportKeyingMaterial(Session.ExporterMasterSecret, label, context, length, Session.CipherSuite);
        }

        // In TLS 1.3 all alerts except close_notify and user_canceled are fatal (RFC 8446 §6).
        protected override bool IsAlertFatal(byte level, AlertDescription description)
            => level == 2 || description != AlertDescription.UserCanceled;

        // ── Handshake hooks for subclasses ───────────────────────────────────────────────────

        /// <summary>Handles a complete epoch-0 handshake record (ClientHello, ServerHello, HelloRetryRequest).</summary>
        protected abstract void OnPlaintextHandshake(byte[] record);

        /// <summary>Handles the next in-order protected handshake message (12-byte DTLS header + body + content type).</summary>
        protected abstract void OnHandshakeMessage(byte[] message, IHandshakeDatagram parsed);

        /// <summary>Called for a retransmitted epoch-0 handshake record while the handshake is in progress.</summary>
        protected virtual void OnDuplicatePlaintextHandshake(byte[] record) => RetransmitFlight();

        // ── TLS 1.3 stream record layer (RFC 8446 §5) ─────────────────────────────────────────

        private const int MaxTlsCiphertextLength = 16384 + 256;
        private readonly List<byte> _tlsInput = new();
        private readonly List<byte> _tlsHandshake = new();
        private readonly Dictionary<Dtls13CryptoContext, ulong> _tlsReadSequence = new();

        /// <summary>
        /// Stops reading the stream and returns <paramref name="firstRecord"/> (a whole-message plaintext record) with
        /// every byte received after it, re-framed as records: another engine takes the connection over.
        /// </summary>
        protected byte[] DetachTlsInput(byte[] firstRecord)
        {
            InputDetached = true;
            var handshake = new List<byte>(firstRecord.AsSpan(5).ToArray());
            handshake.AddRange(_tlsHandshake);
            _tlsHandshake.Clear();
            var output = new List<byte>();
            for (int offset = 0; offset < handshake.Count; offset += MaxRecordPayload)
            {
                int n = Math.Min(MaxRecordPayload, handshake.Count - offset);
                output.AddRange(new byte[] { 0x16, firstRecord[1], firstRecord[2], (byte)(n >> 8), (byte)n });
                output.AddRange(handshake.GetRange(offset, n));
            }
            output.AddRange(_tlsInput);
            _tlsInput.Clear();
            return output.ToArray();
        }

        /// <summary>
        /// Bytes of records that fail to decrypt to skip while the server waits for the client's handshake records: the
        /// client sent 0-RTT data the server did not accept (RFC 8446 §4.2.10).
        /// </summary>
        protected int SkipUndecryptableBytes { get; set; }

        /// <summary>
        /// TLS read keys that apply instead of the newest ones: a server that accepted 0-RTT reads the client's early
        /// traffic keys until EndOfEarlyData (RFC 8446 §4.5).
        /// </summary>
        protected Dtls13CryptoContext TlsReadKeysOverride { get; set; }

        /// <summary>Processes bytes received from a TLS stream (any amount: partial or several records).</summary>
        public void ProcessStreamData(byte[] data, int offset, int count) => Run(() =>
        {
            if (IsClosed)
                return;
            for (int i = 0; i < count; i++)
                _tlsInput.Add(data[offset + i]);
            while (_tlsInput.Count >= 5 && !IsClosed && !InputDetached)
            {
                int length = (_tlsInput[3] << 8) | _tlsInput[4];
                if (length > MaxTlsCiphertextLength)
                    throw new DtlsException(AlertDescription.RecordOverflow, $"Record of {length} bytes.");
                if (_tlsInput.Count < 5 + length)
                    return;
                byte[] record = _tlsInput.GetRange(0, 5 + length).ToArray();
                _tlsInput.RemoveRange(0, 5 + length);
                ProcessTlsRecord(record);
            }
        });

        /// <summary>The TLS stream ended: after the handshake that closes the connection; during it the handshake fails.</summary>
        internal void OnTransportClosed() => Run(() =>
        {
            if (IsClosed || InputDetached)
                return;
            if (!IsHandshakeComplete)
                throw new System.IO.IOException("The connection closed during the handshake.");
            CloseInternal();
        });

        private void ProcessTlsRecord(byte[] record)
        {
            if (record[1] != 0x03)
                throw new DtlsException(AlertDescription.DecodeError, "Not a TLS record.");
            byte contentType = record[0];
            byte[] fragment = record.AsSpan(5).ToArray();

            // RFC 8446 §5: nothing may come between the parts of a handshake message.
            if (contentType != 0x16 && contentType != 0x17 && _tlsHandshake.Count > 0)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Record interleaved with a fragmented handshake message.");

            var keys = TlsReadKeysOverride ?? (Session.ReadKeys.Count > 0 ? Session.ReadKeys[Session.ReadKeys.Count - 1] : null);
            switch (contentType)
            {
                case 0x14:
                    // Middlebox compatibility (RFC 8446 §5, Appendix D.4): a single 0x01 before the handshake ends, ignored.
                    if (fragment.Length != 1 || fragment[0] != 1 || IsHandshakeComplete)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Unexpected change_cipher_spec.");
                    return;

                case 0x15:
                    if (keys != null)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Unprotected alert after keys were established.");
                    if (fragment.Length != 2)
                        throw new DtlsException(AlertDescription.DecodeError, "Invalid alert.");
                    OnAlertReceived(fragment[0], (AlertDescription)fragment[1]);
                    return;

                case 0x16:
                    if (keys != null)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Unprotected handshake message after keys were established.");
                    if (fragment.Length == 0)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Empty handshake record.");
                    _tlsHandshake.AddRange(fragment);
                    while (!InputDetached && TakeTlsHandshakeMessage() is { } message && !IsClosed)
                    {
                        // Handed over as one record holding the whole message, as the DTLS reassembler does.
                        byte[] whole = new byte[5 + message.Length];
                        whole[0] = 0x16;
                        whole[1] = 0x03;
                        whole[2] = 0x03;
                        whole[3] = (byte)(message.Length >> 8);
                        whole[4] = (byte)message.Length;
                        message.CopyTo(whole, 5);
                        OnPlaintextHandshake(whole);
                    }
                    return;

                case 0x17:
                    ProcessTlsProtectedRecord(keys, record);
                    return;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unknown content type 0x{contentType:X2}.");
            }
        }

        private void ProcessTlsProtectedRecord(Dtls13CryptoContext keys, byte[] record)
        {
            if (keys == null)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Protected record before the keys are known.");
            _tlsReadSequence.TryGetValue(keys, out ulong sequence);
            byte[] inner = Dtls13RecordProtection.UnprotectTls(keys, fromClient: !IsClient, sequence, record);
            if (inner == null)
            {
                if (SkipUndecryptableBytes >= record.Length)
                {
                    SkipUndecryptableBytes -= record.Length; // rejected 0-RTT data
                    return;
                }
                throw new DtlsException(AlertDescription.BadRecordMac, "Record failed authentication.");
            }
            SkipUndecryptableBytes = 0;
            _tlsReadSequence[keys] = sequence + 1;

            byte contentType = inner[^1];
            TlsInspector.Current?.OnProtectedRecord(this, IsClient, false, contentType, keys.Epoch, sequence, inner.AsSpan(0, inner.Length - 1));
            CheckReceivedRecordSize(inner.Length - 1);
            if (contentType != 0x16 && _tlsHandshake.Count > 0)
                throw new DtlsException(AlertDescription.UnexpectedMessage, "Record interleaved with a fragmented handshake message.");

            // Early traffic keys carry 0-RTT application data and then EndOfEarlyData.
            if (keys.Epoch == 1 && contentType == 0x17)
            {
                OnEarlyData(inner.AsSpan(0, inner.Length - 1).ToArray());
                return;
            }
            if (keys.Epoch == 1 && contentType != 0x16)
                throw new DtlsException(AlertDescription.UnexpectedMessage, $"Content type 0x{contentType:X2} under the early traffic keys.");

            switch (contentType)
            {
                case 0x16:
                    if (inner.Length == 1)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Empty handshake record.");
                    _tlsHandshake.AddRange(inner.AsSpan(0, inner.Length - 1).ToArray());
                    while (TakeTlsHandshakeMessage() is { } message && !IsClosed)
                    {
                        // The message classes read the DTLS form: 12-byte header, then the content type.
                        int length = message.Length - 4;
                        byte[] dtlsForm = new byte[12 + length + 1];
                        dtlsForm[0] = message[0];
                        dtlsForm[1] = message[1]; dtlsForm[2] = message[2]; dtlsForm[3] = message[3];
                        dtlsForm[4] = (byte)(NextReceiveMessageSeq >> 8);
                        dtlsForm[5] = (byte)NextReceiveMessageSeq;
                        dtlsForm[9] = message[1]; dtlsForm[10] = message[2]; dtlsForm[11] = message[3];
                        Buffer.BlockCopy(message, 4, dtlsForm, 12, length);
                        dtlsForm[^1] = 0x16;
                        DeliverHandshake(dtlsForm);
                    }
                    break;

                case 0x17:
                    if (!IsHandshakeComplete)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Application data before the handshake completed.");
                    RaiseApplicationData(inner.AsSpan(0, inner.Length - 1).ToArray());
                    break;

                case 0x15:
                    if (inner.Length != 3)
                        throw new DtlsException(AlertDescription.DecodeError, "Invalid alert");
                    OnAlertReceived(inner[0], (AlertDescription)inner[1]);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected content type 0x{contentType:X2}");
            }
        }

        /// <summary>The next complete handshake message (4-byte TLS header + body) from the buffer, or null.</summary>
        private byte[] TakeTlsHandshakeMessage()
        {
            if (_tlsHandshake.Count < 4)
                return null;
            int length = (_tlsHandshake[1] << 16) | (_tlsHandshake[2] << 8) | _tlsHandshake[3];
            if (length > HandshakeReassembler.MaxMessageLength)
                throw new DtlsException(AlertDescription.HandshakeFailure, $"Handshake message of {length} bytes.");
            if (_tlsHandshake.Count < 4 + length)
                return null;
            byte[] message = _tlsHandshake.GetRange(0, 4 + length).ToArray();
            _tlsHandshake.RemoveRange(0, 4 + length);
            return message;
        }

        // ── Record layer ─────────────────────────────────────────────────────────────────────

        protected override void ProcessRecord(byte[] record)
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
                        OnAlertReceived(record[13], (AlertDescription)record[14]);
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

            var unprotected = Dtls13RecordProtection.Unprotect(keys, fromClient: !IsClient, record, ReceiveConnectionIdLength);

            // With a CID negotiated it is in every record from the handshake epoch on, and must be ours (RFC 9147 §9).
            if (ReadConnectionId is { Length: > 0 } && keys.Epoch >= 2 && !IsOurConnectionId(unprotected.ConnectionId))
                throw new DtlsRecordDiscardedException("Record without our connection ID");
            OnRecordAuthenticated(keys.Epoch, unprotected.SequenceNumber, unprotected.ConnectionId != null);
            byte[] inner = unprotected.InnerPlaintext;
            byte contentType = inner[inner.Length - 1];
            TlsInspector.Current?.OnProtectedRecord(this, IsClient, false, contentType, keys.Epoch, unprotected.SequenceNumber, inner.AsSpan(0, inner.Length - 1));
            if (keys.Epoch >= 2)
                CheckReceivedRecordSize(inner.Length - 1);

            // Epoch 1 carries only 0-RTT application data; DTLS 1.3 has no EndOfEarlyData (RFC 9147 §5.6).
            if (keys.Epoch == 1)
            {
                if (IsClient || contentType != 0x17)
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Content type 0x{contentType:X2} in the early data epoch.");
                OnEarlyData(inner.AsSpan(0, inner.Length - 1).ToArray());
                return;
            }

            switch (contentType)
            {
                case 0x16:
                    _receivedHandshakeRecords.Add((keys.Epoch, unprotected.SequenceNumber));
                    ProcessHandshakeRecord(inner);
                    break;

                case 0x17:
                    if (keys.Epoch < 3)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Application data in handshake epoch");
                    if (!IsHandshakeComplete)
                        throw new DtlsRecordDiscardedException("Application data before handshake completion");
                    RaiseApplicationData(inner.AsSpan(0, inner.Length - 1).ToArray());
                    break;

                case 0x15:
                    if (inner.Length != 3)
                        throw new DtlsException(AlertDescription.DecodeError, "Invalid alert");
                    OnAlertReceived(inner[0], (AlertDescription)inner[1]);
                    break;

                case 0x1a:
                    var ack = new AcknowledgementDatagram();
                    ack.FromBytes(inner);
                    OnAck(ack);
                    break;

                default:
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected content type 0x{contentType:X2}");
            }
        }

        private void ProcessHandshakeRecord(byte[] inner)
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
                    OnDuplicateHandshake();
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
            if (TlsInspector.Current is { } inspector)
                TlsInspector.Received(inspector, this, IsClient, message, 0, 12, IsDatagram);

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
                EndOfEarlyDataDatagram.HandshakeType => new EndOfEarlyDataDatagram(),
                RequestConnectionIdDatagram.HandshakeType => new RequestConnectionIdDatagram(),
                NewConnectionIdDatagram.HandshakeType => new NewConnectionIdDatagram(),
                0x08 => new EncryptedExtensionsDatagram(),
                0x0b => new CertificateDatagram(),
                CompressedCertificateDatagram.HandshakeType => new CompressedCertificateDatagram(),
                0x0d => new CertificateRequestDatagram(),
                0x0f => new CertificateVerifyDatagram(),
                0x14 => new FinishedDatagram(),
                0x18 => new KeyUpdateDatagram(),
                _ => throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected handshake message type 0x{message[0]:X2}")
            };
            datagram.FromBytes(message);
            return datagram;
        }

        private void OnDuplicateHandshake()
        {
            // The peer retransmitted a flight we already processed, so our response was probably lost:
            // resend our outstanding flight, or the ACK that completed the peer's flight.
            if (IsRetransmissionArmed)
                RetransmitFlight();
            else if (_lastAck != null && Session.WriteKeys != null)
                SendAckRecords(_lastAck);
        }

        // ── Post-handshake messages ──────────────────────────────────────────────────────────

        /// <summary>0-RTT application data arrived in epoch 1 (server only; the keys exist only once early data is accepted).</summary>
        protected virtual void OnEarlyData(byte[] data) { }

        /// <summary>A NewSessionTicket arrived (client only), before NewSessionTicketReceived is raised.</summary>
        protected virtual void OnNewSessionTicket(NewSessionTicketDatagram ticket) { }

        private void OnPostHandshakeMessage(byte[] message, IHandshakeDatagram parsed)
        {
            switch (parsed)
            {
                case NewSessionTicketDatagram nst when IsClient:
                    SendAck();
                    OnNewSessionTicket(nst);
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

                    RaiseEvent(() => KeyUpdateMessageReceived?.Invoke(this, keyUpdate));
                    RaiseKeyUpdateReceived();
                    _peerKeyUpdateRequested = false;
                    // A sender at the last epoch SHOULD ignore update_requested (RFC 9846 §4.7.3).
                    if (keyUpdate.UpdateRequest == 1 && _pendingKeyUpdateRecords == null && CanUpdateWriteKeys)
                        StartKeyUpdate(requestUpdate: false);
                    break;

                // RFC 9147 §9: both need negotiated CIDs; a violation is unexpected_message.
                case NewConnectionIdDatagram newIds:
                    if (PeerConnectionId == null)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "NewConnectionId without a negotiated connection ID.");
                    SendAck();
                    if (newIds.Usage == NewConnectionIdDatagram.CidImmediate)
                    {
                        if (newIds.ConnectionIds.Count == 0)
                            throw new DtlsException(AlertDescription.IllegalParameter, "cid_immediate without connection IDs.");
                        WriteConnectionId = newIds.ConnectionIds[0];
                        _spareWriteConnectionIds.Clear();
                        foreach (byte[] cid in newIds.ConnectionIds.Skip(1))
                            _spareWriteConnectionIds.Enqueue(cid);
                    }
                    else
                    {
                        foreach (byte[] cid in newIds.ConnectionIds.Where(c => c.Length > 0))
                            if (_spareWriteConnectionIds.Count < MaxConnectionIds)
                                _spareWriteConnectionIds.Enqueue(cid);
                    }
                    _connectionIdRequestOutstanding = false;
                    break;

                case RequestConnectionIdDatagram request:
                    if (ConnectionId == null)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "RequestConnectionId without a negotiated connection ID.");
                    SendAck();
                    // Excessive requests get fewer CIDs, possibly none (RFC 9147 §9).
                    SendNewConnectionIds(request.Count, immediate: false);
                    break;

                default:
                    if (!OnPostHandshakeAuthMessage(message, parsed))
                        throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected post-handshake message 0x{message[0]:X2}");
                    break;
            }
        }

        /// <summary>Post-handshake authentication messages (RFC 8446 §4.6.2); false when not expected.</summary>
        protected virtual bool OnPostHandshakeAuthMessage(byte[] message, IHandshakeDatagram parsed) => false;

        private void StartKeyUpdate(bool requestUpdate)
        {
            // Until the peer's KeyUpdate arrives, a second update_requested would ask for nothing new (RFC 9846 §4.7.3).
            requestUpdate &= !_peerKeyUpdateRequested;
            _peerKeyUpdateRequested |= requestUpdate;
            var keyUpdate = new KeyUpdateDatagram(requestUpdate ? (byte)0x01 : (byte)0x00);
            keyUpdate.SequenceNumber = NextSendMessageSeq++;
            if (!IsDatagram)
            {
                // TLS: the new keys apply from the next record on (RFC 8446 §4.6.3).
                byte[] dtlsForm = keyUpdate.ToBytes();
                SendProtected(Session.WriteKeys, new byte[] { dtlsForm[0], dtlsForm[1], dtlsForm[2], dtlsForm[3], dtlsForm[12], 0x16 });
                Session.WriteKeys = IsClient
                    ? Dtls13CryptoUtils.UpdateClientTrafficSecret(Session.WriteKeys)
                    : Dtls13CryptoUtils.UpdateServerTrafficSecret(Session.WriteKeys);
                return;
            }
            _pendingKeyUpdateRecords = new List<(ulong, ulong)> { SendProtected(Session.WriteKeys, keyUpdate.ToBytes()) };
        }

        private void OnAck(AcknowledgementDatagram ack)
        {
            // Any ACK for our last flight completes it; partial ACKs are treated as complete, as
            // flights are always retransmitted in full.
            if (HasFlight && ack.Records.Any(r => _flightRecords.Contains(r)))
            {
                StopRetransmission();
                if (IsHandshakeComplete && _postHandshakeFlights.Count > 0)
                {
                    BeginFlight();
                    _postHandshakeFlights.Dequeue()();
                    ArmRetransmission();
                }
            }

            if (_pendingKeyUpdateRecords != null && ack.Records.Any(r => _pendingKeyUpdateRecords.Contains(r)))
            {
                _pendingKeyUpdateRecords = null;
                Session.WriteKeys = IsClient
                    ? Dtls13CryptoUtils.UpdateClientTrafficSecret(Session.WriteKeys)
                    : Dtls13CryptoUtils.UpdateServerTrafficSecret(Session.WriteKeys);
                Debug.WriteLine($"{LogPrefix} KeyUpdate acknowledged, now writing epoch {Session.WriteKeys.Epoch}");
                if (_queuedKeyUpdateRequest is bool requestUpdate)
                {
                    _queuedKeyUpdateRequest = null;
                    StartKeyUpdate(requestUpdate);
                }
            }
        }

        // ── Sending ──────────────────────────────────────────────────────────────────────────

        protected override void OnFlightStarted() => _flightRecords.Clear();

        /// <summary>Sends an epoch-0 handshake message (ClientHello/ServerHello) as part of the current flight.</summary>
        protected byte[] SendPlaintextHandshake(ServerHelloDatagram serverHello)
        {
            serverHello.SequenceNumber = NextSendMessageSeq++;
            return SendPlaintextRecord(InspectSending(serverHello.ToBytes()));
        }

        protected byte[] SendPlaintextHandshake(ClientHelloDatagram clientHello)
        {
            clientHello.SequenceNumber = NextSendMessageSeq++;
            return SendPlaintextRecord(InspectSending(clientHello.ToBytes()));
        }

        // ── Inspection (TlsInspector.Current; nothing happens without one) ───────────────────

        /// <summary>A whole-message plaintext handshake record, as the inspector may have replaced it.</summary>
        private byte[] InspectSending(byte[] record)
        {
            if (TlsInspector.Current is not { } inspector)
                return record;
            byte[] sent = TlsInspector.Sending(inspector, this, IsClient, record, IsDatagram ? 13 : 5, IsDatagram ? 12 : 4);
            if (!ReferenceEquals(sent, record))
            {
                try
                {
                    OnSentHelloEdited(sent);
                }
                catch (Exception ex) when (ex is System.IO.InvalidDataException or ArgumentException or IndexOutOfRangeException or DtlsException)
                {
                    // Not decodable: the engine keeps its own values; only the peer sees the change.
                }
            }
            return sent;
        }

        /// <summary>
        /// The inspector replaced our ClientHello or ServerHello (a whole-message record): adopt from it what this engine
        /// chose and can follow (see <see cref="TlsInspector.OnHandshakeSending"/>).
        /// </summary>
        protected virtual void OnSentHelloEdited(byte[] record) { }

        /// <summary>Reports a received whole-message plaintext handshake record (ClientHello, ServerHello, HelloRetryRequest).</summary>
        protected void InspectReceivedRecord(byte[] record)
        {
            if (TlsInspector.Current is { } inspector)
                TlsInspector.Received(inspector, this, IsClient, record, IsDatagram ? 13 : 5, IsDatagram ? 12 : 4);
        }

        /// <summary>Reports a secret to the inspector, if there is one.</summary>
        protected void InspectSecret(string name, byte[] value)
        {
            if (value != null)
                TlsInspector.Current?.OnSecret(this, IsClient, name, value);
        }

        /// <summary>Reports the traffic secrets and keys of the handshake (epoch 2) or first application (epoch 3) keys.</summary>
        protected void InspectKeys(Dtls13CryptoContext keys)
        {
            var inspector = TlsInspector.Current;
            if (inspector == null)
                return;
            bool handshake = keys.Epoch == 2;
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.HandshakeSecret : TlsInspector.MasterSecret, keys.Secret);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ClientHandshakeTrafficSecret : TlsInspector.ClientApplicationTrafficSecret, keys.ClientSecret);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ServerHandshakeTrafficSecret : TlsInspector.ServerApplicationTrafficSecret, keys.ServerSecret);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ClientHandshakeKey : TlsInspector.ClientApplicationKey, keys.ClientKey);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ClientHandshakeIv : TlsInspector.ClientApplicationIv, keys.ClientIv);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ServerHandshakeKey : TlsInspector.ServerApplicationKey, keys.ServerKey);
            inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ServerHandshakeIv : TlsInspector.ServerApplicationIv, keys.ServerIv);
            if (IsDatagram)
            {
                inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ClientHandshakeSnKey : TlsInspector.ClientApplicationSnKey, keys.ClientSnKey);
                inspector.OnSecret(this, IsClient, handshake ? TlsInspector.ServerHandshakeSnKey : TlsInspector.ServerApplicationSnKey, keys.ServerSnKey);
            }
        }

        /// <summary>Epoch-0 record sequence numbers continue from here (a stateless server starts after the HelloRetryRequest).</summary>
        protected void SetPlaintextRecordSequence(int next) => _plaintextRecordSequence = (ushort)next;

        /// <summary>The next epoch-0 record sequence number.</summary>
        protected int PlaintextRecordSequence => _plaintextRecordSequence;

        private byte[] SendPlaintextRecord(byte[] record)
        {
            if (!IsDatagram)
            {
                // A TLS ClientHello/ServerHello/HelloRetryRequest already is a record; nothing is retransmitted.
                SendInFlight(() => new[] { record });
                return record;
            }
            SendInFlight(() =>
            {
                int seq = _plaintextRecordSequence;
                var fragments = HandshakeFragmenter.FragmentUnencryptedRecord((byte[])record.Clone(), Math.Min(1200, 13 + PeerRecordLimit), ref seq);
                _plaintextRecordSequence = (ushort)seq;
                return fragments;
            });
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
            if (TlsInspector.Current is { } inspector)
                plaintext = TlsInspector.Sending(inspector, this, IsClient, plaintext, 0, 12, trailer: 1, datagram: IsDatagram);
            if (addToTranscript)
                Session.Transcript.AddHandshake(plaintext);

            if (!IsDatagram)
            {
                // TLS form (4-byte header), in records of at most the peer's limit.
                int length = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
                byte[] tlsMessage = new byte[4 + length];
                Buffer.BlockCopy(plaintext, 0, tlsMessage, 0, 4);
                Buffer.BlockCopy(plaintext, 12, tlsMessage, 4, length);
                SendInFlight(() =>
                {
                    var records = new List<byte[]>();
                    int chunk = Math.Min(MaxRecordPayload, PeerRecordLimit);
                    for (int offset = 0; offset < tlsMessage.Length; offset += chunk)
                    {
                        int n = Math.Min(chunk, tlsMessage.Length - offset);
                        byte[] inner = new byte[n + 1];
                        Buffer.BlockCopy(tlsMessage, offset, inner, 0, n);
                        inner[^1] = 0x16;
                        records.Add(Protect(keys, inner).Record);
                    }
                    return records;
                });
                return plaintext;
            }

            SendInFlight(() =>
            {
                var datagrams = new List<byte[]>();
                foreach (var fragment in HandshakeFragmenter.FragmentHandshakePlaintext(plaintext, Math.Min(MaxHandshakeBodyPerRecord, PeerRecordLimit - 12)))
                {
                    var (record, number) = Protect(keys, fragment);
                    _flightRecords.Add(number);
                    datagrams.Add(record);
                }
                return datagrams;
            });
            return plaintext;
        }

        private (byte[] Record, (ulong Epoch, ulong SequenceNumber) Number) Protect(Dtls13CryptoContext keys, byte[] innerPlaintext)
        {
            ulong seq = IsClient ? keys.ClientKeyUseCounter++ : keys.ServerKeyUseCounter++;
            if (seq >= keys.Suite.RecordLimit)
                throw new DtlsException(AlertDescription.InternalError, "The key has protected as many records as its AEAD allows; a KeyUpdate is required");
            TlsInspector.Current?.OnProtectedRecord(this, IsClient, true, innerPlaintext[^1], keys.Epoch, seq, innerPlaintext.AsSpan(0, innerPlaintext.Length - 1));

            if (!IsDatagram)
                return (Dtls13RecordProtection.ProtectTls(keys, IsClient, seq, innerPlaintext), (keys.Epoch, seq));
            byte[] cid = keys.Epoch >= 2 && WriteConnectionId is { Length: > 0 } ? WriteConnectionId : null;
            return (Dtls13RecordProtection.Protect(keys, IsClient, (int)keys.Epoch, seq, innerPlaintext, cid), (keys.Epoch, seq));
        }

        /// <summary>Protects and queues one record outside any flight. Returns its record number.</summary>
        protected (ulong Epoch, ulong SequenceNumber) SendProtected(Dtls13CryptoContext keys, byte[] innerPlaintext)
        {
            var (record, number) = Protect(keys, innerPlaintext);
            Enqueue(record);
            return number;
        }

        /// <summary>ACKs the handshake records received since the last ACK.</summary>
        protected void SendAck()
        {
            if (_receivedHandshakeRecords.Count == 0 || Session.WriteKeys == null || !IsDatagram)
                return;

            _lastAck = new AcknowledgementDatagram(_receivedHandshakeRecords);
            _receivedHandshakeRecords.Clear();
            SendAckRecords(_lastAck);
        }

        // An ACK lists 16 bytes per record; under a small record size limit it takes several records.
        private void SendAckRecords(AcknowledgementDatagram ack)
        {
            int perRecord = Math.Max(1, (PeerRecordLimit - 2) / 16);
            for (int i = 0; i < ack.Records.Count; i += perRecord)
                SendProtected(Session.WriteKeys, new AcknowledgementDatagram(ack.Records.Skip(i).Take(perRecord)).ToBytes());
        }

        protected void ClearReceivedHandshakeRecords() => _receivedHandshakeRecords.Clear();

        protected void AddReadKeys(Dtls13CryptoContext keys)
        {
            Session.ReadKeys.Add(keys);
            // Keep the handshake epoch (for retransmitted handshake records) and the two newest application epochs.
            while (Session.ReadKeys.Count > 3)
                Session.ReadKeys.RemoveAt(Session.ReadKeys[0].Epoch == 2 ? 1 : 0);
        }

        // ── Alerts ───────────────────────────────────────────────────────────────────────────

        protected override void SendAlert(AlertDescription description, bool fatal)
        {
            byte level = fatal ? (byte)2 : (byte)1;
            if (Session.WriteKeys != null)
            {
                SendProtected(Session.WriteKeys, new byte[] { level, (byte)description, 0x15 });
            }
            else if (!IsDatagram)
            {
                Enqueue(new byte[] { 0x15, 0x03, 0x03, 0, 2, level, (byte)description });
            }
            else
            {
                long seq = _plaintextRecordSequence++;
                byte[] record = { 0x15, 0xFE, 0xFD, 0, 0, (byte)(seq >> 40), (byte)(seq >> 32), (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq, 0, 2, level, (byte)description };
                Enqueue(record);
            }
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
    }
}
