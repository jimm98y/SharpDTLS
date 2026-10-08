using SharpDTLS.DTLS13.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// Per-association DTLS 1.3 machinery shared by client and server: record layer, handshake
    /// message ordering and reassembly, ACKs (RFC 9147 §7) and KeyUpdate (§8).
    /// Subclasses implement the handshake state machine.
    /// </summary>
    public abstract class Dtls13Connection : DtlsConnectionBase
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
        private AcknowledgementDatagram _lastAck;
        private ushort _plaintextRecordSequence;

        protected int NextSendMessageSeq { get; set; }
        protected int NextReceiveMessageSeq { get; set; }

        public Dtls13Session Session { get; } = new Dtls13Session();

        public event EventHandler<NewSessionTicketDatagram> NewSessionTicketReceived;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;

        /// <summary>The CID the peer puts in records it sends us (RFC 9147 §9), or null / empty for none.</summary>
        protected byte[] ReadConnectionId { get; set; }

        /// <summary>The CID we put in records we send (the peer's choice), or null / empty for none.</summary>
        protected byte[] WriteConnectionId { get; set; }

        /// <summary>Our connection ID: the peer sends it in every record from the handshake epoch on. Null when not negotiated.</summary>
        public byte[] ConnectionId => ReadConnectionId is { Length: > 0 } ? ReadConnectionId : null;

        /// <summary>The peer's connection ID, sent in our records. Null when not negotiated.</summary>
        public byte[] PeerConnectionId => WriteConnectionId is { Length: > 0 } ? WriteConnectionId : null;

        protected override int ReceiveConnectionIdLength => ReadConnectionId?.Length ?? 0;

        // CID updates (RFC 9147 §9): every CID we issued stays valid for receiving; the peer's spares wait in order.
        private readonly HashSet<string> _issuedReadConnectionIds = new();
        private readonly Queue<byte[]> _spareWriteConnectionIds = new();
        private bool _connectionIdRequestOutstanding;
        private const int MaxConnectionIds = 16;

        /// <summary>Spare CIDs the peer gave us for sending, e.g. when moving to a new path.</summary>
        public int SpareConnectionIdCount => _spareWriteConnectionIds.Count;

        /// <summary>A CID we issued for receiving (the server registers it for routing).</summary>
        protected virtual void OnConnectionIdIssued(byte[] connectionId) { }

        private bool IsOurConnectionId(byte[] cid)
            => cid != null && (cid.AsSpan().SequenceEqual(ReadConnectionId) || _issuedReadConnectionIds.Contains(Convert.ToHexString(cid)));

        /// <summary>
        /// Asks the peer for <paramref name="count"/> spare CIDs to send with (RFC 9147 §9). Needs a negotiated
        /// non-empty peer CID; only one request may be outstanding.
        /// </summary>
        public void RequestConnectionIds(byte count) => Locked(() =>
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
        public void IssueConnectionIds(int count, bool immediate = false) => Locked(() =>
        {
            if (!IsHandshakeComplete || ConnectionId == null)
                throw new InvalidOperationException("No connection ID was negotiated for receiving.");
            SendNewConnectionIds(count, immediate);
        });

        /// <summary>Switches to the next spare CID for sending; false when there is none.</summary>
        public bool UseSpareConnectionId()
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

        protected Dtls13Connection(bool isClient, Action<byte[]> send)
            : base(isClient, send, "DTLS13")
        {
        }

        /// <summary>
        /// Sends a KeyUpdate. The new write keys take effect once the peer ACKs it (RFC 9147 §8).
        /// </summary>
        public void SendKeyUpdate(bool requestUpdate = false) => Locked(() =>
        {
            if (!IsHandshakeComplete || IsClosed)
                throw new InvalidOperationException("The handshake has not completed.");
            if (_pendingKeyUpdateRecords != null)
                throw new InvalidOperationException("A KeyUpdate is already in progress.");
            StartKeyUpdate(requestUpdate);
        });

        protected override void WriteApplicationData(byte[] data)
            => SendProtected(Session.WriteKeys, new ApplicationDataDatagram(data).ToBytes());

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
                RequestConnectionIdDatagram.HandshakeType => new RequestConnectionIdDatagram(),
                NewConnectionIdDatagram.HandshakeType => new NewConnectionIdDatagram(),
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

        private void OnDuplicateHandshake()
        {
            // The peer retransmitted a flight we already processed, so our response was probably lost:
            // resend our outstanding flight, or the ACK that completed the peer's flight.
            if (IsRetransmissionArmed)
                RetransmitFlight();
            else if (_lastAck != null && Session.WriteKeys != null)
                SendProtected(Session.WriteKeys, _lastAck.ToBytes());
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

                    RaiseEvent(() => KeyUpdateReceived?.Invoke(this, keyUpdate));
                    if (keyUpdate.UpdateRequest == 1 && _pendingKeyUpdateRecords == null)
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
                    throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unexpected post-handshake message 0x{message[0]:X2}");
            }
        }

        private void StartKeyUpdate(bool requestUpdate)
        {
            var keyUpdate = new KeyUpdateDatagram(requestUpdate ? (byte)0x01 : (byte)0x00);
            keyUpdate.SequenceNumber = NextSendMessageSeq++;
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
            }
        }

        // ── Sending ──────────────────────────────────────────────────────────────────────────

        protected override void OnFlightStarted() => _flightRecords.Clear();

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
            SendInFlight(() =>
            {
                int seq = _plaintextRecordSequence;
                var fragments = HandshakeFragmenter.FragmentUnencryptedRecord((byte[])record.Clone(), 1200, ref seq);
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
            if (addToTranscript)
                Session.Transcript.AddHandshake(plaintext);

            SendInFlight(() =>
            {
                var datagrams = new List<byte[]>();
                foreach (var fragment in HandshakeFragmenter.FragmentHandshakePlaintext(plaintext, MaxHandshakeBodyPerRecord))
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
            if (seq >= (1UL << 48) - 1)
                throw new DtlsException(AlertDescription.InternalError, "Record sequence number space exhausted; a KeyUpdate is required");

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

        // ── Alerts ───────────────────────────────────────────────────────────────────────────

        protected override void SendAlert(AlertDescription description, bool fatal)
        {
            byte level = fatal ? (byte)2 : (byte)1;
            if (Session.WriteKeys != null)
            {
                SendProtected(Session.WriteKeys, new byte[] { level, (byte)description, 0x15 });
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
