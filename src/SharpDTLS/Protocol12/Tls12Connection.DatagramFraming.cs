using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SharpDTLS.Protocol12
{
    internal abstract partial class Tls12Connection
    {
        /// <summary>
        /// DTLS framing (RFC 6347): explicit epochs and sequence numbers with replay windows, records of the next
        /// epoch buffered until its ChangeCipherSpec, tls12_cid records (RFC 9146), and handshake messages with
        /// message_seq, fragmented to fit datagrams and reassembled and reordered on receipt.
        /// </summary>
        private sealed class DatagramFraming : Framing
        {
            /// <summary>Target maximum datagram size; handshake messages are fragmented to fit.</summary>
            private const int MaxDatagramSize = 1200;
            private const int MaxHandshakeFragment = MaxDatagramSize - 13 - 12 - 64; // record + handshake headers + cipher overhead
            private const int MaxBufferedMessages = 16;
            private const int MaxFutureEpochRecords = 16;
            private const byte Tls12Cid = 25;

            // write state: one cipher and sequence number space per epoch (epoch 0 is unprotected)
            private ushort _writeEpoch;
            private readonly Dictionary<ushort, IRecordCipher> _writeCiphers = new() { [0] = null };
            private readonly Dictionary<ushort, ulong> _writeSequence = new() { [0] = 0 };
            private IRecordCipher _pendingWriteCipher;

            // read state
            private ushort _readEpoch;
            private readonly Dictionary<ushort, IRecordCipher> _readCiphers = new() { [0] = null };
            private readonly Dictionary<ushort, RecordWindow> _readWindows = new() { [0] = new RecordWindow() };
            private IRecordCipher _pendingReadCipher;
            private bool _changeCipherSpecPending;
            private readonly List<byte[]> _futureEpochRecords = new();

            // handshake transport
            private readonly HandshakeReassembler _reassembler = new();
            private readonly SortedDictionary<int, (byte[] Message, ushort Epoch)> _bufferedMessages = new();
            private DateTime _lastDuplicateResponse = DateTime.MinValue;

            public DatagramFraming(Tls12Connection connection) : base(connection) { }

            public override bool IsDatagram => true;

            // RFC 6347 §4.1: DTLS 1.0 in record headers until a version is negotiated.
            public override ushort InitialRecordVersion => DtlsVersion.Dtls10;

            public override bool IsReadProtected => _readEpoch > 0;

            // A tls12_cid record's DTLSInnerPlaintext has the content type in it as well.
            public override int RecordOverhead => C.WriteConnectionId is { Length: > 0 } ? 1 : 0;

            public override byte[] TranscriptContribution(byte[] message) => DtlsHandshakeHash.Contribution(message, 0);

            public override void SetInitialRecordSequence(ulong next) => _writeSequence[0] = next;

            public override void SetPendingCiphers(IRecordCipher read, IRecordCipher write)
            {
                _pendingReadCipher = read;
                _pendingWriteCipher = write;
            }

            // ── Receiving ────────────────────────────────────────────────────────────────────

            public override void ProcessRecord(byte[] record)
            {
                if (record.Length < 13 || record[1] != 0xFE)
                    throw new DtlsRecordDiscardedException("Not a DTLS 1.0/1.2 record");

                byte contentType = record[0];
                ushort recordVersion = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(1));
                ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(3));
                ulong sequenceNumber = 0;
                for (int i = 5; i < 11; i++)
                    sequenceNumber = (sequenceNumber << 8) | record[i];

                // RFC 9146 §3: with a CID negotiated for this direction, encrypted records carry it in tls12_cid records;
                // any other encrypted record is invalid. Plaintext records never carry one.
                byte[] connectionId = null;
                int headerLength = 13;
                byte[] readCid = C.ReadConnectionId;
                bool expectCid = readCid is { Length: > 0 };
                if (contentType == Tls12Cid)
                {
                    if (!expectCid || epoch == 0 || record.Length < 13 + readCid.Length)
                        throw new DtlsRecordDiscardedException("Unexpected tls12_cid record");
                    connectionId = record.AsSpan(11, readCid.Length).ToArray();
                    if (!connectionId.AsSpan().SequenceEqual(readCid))
                        throw new DtlsRecordDiscardedException("Record for another connection ID");
                    headerLength += connectionId.Length;
                }
                else if (expectCid && epoch > 0)
                {
                    throw new DtlsRecordDiscardedException("Encrypted record without the connection ID");
                }
                byte[] fragment = record.AsSpan(headerLength).ToArray();

                if (epoch > _readEpoch)
                {
                    // The next epoch's records can overtake the ChangeCipherSpec; keep a few until it arrives.
                    if (epoch == _readEpoch + 1 && _futureEpochRecords.Count < MaxFutureEpochRecords)
                        _futureEpochRecords.Add(record);
                    return;
                }

                if (epoch < _readEpoch && contentType != 0x16)
                    throw new DtlsRecordDiscardedException($"Record from old epoch {epoch}");

                var window = _readWindows[epoch];
                if (window.IsDuplicate(sequenceNumber))
                    throw new DtlsRecordDiscardedException($"Replayed record {epoch}:{sequenceNumber}");

                var cipher = _readCiphers[epoch];
                if (connectionId != null && cipher == null)
                    throw new DtlsRecordDiscardedException("tls12_cid record without keys");
                byte[] plaintext = cipher == null ? fragment : cipher.Decrypt(contentType, recordVersion, epoch, sequenceNumber, fragment, connectionId);
                window.Mark(sequenceNumber);

                if (connectionId != null)
                {
                    // DTLSInnerPlaintext: content || real_type || zeros
                    int end = plaintext.Length;
                    while (end > 0 && plaintext[end - 1] == 0)
                        end--;
                    if (end == 0)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "tls12_cid record without a content type.");
                    contentType = plaintext[end - 1];
                    plaintext = plaintext.AsSpan(0, end - 1).ToArray();
                }
                if (cipher != null)
                {
                    C.CheckReceivedRecordSize(plaintext.Length);
                    C.OnRecordAuthenticated(epoch, sequenceNumber, connectionId != null);
                }

                switch (contentType)
                {
                    case 0x14:
                        if (plaintext.Length != 1 || plaintext[0] != 1)
                            throw new DtlsException(AlertDescription.DecodeError, "Invalid ChangeCipherSpec.");
                        if (epoch == _readEpoch)
                            OnChangeCipherSpec();
                        break;

                    case 0x15:
                        if (plaintext.Length != 2)
                            throw new DtlsException(AlertDescription.DecodeError, "Invalid alert.");
                        if (epoch == 0 && _readEpoch > 0)
                            throw new DtlsRecordDiscardedException("Unprotected alert after keys were established");
                        C.OnAlertReceived(plaintext[0], (AlertDescription)plaintext[1]);
                        break;

                    case 0x16:
                        ProcessHandshakeFragments(plaintext, epoch);
                        break;

                    case 0x17:
                        if (epoch == 0)
                            throw new DtlsException(AlertDescription.UnexpectedMessage, "Unprotected application data.");
                        if (!C.IsHandshakeComplete)
                            throw new DtlsRecordDiscardedException("Application data before handshake completion");
                        C.RaiseApplicationData(plaintext);
                        break;

                    default:
                        throw new DtlsRecordDiscardedException($"Unknown content type 0x{contentType:X2}");
                }
            }

            private void OnChangeCipherSpec()
            {
                if (_pendingReadCipher == null)
                {
                    // The ChangeCipherSpec overtook the handshake message that establishes the keys.
                    if (C.IsHandshakeComplete)
                        throw new DtlsRecordDiscardedException("Duplicate ChangeCipherSpec");
                    _changeCipherSpecPending = true;
                    return;
                }

                _readEpoch++;
                _readCiphers[_readEpoch] = _pendingReadCipher;
                _readWindows[_readEpoch] = new RecordWindow();
                _pendingReadCipher = null;
                _changeCipherSpecPending = false;
                C.OnChangeCipherSpecReceived();

                var buffered = _futureEpochRecords.ToList();
                _futureEpochRecords.Clear();
                foreach (var record in buffered)
                {
                    try { ProcessRecord(record); }
                    catch (DtlsRecordDiscardedException ex) { Debug.WriteLine($"{C.LogPrefix} Discarded buffered record: {ex.Message}"); }
                    if (C.IsClosed) return;
                }
            }

            private void ProcessHandshakeFragments(byte[] plaintext, ushort epoch)
            {
                var r = new TlsReader(plaintext);
                while (!r.IsEmpty)
                {
                    int start = r.Position;
                    r.ReadUInt8();                  // msg_type
                    int length = r.ReadUInt24();
                    int messageSeq = r.ReadUInt16();
                    r.ReadUInt24();                 // fragment_offset
                    int fragmentLength = r.ReadUInt24();
                    r.ReadBytes(fragmentLength);

                    if (messageSeq < C.NextReceiveMessageSeq)
                    {
                        OnDuplicateHandshake();
                        continue;
                    }

                    // HandshakeReassembler takes the DTLS 1.3-style layout with a trailing content type.
                    byte[] fragment = new byte[12 + fragmentLength + 1];
                    Buffer.BlockCopy(plaintext, start, fragment, 0, 12 + fragmentLength);
                    fragment[^1] = 0x16;
                    if (!_reassembler.TryAddFragment(fragment, out byte[] complete))
                        continue;

                    byte[] message = complete.AsSpan(0, complete.Length - 1).ToArray();
                    if (messageSeq > C.NextReceiveMessageSeq)
                    {
                        if (_bufferedMessages.Count < MaxBufferedMessages)
                            _bufferedMessages[messageSeq] = (message, epoch);
                        continue;
                    }

                    Deliver(message, epoch);
                    while (!C.IsClosed && _bufferedMessages.TryGetValue(C.NextReceiveMessageSeq, out var next))
                    {
                        _bufferedMessages.Remove(C.NextReceiveMessageSeq);
                        Deliver(next.Message, next.Epoch);
                    }
                    if (C.IsClosed)
                        return;
                }
            }

            private void Deliver(byte[] message, ushort epoch)
            {
                C.NextReceiveMessageSeq++;
                byte[] body = message.AsSpan(12).ToArray();
                C.OnHandshakeMessage(message[0], body, message, epoch);

                // A ChangeCipherSpec that overtook the key exchange takes effect only once the handler that
                // derived the keys has finished updating its state.
                if (_changeCipherSpecPending && _pendingReadCipher != null && !C.IsClosed)
                    OnChangeCipherSpec();
            }

            private void OnDuplicateHandshake()
            {
                // The peer retransmitted a flight we already processed, so it has not received our reply.
                bool resend = C.IsRetransmissionArmed || (C.IsHandshakeComplete && C.HasFlight && C.ResendFinalFlightOnPeerRetransmit);
                if (!resend)
                    return;

                // A retransmitted flight arrives as several records; answer it once.
                var now = DateTime.UtcNow;
                if (now - _lastDuplicateResponse < TimeSpan.FromMilliseconds(100))
                    return;
                _lastDuplicateResponse = now;
                C.RetransmitFlight();
            }

            // ── Sending ──────────────────────────────────────────────────────────────────────

            private byte[] WriteRecord(byte contentType, ushort epoch, byte[] plaintext)
            {
                ulong seq = _writeSequence[epoch]++;
                if (seq >= (1UL << 48))
                    throw new DtlsException(AlertDescription.InternalError, "Record sequence number space exhausted.");

                var cipher = _writeCiphers[epoch];

                // RFC 9146 §4: once encrypting, a peer that asked for a CID gets tls12_cid records with the real content
                // type inside DTLSInnerPlaintext.
                byte[] cid = cipher != null && C.WriteConnectionId is { Length: > 0 } ? C.WriteConnectionId : Array.Empty<byte>();
                ushort recordVersion = C.RecordVersion;
                byte[] fragment;
                if (cid.Length > 0)
                {
                    byte[] inner = new byte[plaintext.Length + 1];
                    plaintext.CopyTo(inner, 0);
                    inner[^1] = contentType;
                    fragment = cipher.Encrypt(Tls12Cid, recordVersion, epoch, seq, inner, cid);
                    contentType = Tls12Cid;
                }
                else
                {
                    fragment = cipher == null ? plaintext : cipher.Encrypt(contentType, recordVersion, epoch, seq, plaintext);
                }

                byte[] record = new byte[13 + cid.Length + fragment.Length];
                record[0] = contentType;
                BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(1), recordVersion);
                BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), epoch);
                for (int i = 0; i < 6; i++)
                    record[10 - i] = (byte)(seq >> (8 * i));
                cid.CopyTo(record, 11);
                BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(11 + cid.Length), (ushort)fragment.Length);
                Buffer.BlockCopy(fragment, 0, record, 13 + cid.Length, fragment.Length);
                return record;
            }

            private static byte[] HandshakeHeader(byte type, int length, int messageSeq, int offset, int fragmentLength, byte[] body, int bodyOffset)
            {
                byte[] message = new byte[12 + fragmentLength];
                message[0] = type;
                message[1] = (byte)(length >> 16); message[2] = (byte)(length >> 8); message[3] = (byte)length;
                message[4] = (byte)(messageSeq >> 8); message[5] = (byte)messageSeq;
                message[6] = (byte)(offset >> 16); message[7] = (byte)(offset >> 8); message[8] = (byte)offset;
                message[9] = (byte)(fragmentLength >> 16); message[10] = (byte)(fragmentLength >> 8); message[11] = (byte)fragmentLength;
                Buffer.BlockCopy(body, bodyOffset, message, 12, fragmentLength);
                return message;
            }

            public override byte[] SendHandshake(byte type, byte[] body, bool addToTranscript)
            {
                int messageSeq = C.NextSendMessageSeq++;
                byte[] message = HandshakeHeader(type, body.Length, messageSeq, 0, body.Length, body, 0);
                if (addToTranscript)
                    C.AddToTranscript(message);

                ushort epoch = _writeEpoch;
                C.SendInFlight(() => FragmentAndWrite(type, body, messageSeq, epoch));
                return message;
            }

            private List<byte[]> FragmentAndWrite(byte type, byte[] body, int messageSeq, ushort epoch)
            {
                var records = new List<byte[]>();
                int offset = 0;
                do
                {
                    int length = Math.Min(Math.Min(MaxHandshakeFragment, C.MaxApplicationDataSize - 12), body.Length - offset);
                    records.Add(WriteRecord(0x16, epoch, HandshakeHeader(type, body.Length, messageSeq, offset, length, body, offset)));
                    offset += length;
                }
                while (offset < body.Length);
                return records;
            }

            public override void SendChangeCipherSpec()
            {
                if (_pendingWriteCipher == null)
                    throw new InvalidOperationException("No pending write cipher.");

                ushort epoch = _writeEpoch;
                C.SendInFlight(() => new[] { WriteRecord(0x14, epoch, new byte[] { 1 }) });

                _writeEpoch++;
                _writeCiphers[_writeEpoch] = _pendingWriteCipher;
                _writeSequence[_writeEpoch] = 0;
                _pendingWriteCipher = null;
            }

            public override void WriteApplicationData(byte[] data) => C.Enqueue(WriteRecord(0x17, _writeEpoch, data));

            public override void SendAlert(byte level, AlertDescription description)
                => C.Enqueue(WriteRecord(0x15, _writeEpoch, new[] { level, (byte)description }));
        }
    }
}
