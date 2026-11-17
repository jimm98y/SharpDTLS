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

using System;
using System.Buffers;
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

            public override void DisposeCiphers()
            {
                foreach (var cipher in _writeCiphers.Values)
                    cipher?.Dispose();
                foreach (var cipher in _readCiphers.Values)
                    cipher?.Dispose();
                _pendingReadCipher?.Dispose();
                _pendingWriteCipher?.Dispose();
            }
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

            public override void ProcessRecord(ReadOnlySpan<byte> record)
            {
                if (record.Length < 13 || record[1] != 0xFE)
                    throw new DtlsRecordDiscardedException("Not a DTLS 1.0/1.2 record");

                byte contentType = record[0];
                ushort recordVersion = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(1));
                ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(3));
                ulong sequenceNumber = 0;
                for (int i = 5; i < 11; i++)
                    sequenceNumber = (sequenceNumber << 8) | record[i];

                // RFC 9146 §3: with a CID negotiated for this direction, encrypted records carry it in tls12_cid records;
                // any other encrypted record is invalid. Plaintext records never carry one.
                ReadOnlySpan<byte> connectionId = default;
                bool withCid = false;
                int headerLength = 13;
                byte[] readCid = C.ReadConnectionId;
                bool expectCid = readCid is { Length: > 0 };
                if (contentType == Tls12Cid)
                {
                    if (!expectCid || epoch == 0 || record.Length < 13 + readCid.Length)
                        throw new DtlsRecordDiscardedException("Unexpected tls12_cid record");
                    connectionId = record.Slice(11, readCid.Length);
                    if (!connectionId.SequenceEqual(readCid))
                        throw new DtlsRecordDiscardedException("Record for another connection ID");
                    headerLength += connectionId.Length;
                    withCid = true;
                }
                else if (expectCid && epoch > 0)
                {
                    throw new DtlsRecordDiscardedException("Encrypted record without the connection ID");
                }
                var fragment = record.Slice(headerLength);

                if (epoch > _readEpoch)
                {
                    // The next epoch's records can overtake the ChangeCipherSpec; keep a few until it arrives.
                    if (epoch == _readEpoch + 1 && _futureEpochRecords.Count < MaxFutureEpochRecords)
                        _futureEpochRecords.Add(record.ToArray());
                    return;
                }

                if (epoch == 0 && _readEpoch > 0)
                {
                    // Nothing authenticates an epoch-0 record once keys are in use, so it must never fail the
                    // connection (RFC 6347 §4.1.2.7): anyone can send one from the peer's address. Until the handshake
                    // completes, a handshake message sent before the peer's ChangeCipherSpec (a NewSessionTicket) can
                    // still arrive after it, retransmitted, and is taken if well formed; once it completes, an
                    // epoch-0 record only tells that the peer retransmitted a flight we already answered.
                    if (contentType != 0x16)
                        throw new DtlsRecordDiscardedException("Unprotected record after keys were established");
                    if (C.IsHandshakeComplete || !IsWellFormedHandshake(fragment.ToArray()))
                    {
                        if (IsRetransmittedHandshake(fragment.ToArray()))
                            OnDuplicateHandshake();
                        throw new DtlsRecordDiscardedException("Unprotected handshake record after keys were established");
                    }
                }

                if (epoch < _readEpoch && contentType != 0x16)
                    throw new DtlsRecordDiscardedException($"Record from old epoch {epoch}");

                var window = _readWindows[epoch];
                if (window.IsDuplicate(sequenceNumber))
                    throw new DtlsRecordDiscardedException($"Replayed record {epoch}:{sequenceNumber}");

                var cipher = _readCiphers[epoch];
                if (withCid && cipher == null)
                    throw new DtlsRecordDiscardedException("tls12_cid record without keys");

                // the plaintext of a buffer of the pool's: application data's goes on with the event, any other's back
                byte[] buffer = RecordBuffers.Pool.Rent(Math.Max(fragment.Length, 1));
                bool handedOver = false;
                try
                {
                    ProcessPlaintext(ref contentType, epoch, sequenceNumber, recordVersion, cipher, fragment, connectionId, withCid, buffer, ref handedOver);
                }
                finally
                {
                    if (!handedOver)
                        RecordBuffers.Pool.Return(buffer);
                }
            }

            private void ProcessPlaintext(ref byte contentType, ushort epoch, ulong sequenceNumber, ushort recordVersion, IRecordCipher cipher,
                ReadOnlySpan<byte> fragment, ReadOnlySpan<byte> connectionId, bool withCid, byte[] buffer, ref bool handedOver)
            {
                var window = _readWindows[epoch];
                int length;
                if (cipher == null)
                {
                    fragment.CopyTo(buffer);
                    length = fragment.Length;
                }
                else
                {
                    length = cipher.Decrypt(contentType, recordVersion, epoch, sequenceNumber, fragment, buffer, connectionId);
                }
                window.Mark(sequenceNumber);

                if (withCid)
                {
                    // DTLSInnerPlaintext: content || real_type || zeros
                    int end = ByteSpans.WithoutTrailingZeros(buffer.AsSpan(0, length));
                    if (end == 0)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "tls12_cid record without a content type.");
                    contentType = buffer[end - 1];
                    length = end - 1;
                }
                var plaintext = new ReadOnlySpan<byte>(buffer, 0, length);
                if (cipher != null)
                {
                    C.InspectRecord(false, contentType, epoch, sequenceNumber, plaintext);
                    C.CheckReceivedRecordSize(plaintext.Length);
                    C.OnRecordAuthenticated(epoch, sequenceNumber, withCid);
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
                        ProcessHandshakeFragments(plaintext.ToArray(), epoch);
                        break;

                    case 0x17:
                        if (epoch == 0)
                            throw new DtlsException(AlertDescription.UnexpectedMessage, "Unprotected application data.");
                        if (!C.IsHandshakeComplete)
                            throw new DtlsRecordDiscardedException("Application data before handshake completion");
                        handedOver = true;
                        C.RaiseApplicationData(buffer, length);
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

                    // Finished is always protected (RFC 6347 §4.2.6); an unprotected one is not the peer's.
                    if (epoch == 0 && plaintext[start] == HandshakeType.Finished)
                        continue;

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

            /// <summary>Whether a handshake record's fragments are well formed: each header and its fragment within the record.</summary>
            private static bool IsWellFormedHandshake(byte[] plaintext)
            {
                try
                {
                    var r = new TlsReader(plaintext);
                    while (!r.IsEmpty)
                    {
                        r.ReadUInt8();
                        int length = r.ReadUInt24();
                        r.ReadUInt16();
                        int offset = r.ReadUInt24();
                        int fragmentLength = r.ReadUInt24();
                        if (offset + fragmentLength > length || length > HandshakeReassembler.MaxMessageLength)
                            return false;
                        r.ReadBytes(fragmentLength);
                    }
                    return plaintext.Length > 0;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            /// <summary>Whether an unauthenticated handshake record holds a fragment of a message already processed.</summary>
            private bool IsRetransmittedHandshake(byte[] plaintext)
            {
                try
                {
                    var r = new TlsReader(plaintext);
                    while (!r.IsEmpty)
                    {
                        r.ReadUInt8();
                        r.ReadUInt24();
                        int messageSeq = r.ReadUInt16();
                        r.ReadUInt24();
                        r.ReadBytes(r.ReadUInt24());
                        if (messageSeq < C.NextReceiveMessageSeq)
                            return true;
                    }
                }
                catch (Exception)
                {
                    // malformed: not the peer's
                }
                return false;
            }

            private void Deliver(byte[] message, ushort epoch)
            {
                C.NextReceiveMessageSeq++;
                C.InspectReceived(message, 12);
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

            // RFC 9146 §4: once encrypting, a peer that asked for a CID gets tls12_cid records with the real content
            // type inside DTLSInnerPlaintext.
            private byte[] WriteCid(IRecordCipher cipher) => cipher != null && C.WriteConnectionId is { Length: > 0 } ? C.WriteConnectionId : Array.Empty<byte>();

            private int RecordLength(ushort epoch, int plaintextLength)
            {
                var cipher = _writeCiphers[epoch];
                int cid = WriteCid(cipher).Length;
                int inner = plaintextLength + (cid > 0 ? 1 : 0);
                return 13 + cid + (cipher == null ? inner : cipher.FragmentLength(inner));
            }

            private byte[] WriteRecord(byte contentType, ushort epoch, byte[] plaintext)
            {
                byte[] record = new byte[RecordLength(epoch, plaintext.Length)];
                WriteRecord(contentType, epoch, plaintext, record);
                return record;
            }

            /// <summary>Writes the record into <paramref name="record"/>, of <see cref="RecordLength"/> bytes.</summary>
            private void WriteRecord(byte contentType, ushort epoch, ReadOnlySpan<byte> plaintext, Span<byte> record)
            {
                ulong seq = _writeSequence[epoch]++;
                if (seq >= (1UL << 48))
                    throw new DtlsException(AlertDescription.InternalError, "Record sequence number space exhausted.");

                var cipher = _writeCiphers[epoch];
                if (cipher != null)
                    C.InspectRecord(true, contentType, epoch, seq, plaintext);

                byte[] cid = WriteCid(cipher);
                ushort recordVersion = C.RecordVersion;
                var fragment = record.Slice(13 + cid.Length);
                int fragmentLength;
                if (cid.Length > 0)
                {
                    byte[] inner = RecordBuffers.Pool.Rent(plaintext.Length + 1);
                    try
                    {
                        plaintext.CopyTo(inner);
                        inner[plaintext.Length] = contentType;
                        cipher.Encrypt(Tls12Cid, recordVersion, epoch, seq, inner.AsSpan(0, plaintext.Length + 1), fragment, cid);
                    }
                    finally
                    {
                        RecordBuffers.Pool.Return(inner);
                    }
                    fragmentLength = cipher.FragmentLength(plaintext.Length + 1);
                    contentType = Tls12Cid;
                }
                else if (cipher == null)
                {
                    plaintext.CopyTo(fragment);
                    fragmentLength = plaintext.Length;
                }
                else
                {
                    cipher.Encrypt(contentType, recordVersion, epoch, seq, plaintext, fragment, default);
                    fragmentLength = cipher.FragmentLength(plaintext.Length);
                }

                record[0] = contentType;
                BinaryPrimitives.WriteUInt16BigEndian(record.Slice(1), recordVersion);
                BinaryPrimitives.WriteUInt16BigEndian(record.Slice(3), epoch);
                for (int i = 0; i < 6; i++)
                    record[10 - i] = (byte)(seq >> (8 * i));
                cid.CopyTo(record.Slice(11));
                BinaryPrimitives.WriteUInt16BigEndian(record.Slice(11 + cid.Length), (ushort)fragmentLength);
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

            public override void WriteApplicationData(ReadOnlySpan<byte> data)
            {
                int length = RecordLength(_writeEpoch, data.Length);
                byte[] record = RecordBuffers.Pool.Rent(length);
                WriteRecord(0x17, _writeEpoch, data, record);
                C.EnqueueRented(record, length);
            }

            public override void SendAlert(byte level, AlertDescription description)
                => C.Enqueue(WriteRecord(0x15, _writeEpoch, new[] { level, (byte)description }));
        }
    }
}
