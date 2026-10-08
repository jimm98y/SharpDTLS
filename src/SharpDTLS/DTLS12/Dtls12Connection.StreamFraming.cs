using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace SharpDTLS.DTLS12
{
    public abstract partial class Dtls12Connection
    {
        /// <summary>
        /// TLS framing over a reliable byte stream (RFC 5246 §6.2): 5-byte record headers, an implicit 64-bit sequence
        /// number per direction that restarts at each ChangeCipherSpec, and handshake messages with 4-byte headers that
        /// may span or share records. Nothing is retransmitted or reordered.
        /// </summary>
        private sealed class StreamFraming : Framing
        {
            private const int MaxCiphertextLength = 16384 + 2048;

            private readonly List<byte> _input = new();
            private readonly List<byte> _handshake = new();

            private IRecordCipher _readCipher, _writeCipher, _pendingReadCipher, _pendingWriteCipher;
            private ulong _readSequence, _writeSequence;
            private ushort _readEpoch;

            public StreamFraming(Dtls12Connection connection) : base(connection) { }

            public override bool IsDatagram => false;

            // The record version of a ClientHello is commonly TLS 1.0 for compatibility (RFC 5246 Appendix E.1).
            public override ushort InitialRecordVersion => TlsVersion.Tls10;

            public override bool IsReadProtected => _readEpoch > 0;
            public override int RecordOverhead => 0;
            public override byte[] TranscriptContribution(byte[] message) => message;
            public override void SetInitialRecordSequence(ulong next) { }

            public override void SetPendingCiphers(IRecordCipher read, IRecordCipher write)
            {
                _pendingReadCipher = read;
                _pendingWriteCipher = write;
            }

            // ── Receiving ────────────────────────────────────────────────────────────────────

            public override void ProcessInput(byte[] data, int offset, int count)
            {
                for (int i = 0; i < count; i++)
                    _input.Add(data[offset + i]);

                while (_input.Count >= 5 && !C.IsClosed)
                {
                    int length = (_input[3] << 8) | _input[4];
                    if (length > MaxCiphertextLength)
                        throw new DtlsException(AlertDescription.RecordOverflow, $"Record of {length} bytes.");
                    if (_input.Count < 5 + length)
                        return;
                    byte[] record = _input.GetRange(0, 5 + length).ToArray();
                    _input.RemoveRange(0, 5 + length);
                    ProcessRecord(record);
                }
            }

            public override void ProcessRecord(byte[] record)
            {
                byte contentType = record[0];
                ushort version = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(1));
                if (record[1] != 0x03)
                    throw new DtlsException(AlertDescription.ProtocolVersion, $"Not a TLS record (version 0x{version:X4}).");
                byte[] fragment = record.AsSpan(5).ToArray();

                ulong sequence = _readSequence++;
                byte[] plaintext = _readCipher == null
                    ? fragment
                    : _readCipher.Decrypt(contentType, version, (ushort)(sequence >> 48), sequence & 0xFFFFFFFFFFFFUL, fragment);
                if (_readCipher != null)
                    C.CheckReceivedRecordSize(plaintext.Length);
                else if (plaintext.Length > MaxRecordPayload)
                    throw new DtlsException(AlertDescription.RecordOverflow, $"Record of {plaintext.Length} bytes.");

                // RFC 5246 §6.2.1: handshake messages may span records, but nothing else may come between their parts.
                if (contentType != 0x16 && _handshake.Count > 0)
                    throw new DtlsException(AlertDescription.UnexpectedMessage, "Record interleaved with a fragmented handshake message.");

                switch (contentType)
                {
                    case 0x14:
                        if (plaintext.Length != 1 || plaintext[0] != 1)
                            throw new DtlsException(AlertDescription.DecodeError, "Invalid ChangeCipherSpec.");
                        if (_pendingReadCipher == null)
                            throw new DtlsException(AlertDescription.UnexpectedMessage, "ChangeCipherSpec before the keys are known.");
                        _readCipher = _pendingReadCipher;
                        _pendingReadCipher = null;
                        _readSequence = 0;
                        _readEpoch++;
                        C.OnChangeCipherSpecReceived();
                        break;

                    case 0x15:
                        if (plaintext.Length != 2)
                            throw new DtlsException(AlertDescription.DecodeError, "Invalid alert.");
                        C.OnAlertReceived(plaintext[0], (AlertDescription)plaintext[1]);
                        break;

                    case 0x16:
                        if (plaintext.Length == 0)
                            throw new DtlsException(AlertDescription.UnexpectedMessage, "Empty handshake record.");
                        _handshake.AddRange(plaintext);
                        DeliverHandshakeMessages();
                        break;

                    case 0x17:
                        if (_readCipher == null || !C.IsHandshakeComplete)
                            throw new DtlsException(AlertDescription.UnexpectedMessage, "Application data before the handshake completed.");
                        C.RaiseApplicationData(plaintext);
                        break;

                    default:
                        throw new DtlsException(AlertDescription.UnexpectedMessage, $"Unknown content type 0x{contentType:X2}.");
                }
            }

            private void DeliverHandshakeMessages()
            {
                while (_handshake.Count >= 4 && !C.IsClosed)
                {
                    int length = (_handshake[1] << 16) | (_handshake[2] << 8) | _handshake[3];
                    if (length > HandshakeReassembler.MaxMessageLength)
                        throw new DtlsException(AlertDescription.HandshakeFailure, $"Handshake message of {length} bytes.");
                    if (_handshake.Count < 4 + length)
                        return;
                    byte[] message = _handshake.GetRange(0, 4 + length).ToArray();
                    _handshake.RemoveRange(0, 4 + length);
                    C.NextReceiveMessageSeq++;
                    C.OnHandshakeMessage(message[0], message.AsSpan(4).ToArray(), message, _readEpoch);
                }
            }

            // ── Sending ──────────────────────────────────────────────────────────────────────

            private byte[] WriteRecord(byte contentType, byte[] payload)
            {
                ulong sequence = _writeSequence++;
                ushort version = C.RecordVersion;
                byte[] fragment = _writeCipher == null
                    ? payload
                    : _writeCipher.Encrypt(contentType, version, (ushort)(sequence >> 48), sequence & 0xFFFFFFFFFFFFUL, payload);
                byte[] record = new byte[5 + fragment.Length];
                record[0] = contentType;
                BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(1), version);
                BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), (ushort)fragment.Length);
                fragment.CopyTo(record, 5);
                return record;
            }

            public override byte[] SendHandshake(byte type, byte[] body, bool addToTranscript)
            {
                byte[] message = new byte[4 + body.Length];
                message[0] = type;
                message[1] = (byte)(body.Length >> 16);
                message[2] = (byte)(body.Length >> 8);
                message[3] = (byte)body.Length;
                body.CopyTo(message, 4);
                C.NextSendMessageSeq++;
                if (addToTranscript)
                    C.AddToTranscript(message);

                C.SendInFlight(() =>
                {
                    var records = new List<byte[]>();
                    int chunk = Math.Min(MaxRecordPayload, C.MaxApplicationDataSize);
                    for (int offset = 0; offset < message.Length; offset += chunk)
                        records.Add(WriteRecord(0x16, message.AsSpan(offset, Math.Min(chunk, message.Length - offset)).ToArray()));
                    return records;
                });
                return message;
            }

            public override void SendChangeCipherSpec()
            {
                if (_pendingWriteCipher == null)
                    throw new InvalidOperationException("No pending write cipher.");
                C.SendInFlight(() => new[] { WriteRecord(0x14, new byte[] { 1 }) });
                _writeCipher = _pendingWriteCipher;
                _pendingWriteCipher = null;
                _writeSequence = 0;
            }

            public override void WriteApplicationData(byte[] data) => C.Enqueue(WriteRecord(0x17, data));

            public override void SendAlert(byte level, AlertDescription description)
                => C.Enqueue(WriteRecord(0x15, new[] { level, (byte)description }));
        }
    }
}
