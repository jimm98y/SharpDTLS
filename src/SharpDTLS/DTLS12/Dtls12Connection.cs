using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using SharpDTLS.DTLS10;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// Per-association DTLS 1.0/1.2 machinery shared by client and server (RFC 4347, RFC 6347):
    /// record layer with per-epoch ciphers and replay windows, ChangeCipherSpec handling, handshake
    /// message transport (message_seq, fragmentation, reassembly, reordering, retransmission) and the
    /// version-dependent cryptography (PRF, transcript hash, Finished, exporter, signatures).
    /// </summary>
    public abstract class Dtls12Connection : DtlsConnectionBase
    {
        /// <summary>Target maximum datagram size; handshake messages are fragmented to fit.</summary>
        protected const int MaxDatagramSize = 1200;
        private const int MaxHandshakeFragment = MaxDatagramSize - 13 - 12 - 64; // record + handshake headers + cipher overhead
        private const int MaxBufferedMessages = 16;
        private const int MaxFutureEpochRecords = 16;

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

        /// <summary>Handshake messages in DTLS form (12-byte header + body), as hashed (RFC 6347 §4.2.6).</summary>
        private readonly List<byte[]> _transcript = new();

        protected Dtls12Connection(bool isClient, Action<byte[]> send)
            : base(isClient, send, "DTLS12")
        {
        }

        /// <summary>Oldest protocol version this endpoint accepts.</summary>
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>Newest protocol version this endpoint offers.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>The negotiated version, or 0 before ServerHello.</summary>
        public ushort NegotiatedVersion { get; protected set; }

        public CipherSuiteInfo CipherSuite { get; protected set; }

        protected byte[] ClientRandom { get; set; }
        protected byte[] ServerRandom { get; set; }
        protected byte[] MasterSecret { get; private set; }
        protected bool UseEncryptThenMac { get; set; }
        protected bool UseExtendedMasterSecret { get; set; }
        protected int NextSendMessageSeq { get; set; }
        protected int NextReceiveMessageSeq { get; set; }

        /// <summary>Version written in record headers: DTLS 1.0 until a version is negotiated (RFC 6347 §4.1).</summary>
        protected ushort RecordVersion => NegotiatedVersion != 0 ? NegotiatedVersion : DtlsVersion.Dtls10;

        protected bool IsDtls12 => NegotiatedVersion == DtlsVersion.Dtls12;

        /// <summary>
        /// The side that sends the final flight resends it when the peer retransmits its own last
        /// flight (RFC 6347 §4.2.4); in a full handshake that is the server.
        /// </summary>
        protected virtual bool ResendFinalFlightOnPeerRetransmit => false;

        // ── Hooks for the handshake state machines ───────────────────────────────────────────

        /// <summary>Handles the next in-order handshake message. <paramref name="message"/> is the full DTLS form.</summary>
        protected abstract void OnHandshakeMessage(byte type, byte[] body, byte[] message, ushort epoch);

        /// <summary>The peer's ChangeCipherSpec took effect: reads are now in the next epoch.</summary>
        protected virtual void OnChangeCipherSpecReceived() { }

        // ── Record layer: receiving ──────────────────────────────────────────────────────────

        protected override void ProcessRecord(byte[] record)
        {
            if (record.Length < 13 || record[1] != 0xFE)
                throw new DtlsRecordDiscardedException("Not a DTLS 1.0/1.2 record");

            byte contentType = record[0];
            ushort recordVersion = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(1));
            ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(3));
            ulong sequenceNumber = 0;
            for (int i = 5; i < 11; i++)
                sequenceNumber = (sequenceNumber << 8) | record[i];
            byte[] fragment = record.AsSpan(13).ToArray();

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
            byte[] plaintext = cipher == null ? fragment : cipher.Decrypt(contentType, recordVersion, epoch, sequenceNumber, fragment);
            window.Mark(sequenceNumber);

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
                    OnAlertReceived(plaintext[0], (AlertDescription)plaintext[1]);
                    break;

                case 0x16:
                    ProcessHandshakeFragments(plaintext, epoch);
                    break;

                case 0x17:
                    if (epoch == 0)
                        throw new DtlsException(AlertDescription.UnexpectedMessage, "Unprotected application data.");
                    if (!IsHandshakeComplete)
                        throw new DtlsRecordDiscardedException("Application data before handshake completion");
                    RaiseApplicationData(plaintext);
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
                if (IsHandshakeComplete)
                    throw new DtlsRecordDiscardedException("Duplicate ChangeCipherSpec");
                _changeCipherSpecPending = true;
                return;
            }

            _readEpoch++;
            _readCiphers[_readEpoch] = _pendingReadCipher;
            _readWindows[_readEpoch] = new RecordWindow();
            _pendingReadCipher = null;
            _changeCipherSpecPending = false;
            OnChangeCipherSpecReceived();

            var buffered = _futureEpochRecords.ToList();
            _futureEpochRecords.Clear();
            foreach (var record in buffered)
            {
                try { ProcessRecord(record); }
                catch (DtlsRecordDiscardedException ex) { Debug.WriteLine($"{LogPrefix} Discarded buffered record: {ex.Message}"); }
                if (IsClosed) return;
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

                if (messageSeq < NextReceiveMessageSeq)
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
                if (messageSeq > NextReceiveMessageSeq)
                {
                    if (_bufferedMessages.Count < MaxBufferedMessages)
                        _bufferedMessages[messageSeq] = (message, epoch);
                    continue;
                }

                Deliver(message, epoch);
                while (!IsClosed && _bufferedMessages.TryGetValue(NextReceiveMessageSeq, out var next))
                {
                    _bufferedMessages.Remove(NextReceiveMessageSeq);
                    Deliver(next.Message, next.Epoch);
                }
                if (IsClosed)
                    return;
            }
        }

        private void Deliver(byte[] message, ushort epoch)
        {
            NextReceiveMessageSeq++;
            byte[] body = message.AsSpan(12).ToArray();
            OnHandshakeMessage(message[0], body, message, epoch);

            // A ChangeCipherSpec that overtook the key exchange takes effect only once the handler that
            // derived the keys has finished updating its state.
            if (_changeCipherSpecPending && _pendingReadCipher != null && !IsClosed)
                OnChangeCipherSpec();
        }

        private void OnDuplicateHandshake()
        {
            // The peer retransmitted a flight we already processed, so it has not received our reply.
            bool resend = IsRetransmissionArmed || (IsHandshakeComplete && HasFlight && ResendFinalFlightOnPeerRetransmit);
            if (!resend)
                return;

            // A retransmitted flight arrives as several records; answer it once.
            var now = DateTime.UtcNow;
            if (now - _lastDuplicateResponse < TimeSpan.FromMilliseconds(100))
                return;
            _lastDuplicateResponse = now;
            RetransmitFlight();
        }

        // ── Record layer: sending ────────────────────────────────────────────────────────────

        private byte[] WriteRecord(byte contentType, ushort epoch, byte[] plaintext)
        {
            ulong seq = _writeSequence[epoch]++;
            if (seq >= (1UL << 48))
                throw new DtlsException(AlertDescription.InternalError, "Record sequence number space exhausted.");

            var cipher = _writeCiphers[epoch];
            byte[] fragment = cipher == null ? plaintext : cipher.Encrypt(contentType, RecordVersion, epoch, seq, plaintext);

            byte[] record = new byte[13 + fragment.Length];
            record[0] = contentType;
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(1), RecordVersion);
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), epoch);
            for (int i = 0; i < 6; i++)
                record[10 - i] = (byte)(seq >> (8 * i));
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(11), (ushort)fragment.Length);
            Buffer.BlockCopy(fragment, 0, record, 13, fragment.Length);
            return record;
        }

        /// <summary>Epoch-0 record sequence numbers continue from here (a stateless server continues after HelloVerifyRequest).</summary>
        protected void SetInitialRecordSequence(ulong next) => _writeSequence[0] = next;

        /// <summary>Builds a handshake message in DTLS form with the next message_seq.</summary>
        protected byte[] BuildHandshakeMessage(byte type, byte[] body)
        {
            int seq = NextSendMessageSeq++;
            return HandshakeHeader(type, body.Length, seq, 0, body.Length, body, 0);
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

        /// <summary>
        /// Sends a handshake message as part of the current flight in the current write epoch, adding it
        /// to the transcript unless <paramref name="addToTranscript"/> is false. Returns the DTLS-form message.
        /// </summary>
        protected byte[] SendHandshake(byte type, byte[] body, bool addToTranscript = true)
        {
            byte[] message = BuildHandshakeMessage(type, body);
            if (addToTranscript)
                AddToTranscript(message);

            ushort epoch = _writeEpoch;
            int messageSeq = (message[4] << 8) | message[5];
            SendInFlight(() => FragmentAndWrite(type, body, messageSeq, epoch));
            return message;
        }

        /// <summary>Sends a handshake message outside any flight (post-handshake messages).</summary>
        protected void SendHandshakeNoFlight(byte type, byte[] body)
        {
            byte[] message = BuildHandshakeMessage(type, body);
            int messageSeq = (message[4] << 8) | message[5];
            foreach (var record in FragmentAndWrite(type, body, messageSeq, _writeEpoch))
                Enqueue(record);
        }

        private List<byte[]> FragmentAndWrite(byte type, byte[] body, int messageSeq, ushort epoch)
        {
            var records = new List<byte[]>();
            int offset = 0;
            do
            {
                int length = Math.Min(MaxHandshakeFragment, body.Length - offset);
                records.Add(WriteRecord(0x16, epoch, HandshakeHeader(type, body.Length, messageSeq, offset, length, body, offset)));
                offset += length;
            }
            while (offset < body.Length);
            return records;
        }

        /// <summary>Sends ChangeCipherSpec (in the current epoch) and switches writes to the pending cipher.</summary>
        protected void SendChangeCipherSpec()
        {
            if (_pendingWriteCipher == null)
                throw new InvalidOperationException("No pending write cipher.");

            ushort epoch = _writeEpoch;
            SendInFlight(() => new[] { WriteRecord(0x14, epoch, new byte[] { 1 }) });

            _writeEpoch++;
            _writeCiphers[_writeEpoch] = _pendingWriteCipher;
            _writeSequence[_writeEpoch] = 0;
            _pendingWriteCipher = null;
        }

        protected override void WriteApplicationData(byte[] data) => Enqueue(WriteRecord(0x17, _writeEpoch, data));

        protected override void SendAlert(AlertDescription description, bool fatal)
            => Enqueue(WriteRecord(0x15, _writeEpoch, new[] { fatal ? (byte)2 : (byte)1, (byte)description }));

        // ── Transcript, PRF and keys ─────────────────────────────────────────────────────────

        protected void AddToTranscript(byte[] message) => _transcript.Add(DtlsHandshakeHash.Contribution(message, 0));

        protected void ResetTranscript() => _transcript.Clear();

        /// <summary>Concatenated handshake messages, the input to CertificateVerify signatures.</summary>
        protected byte[] TranscriptBytes() => _transcript.SelectMany(m => m).ToArray();

        /// <summary>MD5 || SHA-1 in DTLS 1.0; the PRF hash of the cipher suite in DTLS 1.2.</summary>
        protected byte[] TranscriptHash()
        {
            if (!IsDtls12)
            {
                var md5 = new MD5Digest();
                var sha1 = new Sha1Digest();
                foreach (var m in _transcript) { md5.BlockUpdate(m, 0, m.Length); sha1.BlockUpdate(m, 0, m.Length); }
                byte[] result = new byte[36];
                md5.DoFinal(result, 0);
                sha1.DoFinal(result, 16);
                return result;
            }

            IDigest digest = CipherSuite.Prf == PrfHashAlgorithm.Sha384 ? new Sha384Digest() : new Sha256Digest();
            foreach (var m in _transcript)
                digest.BlockUpdate(m, 0, m.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        protected byte[] Prf(byte[] secret, string label, byte[] seed, int length)
            => IsDtls12
                ? Dtls12CryptoUtils.PRF(secret, label, seed, length, CipherSuite.Prf == PrfHashAlgorithm.Sha384)
                : Dtls10CryptoUtils.PRF(secret, label, seed, length);

        /// <summary>
        /// Computes the master secret (with RFC 7627 when negotiated; call after ClientKeyExchange is in the
        /// transcript) and the pending ciphers for both directions.
        /// </summary>
        protected void DeriveKeys(byte[] preMasterSecret)
        {
            DeriveKeysFromMasterSecret(UseExtendedMasterSecret
                ? Prf(preMasterSecret, "extended master secret", TranscriptHash(), 48)
                : Prf(preMasterSecret, "master secret", Concat(ClientRandom, ServerRandom), 48));
        }

        /// <summary>
        /// The pending ciphers from an existing master secret: a resumed session's keys come from its master
        /// secret and the new hello randoms (RFC 5246 §7.3).
        /// </summary>
        protected void DeriveKeysFromMasterSecret(byte[] masterSecret)
        {
            MasterSecret = masterSecret;
            byte[] keyBlock = Prf(MasterSecret, "key expansion", Concat(ServerRandom, ClientRandom), RecordCiphers.KeyBlockLength(CipherSuite));
            var (clientWrite, serverWrite) = RecordCiphers.Create(CipherSuite, keyBlock, UseEncryptThenMac && CipherSuite.IsCbc);
            _pendingReadCipher = IsClient ? serverWrite : clientWrite;
            _pendingWriteCipher = IsClient ? clientWrite : serverWrite;

            KeyLogWriter?.Invoke($"CLIENT_RANDOM {Convert.ToHexString(ClientRandom).ToLowerInvariant()} {Convert.ToHexString(MasterSecret).ToLowerInvariant()}");
        }

        /// <summary>verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]</summary>
        protected byte[] ComputeVerifyData(bool fromClient)
            => Prf(MasterSecret, fromClient ? "client finished" : "server finished", TranscriptHash(), 12);

        /// <summary>Whether reads have switched to the epoch protected by the negotiated keys.</summary>
        protected bool IsReadEpochProtected => _readEpoch > 0;

        protected override byte[] ExportKeyingMaterialCore(string label, byte[] context, int length)
            => Prf(MasterSecret, label, Dtls12CryptoUtils.BuildExporterSeed(ClientRandom, ServerRandom, context), length);

        // ── Signatures (TLS 1.2 schemes vs. TLS 1.1 MD5/SHA-1) ───────────────────────────────

        /// <summary>
        /// Signs <paramref name="content"/>. In DTLS 1.2 the scheme is the first supported one the peer
        /// accepts; DTLS 1.0 uses the fixed TLS 1.1 algorithms and returns a null scheme.
        /// </summary>
        protected byte[] Sign(AsymmetricKeyParameter privateKey, byte[] content, IEnumerable<ushort> peerSchemes, out ushort? scheme)
        {
            if (!IsDtls12)
            {
                scheme = null;
                return Dtls10Signatures.Sign(privateKey, content);
            }

            scheme = Dtls12Signatures.SelectScheme(privateKey, peerSchemes)
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "No signature algorithm in common.");
            return Dtls12Signatures.Sign(scheme.Value, privateKey, content);
        }

        protected bool Verify(AsymmetricKeyParameter publicKey, byte[] content, ushort? scheme, byte[] signature, IEnumerable<ushort> acceptedSchemes)
        {
            if (!IsDtls12)
                return Dtls10Signatures.Verify(publicKey, content, signature);

            if (scheme == null || !acceptedSchemes.Contains(scheme.Value))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Signature scheme 0x{scheme:X4} was not offered.");
            return Dtls12Signatures.Verify(scheme.Value, publicKey, content, signature);
        }

        protected static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
