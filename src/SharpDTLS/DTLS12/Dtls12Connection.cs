using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using SharpDTLS.DTLS10;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// Per-association DTLS 1.0/1.2 machinery shared by client and server (RFC 4347, RFC 6347): the
    /// version-dependent cryptography (PRF, transcript hash, Finished, exporter, signatures) over a
    /// <see cref="Framing"/> that owns the record layer and handshake message transport (for DTLS:
    /// epochs, replay windows, message_seq, fragmentation, reassembly, reordering, retransmission).
    /// </summary>
    public abstract partial class Dtls12Connection : DtlsConnectionBase
    {
        private readonly Framing _framing;

        /// <summary>Handshake messages as hashed: in DTLS with the full 12-byte header (RFC 6347 §4.2.6).</summary>
        private readonly List<byte[]> _transcript = new();

        protected Dtls12Connection(bool isClient, Action<byte[]> send)
            : base(isClient, send, "DTLS12")
        {
            _framing = new DatagramFraming(this);
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

        /// <summary>Version written in record headers: the negotiated one, or the framing's initial version.</summary>
        protected ushort RecordVersion => NegotiatedVersion != 0 ? NegotiatedVersion : _framing.InitialRecordVersion;

        /// <summary>Whether the negotiated version is (D)TLS 1.2, with its PRF, transcript hash and signature schemes.</summary>
        protected bool IsDtls12 => ProtocolVersions.Level(NegotiatedVersion) >= 3;

        /// <summary>Whether this runs over datagrams (DTLS) rather than a stream (TLS).</summary>
        protected bool IsDatagram => _framing.IsDatagram;

        /// <summary>
        /// The side that sends the final flight resends it when the peer retransmits its own last
        /// flight (RFC 6347 §4.2.4); in a full handshake that is the server.
        /// </summary>
        protected virtual bool ResendFinalFlightOnPeerRetransmit => false;

        /// <summary>The CID the peer puts in records it sends us (RFC 9146), or null / empty for none.</summary>
        protected byte[] ReadConnectionId { get; set; }

        /// <summary>The CID we put in records we send (the peer's choice), or null / empty for none.</summary>
        protected byte[] WriteConnectionId { get; set; }

        /// <summary>Our connection ID (RFC 9146): the peer sends it in every encrypted record. Null when not negotiated.</summary>
        public byte[] ConnectionId => ReadConnectionId is { Length: > 0 } ? ReadConnectionId : null;

        /// <summary>The peer's connection ID, sent in our encrypted records. Null when not negotiated.</summary>
        public byte[] PeerConnectionId => WriteConnectionId is { Length: > 0 } ? WriteConnectionId : null;

        protected override int ReceiveConnectionIdLength => ReadConnectionId?.Length ?? 0;

        /// <summary>
        /// An encrypted record authenticated and passed the replay window; <paramref name="withConnectionId"/> tells
        /// whether it carried our CID. Used for peer address updates (RFC 9146 §6).
        /// </summary>
        protected virtual void OnRecordAuthenticated(ushort epoch, ulong sequenceNumber, bool withConnectionId) { }

        // ── Hooks for the handshake state machines ───────────────────────────────────────────

        /// <summary>Handles the next in-order handshake message. <paramref name="message"/> is the message as framed (DTLS: 12-byte header).</summary>
        protected abstract void OnHandshakeMessage(byte type, byte[] body, byte[] message, ushort epoch);

        /// <summary>The peer's ChangeCipherSpec took effect: reads are now in the next epoch.</summary>
        protected virtual void OnChangeCipherSpecReceived() { }

        // ── Record layer and handshake transport (delegated to the framing) ──────────────────

        protected override void ProcessRecord(byte[] record) => _framing.ProcessRecord(record);

        /// <summary>Epoch-0 record sequence numbers continue from here (a stateless server continues after HelloVerifyRequest).</summary>
        protected void SetInitialRecordSequence(ulong next) => _framing.SetInitialRecordSequence(next);

        /// <summary>
        /// Sends a handshake message as part of the current flight in the current write epoch, adding it
        /// to the transcript unless <paramref name="addToTranscript"/> is false. Returns the message as framed.
        /// </summary>
        protected byte[] SendHandshake(byte type, byte[] body, bool addToTranscript = true) => _framing.SendHandshake(type, body, addToTranscript);

        /// <summary>Sends ChangeCipherSpec (in the current epoch) and switches writes to the pending cipher.</summary>
        protected void SendChangeCipherSpec() => _framing.SendChangeCipherSpec();

        /// <summary>Whether reads have switched to the epoch protected by the negotiated keys.</summary>
        protected bool IsReadEpochProtected => _framing.IsReadProtected;

        public override int MaxApplicationDataSize => PeerRecordLimit - _framing.RecordOverhead;

        protected override void WriteApplicationData(byte[] data) => _framing.WriteApplicationData(data);

        protected override void SendAlert(AlertDescription description, bool fatal) => _framing.SendAlert(fatal ? (byte)2 : (byte)1, description);

        // ── Transcript, PRF and keys ─────────────────────────────────────────────────────────

        protected void AddToTranscript(byte[] message) => _transcript.Add(_framing.TranscriptContribution(message));

        protected void ResetTranscript() => _transcript.Clear();

        /// <summary>Concatenated handshake messages, the input to CertificateVerify signatures.</summary>
        protected byte[] TranscriptBytes() => _transcript.SelectMany(m => m).ToArray();

        /// <summary>MD5 || SHA-1 before (D)TLS 1.2; the PRF hash of the cipher suite in (D)TLS 1.2.</summary>
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
            _framing.SetPendingCiphers(read: IsClient ? serverWrite : clientWrite, write: IsClient ? clientWrite : serverWrite);

            KeyLogWriter?.Invoke($"CLIENT_RANDOM {Convert.ToHexString(ClientRandom).ToLowerInvariant()} {Convert.ToHexString(MasterSecret).ToLowerInvariant()}");
        }

        /// <summary>verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]</summary>
        protected byte[] ComputeVerifyData(bool fromClient)
            => Prf(MasterSecret, fromClient ? "client finished" : "server finished", TranscriptHash(), 12);

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
