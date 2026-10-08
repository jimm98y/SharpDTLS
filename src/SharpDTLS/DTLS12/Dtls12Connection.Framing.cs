using System;

namespace SharpDTLS.DTLS12
{
    public abstract partial class Dtls12Connection
    {
        /// <summary>
        /// The record layer and handshake message transport under the (D)TLS 1.0-1.2 handshake: record protection
        /// state, the ChangeCipherSpec switch, handshake message framing and the transcript form of a message. The
        /// handshake state machines only use it through <see cref="Dtls12Connection"/>'s protected members.
        /// </summary>
        private abstract class Framing
        {
            protected Framing(Dtls12Connection connection) => C = connection;

            /// <summary>The connection this framing serves.</summary>
            protected Dtls12Connection C { get; }

            /// <summary>Processes received transport bytes (TLS; DTLS splits datagrams into records first).</summary>
            public virtual void ProcessInput(byte[] data, int offset, int count) => throw new NotSupportedException();

            /// <summary>Processes one received record.</summary>
            public abstract void ProcessRecord(byte[] record);

            /// <summary>Frames, records and sends a handshake message; returns the framed message.</summary>
            public abstract byte[] SendHandshake(byte type, byte[] body, bool addToTranscript);

            public abstract void SendChangeCipherSpec();
            public abstract void WriteApplicationData(byte[] data);
            public abstract void SendAlert(byte level, AlertDescription description);

            /// <summary>The ciphers that take effect at the next ChangeCipherSpec in each direction.</summary>
            public abstract void SetPendingCiphers(IRecordCipher read, IRecordCipher write);

            /// <summary>Whether reads have switched to the negotiated keys.</summary>
            public abstract bool IsReadProtected { get; }

            /// <summary>Payload bytes per record taken by the framing itself (e.g. a CID record's inner content type).</summary>
            public abstract int RecordOverhead { get; }

            /// <summary>What a framed handshake message contributes to the transcript.</summary>
            public abstract byte[] TranscriptContribution(byte[] message);

            /// <summary>Whether this is DTLS (versions count down from 0xFEFF) rather than TLS.</summary>
            public abstract bool IsDatagram { get; }

            /// <summary>The record version before one is negotiated.</summary>
            public abstract ushort InitialRecordVersion { get; }

            /// <summary>Record sequence numbers for unprotected records continue from here.</summary>
            public abstract void SetInitialRecordSequence(ulong next);
        }
    }
}
