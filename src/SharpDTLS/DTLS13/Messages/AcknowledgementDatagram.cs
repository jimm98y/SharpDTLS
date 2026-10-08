using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDTLS.DTLS13.Messages
{
    /// <summary>
    /// DTLS 1.3 ACK (RFC 9147 §7): struct { RecordNumber record_numbers&lt;0..2^16-1&gt;; } ACK;
    /// where RecordNumber is { uint64 epoch; uint64 sequence_number; }.
    /// </summary>
    public class AcknowledgementDatagram : IDatagram
    {
        public List<(ulong Epoch, ulong SequenceNumber)> Records { get; set; } = new List<(ulong, ulong)>();

        // First acknowledged record, kept for callers that only deal with one record.
        public long RecordEpoch
        {
            get => Records.Count > 0 ? (long)Records[0].Epoch : 0;
            set => SetFirst((ulong)value, Records.Count > 0 ? Records[0].SequenceNumber : 0);
        }

        public long RecordNumber
        {
            get => Records.Count > 0 ? (long)Records[0].SequenceNumber : 0;
            set => SetFirst(Records.Count > 0 ? Records[0].Epoch : 0, (ulong)value);
        }

        public byte[] Bytes { get; private set; }

        public AcknowledgementDatagram()
        { }

        public AcknowledgementDatagram(IEnumerable<(ulong Epoch, ulong SequenceNumber)> records)
        {
            Records = new List<(ulong, ulong)>(records);
        }

        private void SetFirst(ulong epoch, ulong sequenceNumber)
        {
            if (Records.Count == 0) Records.Add((epoch, sequenceNumber));
            else Records[0] = (epoch, sequenceNumber);
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 3) throw new DtlsException(AlertDescription.DecodeError, "Buffer too small for ACK.");
            if (bytes[bytes.Length - 1] != 0x1a) throw new InvalidDataException("Unexpected record type (expected 0x1a).");

            int length = (bytes[0] << 8) | bytes[1];
            if (length % 16 != 0 || 2 + length + 1 != bytes.Length)
                throw new DtlsException(AlertDescription.DecodeError, $"Invalid ACK length: {length}");

            Bytes = (byte[])bytes.Clone();
            Records = new List<(ulong, ulong)>();
            for (int pos = 2; pos < 2 + length; pos += 16)
            {
                ulong epoch = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(pos, 8));
                ulong seq   = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(pos + 8, 8));
                Records.Add((epoch, seq));
            }
        }

        public byte[] ToBytes()
        {
            int length = 16 * Records.Count;
            byte[] data = new byte[2 + length + 1];
            data[0] = (byte)(length >> 8);
            data[1] = (byte)length;

            int pos = 2;
            foreach (var (epoch, seq) in Records)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(pos, 8), epoch);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(pos + 8, 8), seq);
                pos += 16;
            }

            data[pos] = 0x1a; // ACK content type

            Bytes = data;
            return data;
        }
    }
}
