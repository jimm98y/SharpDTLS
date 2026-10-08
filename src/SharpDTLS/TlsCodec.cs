using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// Bounds-checked reader for TLS presentation-language structures. Any underflow is a decode_error.
    /// </summary>
    public sealed class TlsReader
    {
        private readonly byte[] _buffer;
        private readonly int _end;

        public TlsReader(byte[] buffer, int offset = 0, int length = -1)
        {
            _buffer = buffer;
            Position = offset;
            _end = length < 0 ? buffer.Length : offset + length;
            if (_end > buffer.Length)
                throw new DtlsException(AlertDescription.DecodeError, "Truncated message.");
        }

        public byte[] Buffer => _buffer;
        public int Position { get; private set; }
        public int Remaining => _end - Position;
        public bool IsEmpty => Position >= _end;

        private void Require(int count)
        {
            if (count < 0 || Position + count > _end)
                throw new DtlsException(AlertDescription.DecodeError, "Truncated message.");
        }

        public byte ReadUInt8() { Require(1); return _buffer[Position++]; }
        public ushort ReadUInt16() { Require(2); ushort v = (ushort)((_buffer[Position] << 8) | _buffer[Position + 1]); Position += 2; return v; }
        public int ReadUInt24() { Require(3); int v = (_buffer[Position] << 16) | (_buffer[Position + 1] << 8) | _buffer[Position + 2]; Position += 3; return v; }
        public uint ReadUInt32() { Require(4); uint v = (uint)((_buffer[Position] << 24) | (_buffer[Position + 1] << 16) | (_buffer[Position + 2] << 8) | _buffer[Position + 3]); Position += 4; return v; }

        public byte[] ReadBytes(int count)
        {
            Require(count);
            byte[] result = _buffer.AsSpan(Position, count).ToArray();
            Position += count;
            return result;
        }

        public byte[] ReadOpaque8() => ReadBytes(ReadUInt8());
        public byte[] ReadOpaque16() => ReadBytes(ReadUInt16());
        public byte[] ReadOpaque24() => ReadBytes(ReadUInt24());

        public ushort[] ReadUInt16List16()
        {
            int length = ReadUInt16();
            if ((length & 1) != 0)
                throw new DtlsException(AlertDescription.DecodeError, "Odd-length uint16 list.");
            var values = new ushort[length / 2];
            for (int i = 0; i < values.Length; i++)
                values[i] = ReadUInt16();
            return values;
        }

        /// <summary>Reads a sub-structure of <paramref name="length"/> bytes as its own reader.</summary>
        public TlsReader ReadNested(int length)
        {
            Require(length);
            var nested = new TlsReader(_buffer, Position, length);
            Position += length;
            return nested;
        }

        /// <summary>
        /// Reads an extensions block (uint16 length + extensions), creating each extension with
        /// <paramref name="factory"/>. Duplicate extension types are a decode_error.
        /// </summary>
        public List<ITlsExtension> ReadExtensions(Func<ushort, ITlsExtension> factory)
        {
            var extensions = new List<ITlsExtension>();
            if (IsEmpty)
                return extensions; // the extensions block is optional in hellos

            var block = ReadNested(ReadUInt16());
            var seen = new HashSet<ushort>();
            while (!block.IsEmpty)
            {
                int start = block.Position;
                ushort type = block.ReadUInt16();
                int length = block.ReadUInt16();
                block.ReadBytes(length);

                if (!seen.Add(type))
                    throw new DtlsException(AlertDescription.DecodeError, $"Duplicate extension 0x{type:X4}.");

                var extension = factory(type) ?? new UnknownExtension();
                int consumed = extension.Read(start, _buffer);
                if (consumed != 4 + length)
                    throw new DtlsException(AlertDescription.DecodeError, $"Malformed extension 0x{type:X4}.");
                extensions.Add(extension);
            }
            return extensions;
        }

        public void EnsureEnd()
        {
            if (!IsEmpty)
                throw new DtlsException(AlertDescription.DecodeError, "Trailing bytes in message.");
        }
    }

    /// <summary>
    /// Writer for TLS presentation-language structures.
    /// </summary>
    public sealed class TlsWriter
    {
        private byte[] _buffer = new byte[256];

        public int Length { get; private set; }

        private void Ensure(int count)
        {
            if (Length + count > _buffer.Length)
                Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, Length + count));
        }

        public TlsWriter WriteUInt8(int value) { Ensure(1); _buffer[Length++] = (byte)value; return this; }
        public TlsWriter WriteUInt16(int value) { Ensure(2); _buffer[Length++] = (byte)(value >> 8); _buffer[Length++] = (byte)value; return this; }
        public TlsWriter WriteUInt24(int value) { Ensure(3); _buffer[Length++] = (byte)(value >> 16); _buffer[Length++] = (byte)(value >> 8); _buffer[Length++] = (byte)value; return this; }
        public TlsWriter WriteUInt32(uint value) { WriteUInt16((int)(value >> 16)); return WriteUInt16((int)value); }

        public TlsWriter WriteBytes(byte[] data)
        {
            Ensure(data.Length);
            System.Buffer.BlockCopy(data, 0, _buffer, Length, data.Length);
            Length += data.Length;
            return this;
        }

        public TlsWriter WriteOpaque8(byte[] data)
        {
            if (data.Length > 0xFF) throw new ArgumentException("Too long for opaque<0..2^8-1>.");
            return WriteUInt8(data.Length).WriteBytes(data);
        }

        public TlsWriter WriteOpaque16(byte[] data)
        {
            if (data.Length > 0xFFFF) throw new ArgumentException("Too long for opaque<0..2^16-1>.");
            return WriteUInt16(data.Length).WriteBytes(data);
        }

        public TlsWriter WriteOpaque24(byte[] data) => WriteUInt24(data.Length).WriteBytes(data);

        public TlsWriter WriteUInt16List16(IReadOnlyCollection<ushort> values)
        {
            WriteUInt16(values.Count * 2);
            foreach (ushort v in values)
                WriteUInt16(v);
            return this;
        }

        /// <summary>Writes an extensions block; nothing is written when <paramref name="omitWhenEmpty"/> and the list is empty.</summary>
        public TlsWriter WriteExtensions(IReadOnlyCollection<ITlsExtension> extensions, bool omitWhenEmpty = false)
        {
            if (extensions.Count == 0 && omitWhenEmpty)
                return this;

            int total = 0;
            foreach (var extension in extensions)
                total += extension.CalculateLength();

            WriteUInt16(total);
            Ensure(total);
            foreach (var extension in extensions)
                Length += extension.Write(Length, _buffer);
            return this;
        }

        public byte[] ToArray() => _buffer.AsSpan(0, Length).ToArray();
    }
}
