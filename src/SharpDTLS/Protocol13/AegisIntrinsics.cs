#if NETSTANDARD2_0
// netstandard2.0 has no hardware intrinsics: the 16-byte block type and the (unsupported) AES instructions AEGIS is
// written against, so it runs its software AES round there.
using System;

namespace System.Runtime.Intrinsics
{
    /// <summary>16 bytes with the operations AEGIS uses; only byte elements are supported.</summary>
    internal readonly struct Vector128<T> where T : struct
    {
        internal readonly ulong Lower;
        internal readonly ulong Upper;

        internal Vector128(ulong lower, ulong upper)
        {
            Lower = lower;
            Upper = upper;
        }

        public static Vector128<T> Zero => default;

        public static Vector128<T> operator ^(Vector128<T> a, Vector128<T> b) => new(a.Lower ^ b.Lower, a.Upper ^ b.Upper);
        public static Vector128<T> operator &(Vector128<T> a, Vector128<T> b) => new(a.Lower & b.Lower, a.Upper & b.Upper);

        public void CopyTo(Span<byte> destination)
        {
            if (destination.Length < 16)
                throw new ArgumentException("The destination is shorter than 16 bytes.", nameof(destination));
            for (int i = 0; i < 8; i++)
            {
                destination[i] = (byte)(Lower >> (8 * i));
                destination[8 + i] = (byte)(Upper >> (8 * i));
            }
        }

        public void CopyTo(byte[] destination) => CopyTo(destination.AsSpan());
    }

    internal static class Vector128
    {
        public static Vector128<byte> Create(ReadOnlySpan<byte> values)
        {
            if (values.Length < 16)
                throw new ArgumentException("Fewer than 16 bytes.", nameof(values));
            ulong lower = 0, upper = 0;
            for (int i = 0; i < 8; i++)
            {
                lower |= (ulong)values[i] << (8 * i);
                upper |= (ulong)values[8 + i] << (8 * i);
            }
            return new Vector128<byte>(lower, upper);
        }

        public static Vector128<byte> Create(params byte[] values) => Create((ReadOnlySpan<byte>)values);
    }
}

namespace System.Runtime.Intrinsics.X86
{
    /// <summary>No hardware AES here: AEGIS uses its software round.</summary>
    internal static class Aes
    {
        public static bool IsSupported => false;
        public static Vector128<byte> Encrypt(Vector128<byte> value, Vector128<byte> roundKey) => throw new PlatformNotSupportedException();
    }
}

namespace System.Runtime.Intrinsics.Arm
{
    /// <summary>No hardware AES here: AEGIS uses its software round.</summary>
    internal static class Aes
    {
        public static bool IsSupported => false;
        public static Vector128<byte> Encrypt(Vector128<byte> value, Vector128<byte> roundKey) => throw new PlatformNotSupportedException();
        public static Vector128<byte> MixColumns(Vector128<byte> value) => throw new PlatformNotSupportedException();
    }
}
#endif
