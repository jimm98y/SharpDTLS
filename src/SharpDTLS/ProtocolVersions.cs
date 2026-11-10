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

namespace SharpDTLS
{
    /// <summary>TLS protocol version code points (RFC 2246, 4346, 5246, 8446). SSL 3.0 is prohibited (RFC 7568).</summary>
    public static class TlsVersion
    {
        public const ushort Tls10 = 0x0301;
        public const ushort Tls11 = 0x0302;
        public const ushort Tls12 = 0x0303;
        public const ushort Tls13 = 0x0304;
    }

    /// <summary>
    /// Version arithmetic across TLS and DTLS. DTLS code points count down and TLS ones up, so ordering is per family;
    /// <see cref="Level"/> gives the shared semantics (DTLS 1.0 is TLS 1.1, DTLS 1.2 is TLS 1.2).
    /// </summary>
    internal static class ProtocolVersions
    {
        public static bool IsDatagram(ushort version) => (version >> 8) == 0xFE;

        /// <summary>1 for TLS 1.0, 2 for TLS 1.1 / DTLS 1.0, 3 for (D)TLS 1.2, 4 for (D)TLS 1.3; 0 when unknown.</summary>
        public static int Level(ushort version) => version switch
        {
            TlsVersion.Tls10 => 1,
            TlsVersion.Tls11 or DtlsVersion.Dtls10 => 2,
            TlsVersion.Tls12 or DtlsVersion.Dtls12 => 3,
            TlsVersion.Tls13 or DtlsVersion.Dtls13 => 4,
            _ => 0,
        };

        /// <summary>
        /// True when <paramref name="version"/> is the same as or newer than <paramref name="minimum"/> of the same
        /// family (also for versions newer than any known one).
        /// </summary>
        public static bool IsAtLeast(ushort version, ushort minimum)
            => IsDatagram(version) == IsDatagram(minimum) && (IsDatagram(version) ? version <= minimum : version >= minimum);

        /// <summary>The (D)TLS 1.0-1.2 versions of a family, newest first.</summary>
        internal static ushort[] Legacy(bool datagram)
            => datagram ? new[] { DtlsVersion.Dtls12, DtlsVersion.Dtls10 } : new[] { TlsVersion.Tls12, TlsVersion.Tls11, TlsVersion.Tls10 };

        public static string Name(ushort version) => version switch
        {
            DtlsVersion.Dtls10 => "DTLS 1.0",
            DtlsVersion.Dtls12 => "DTLS 1.2",
            DtlsVersion.Dtls13 => "DTLS 1.3",
            TlsVersion.Tls10 => "TLS 1.0",
            TlsVersion.Tls11 => "TLS 1.1",
            TlsVersion.Tls12 => "TLS 1.2",
            TlsVersion.Tls13 => "TLS 1.3",
            _ => $"0x{version:X4}",
        };
    }
}
