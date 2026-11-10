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
    /// <summary>
    /// DTLS protocol version code points. DTLS versions count down: 1.0 = 0xFEFF, 1.2 = 0xFEFD, 1.3 = 0xFEFC.
    /// (DTLS 1.1 was never defined; DTLS 1.2 corresponds to TLS 1.2, DTLS 1.0 to TLS 1.1.)
    /// </summary>
    public static class DtlsVersion
    {
        public const ushort Dtls10 = 0xFEFF;
        public const ushort Dtls12 = 0xFEFD;
        public const ushort Dtls13 = 0xFEFC;

        /// <summary>True when <paramref name="version"/> is the same as or newer than <paramref name="minimum"/>.</summary>
        public static bool IsAtLeast(ushort version, ushort minimum) => version <= minimum;

        public static string Name(ushort version) => ProtocolVersions.Name(version);
    }
}
