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
    /// Key exchange groups (IANA TLS Supported Groups). TLS/DTLS 1.0-1.2 use the elliptic curves for ECDHE suites
    /// and the FFDHE groups for DHE suites; TLS/DTLS 1.3 use all of them, including ML-KEM and the hybrids.
    /// </summary>
    public static class NamedGroups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort Secp521r1 = 0x0019;
        public const ushort X25519 = 0x001d;
        public const ushort X448 = 0x001e;
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;
        public const ushort MlKem512 = 0x0200;
        public const ushort MlKem768 = 0x0201;
        public const ushort MlKem1024 = 0x0202;
        public const ushort SecP256r1MlKem768 = 0x11eb;
        public const ushort X25519MlKem768 = 0x11ec;
        public const ushort SecP384r1MlKem1024 = 0x11ed;
    }
}
