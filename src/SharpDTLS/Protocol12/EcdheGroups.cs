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

using System;
using System.Linq;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// (EC)DHE named groups (RFC 8422, RFC 8446 §4.2.7). Private keys are opaque byte arrays:
    /// the raw scalar for X25519, the big-endian scalar for NIST curves.
    /// </summary>
    internal static class EcdheGroups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort X25519    = 0x001d;

        /// <summary>Implemented groups in preference order.</summary>
        public static readonly ushort[] Supported = { X25519, Secp256r1, Secp384r1 };

        public static bool IsSupported(ushort group) => Supported.Contains(group);




    }
}
