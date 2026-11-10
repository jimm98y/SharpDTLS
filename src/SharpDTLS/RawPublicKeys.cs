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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>Certificate types (RFC 7250 §3): what a Certificate message carries.</summary>
    public enum CertificateType : byte
    {
        X509 = 0,

        /// <summary>A bare SubjectPublicKeyInfo, authenticated out of band (e.g. a pinned key).</summary>
        RawPublicKey = 2,
    }

    /// <summary>
    /// client_certificate_type (19) and server_certificate_type (20), RFC 7250 §4: the client lists the types it supports
    /// in preference order; the server answers with the one it chose.
    /// </summary>
    internal class CertificateTypeExtension : ITlsExtension
    {
        public const ushort ClientType = 19;
        public const ushort ServerType = 20;

        public CertificateTypeExtension(ushort extensionType) => ExtensionType = extensionType;

        /// <summary>The client's list.</summary>
        public CertificateTypeExtension(ushort extensionType, IEnumerable<CertificateType> types) : this(extensionType)
        {
            Types = types.ToList();
            if (Types.Count == 0 || Types.Count > 255)
                throw new ArgumentException("One to 255 certificate types.", nameof(types));
        }

        /// <summary>The server's choice.</summary>
        public CertificateTypeExtension(ushort extensionType, CertificateType selected) : this(extensionType)
        {
            Types = new[] { selected };
            IsSelection = true;
        }

        public ushort ExtensionType { get; }
        public IReadOnlyList<CertificateType> Types { get; private set; } = Array.Empty<CertificateType>();
        public bool IsSelection { get; private set; }
        public CertificateType Selected => Types[0];

        public int CalculateLength() => 4 + (IsSelection ? 1 : 1 + Types.Count);

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (length == 0 || source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate type extension.");
            IsSelection = length == 1;
            if (!IsSelection && source[offset + 4] != length - 1)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate type list.");
            Types = source.AsSpan(offset + 4 + (IsSelection ? 0 : 1), IsSelection ? 1 : length - 1).ToArray().Select(t => (CertificateType)t).ToList();
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            int length = CalculateLength() - 4;
            destination[offset] = (byte)(ExtensionType >> 8);
            destination[offset + 1] = (byte)ExtensionType;
            destination[offset + 2] = 0;
            destination[offset + 3] = (byte)length;
            int pos = offset + 4;
            if (!IsSelection)
                destination[pos++] = (byte)Types.Count;
            foreach (var type in Types)
                destination[pos++] = (byte)type;
            return 4 + length;
        }
    }

    /// <summary>Certificate type negotiation and raw public key encoding (RFC 7250).</summary>
    internal static class RawPublicKeys
    {
        /// <summary>The client_certificate_type or server_certificate_type extension among <paramref name="extensions"/>.</summary>
        public static CertificateTypeExtension Find(IEnumerable<ITlsExtension> extensions, ushort extensionType)
            => extensions.OfType<CertificateTypeExtension>().FirstOrDefault(e => e.ExtensionType == extensionType);

        public static CertificateTypeExtension Offer(ushort extensionType, IList<CertificateType> types)
            => types == null ? null : new CertificateTypeExtension(extensionType, types);

        /// <summary>
        /// The server's choice: its first preferred type the client offered and it can use; X.509 when the client sent no
        /// list (if usable). Null when there is none, which rules out authentication of that side.
        /// </summary>
        public static CertificateType? Choose(IList<CertificateType> preference, CertificateTypeExtension offered, Func<CertificateType, bool> usable)
        {
            var offeredTypes = offered?.Types ?? new[] { CertificateType.X509 };
            foreach (var type in preference ?? new[] { CertificateType.X509 })
            {
                if (offeredTypes.Contains(type) && usable(type))
                    return type;
            }
            return null;
        }

        /// <summary>
        /// The type the server chose from our <paramref name="offered"/> list; without an answer it is X.509, which
        /// <paramref name="requireSupport"/> rejects when we did not offer it.
        /// </summary>
        public static CertificateType Accept(IList<CertificateType> offered, CertificateTypeExtension selection, bool requireSupport)
        {
            if (selection == null)
            {
                if (requireSupport && offered != null && !offered.Contains(CertificateType.X509))
                    throw new DtlsException(AlertDescription.UnsupportedCertificate, "The server did not agree to a raw public key.");
                return CertificateType.X509;
            }
            if (offered == null)
                throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited certificate type extension.");
            if (!selection.IsSelection || !offered.Contains(selection.Selected))
                throw new DtlsException(AlertDescription.IllegalParameter, $"The server chose certificate type {selection.Types.FirstOrDefault()}, which was not offered.");
            return selection.Selected;
        }

        /// <summary>The DER SubjectPublicKeyInfo of <paramref name="publicKey"/>.</summary>
        public static byte[] Encode(AsymmetricKeyParameter publicKey)
            => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetEncoded();

        public static AsymmetricKeyParameter Decode(byte[] subjectPublicKeyInfo)
        {
            try
            {
                return PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
            }
            catch (Exception ex)
            {
                throw new DtlsException(AlertDescription.BadCertificate, "The raw public key could not be parsed.", ex);
            }
        }

        /// <summary>A DTLS 1.0/1.2 Certificate body with a raw public key (RFC 7250 §3): one opaque&lt;1..2^24-1&gt;, or empty.</summary>
        public static byte[] EncodeCertificate(byte[] subjectPublicKeyInfo)
            => new TlsWriter().WriteOpaque24(subjectPublicKeyInfo ?? Array.Empty<byte>()).ToArray();

        /// <summary>The SubjectPublicKeyInfo in a DTLS 1.0/1.2 raw public key Certificate body, or null when empty.</summary>
        public static byte[] DecodeCertificate(byte[] body)
        {
            var reader = new TlsReader(body);
            byte[] key = reader.ReadOpaque24();
            reader.EnsureEnd();
            return key.Length == 0 ? null : key;
        }
    }
}
