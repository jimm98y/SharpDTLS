using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>
    /// What the peer said about the certificate it wants, for choosing credentials: the server_name (servers only),
    /// the CAs it trusts (certificate_authorities, RFC 8446 §4.2.4, or a DTLS 1.2 CertificateRequest's list) and the
    /// signature schemes it accepts in CertificateVerify and in certificates (signature_algorithms_cert, §4.2.3).
    /// </summary>
    public sealed class CertificateSelectionContext
    {
        internal CertificateSelectionContext(string serverName, IEnumerable<X509Name> certificateAuthorities,
            IReadOnlyList<ushort> signatureAlgorithms, IReadOnlyList<ushort> signatureAlgorithmsCert)
        {
            ServerName = serverName;
            CertificateAuthorities = certificateAuthorities?.ToList() ?? new List<X509Name>();
            SignatureAlgorithms = signatureAlgorithms;
            SignatureAlgorithmsCert = signatureAlgorithmsCert;
        }

        /// <summary>The host name the client asked for, or null (and always null for client credentials).</summary>
        public string ServerName { get; }

        /// <summary>Distinguished names of the CAs the peer trusts; empty when it named none.</summary>
        public IReadOnlyList<X509Name> CertificateAuthorities { get; }

        /// <summary>Signature schemes the peer accepts in CertificateVerify, or null when it did not say.</summary>
        public IReadOnlyList<ushort> SignatureAlgorithms { get; }

        /// <summary>Signature schemes the peer accepts in certificates, or null (then SignatureAlgorithms applies).</summary>
        public IReadOnlyList<ushort> SignatureAlgorithmsCert { get; }

        /// <summary>
        /// Whether <paramref name="credentials"/> chain up to a CA the peer named: some certificate in it is issued by, or
        /// is, one of <see cref="CertificateAuthorities"/>. True when the peer named none.
        /// </summary>
        public bool IsIssuedByAcceptedAuthority(CertificateCredentials credentials)
        {
            if (CertificateAuthorities.Count == 0)
                return true;
            var chain = new[] { credentials.Certificate }.Concat(credentials.IntermediateCertificates ?? Array.Empty<X509Certificate>());
            return chain.Any(c => CertificateAuthorities.Any(n => n.Equivalent(c.IssuerDN) || n.Equivalent(c.SubjectDN)));
        }

        internal static X509Name ParseName(byte[] der)
        {
            try
            {
                return X509Name.GetInstance(Asn1Object.FromByteArray(der));
            }
            catch (Exception ex)
            {
                throw new DtlsException(AlertDescription.DecodeError, "Invalid distinguished name.", ex);
            }
        }

        internal static IEnumerable<X509Name> ParseNames(IEnumerable<byte[]> names) => names?.Select(ParseName) ?? Enumerable.Empty<X509Name>();

        internal static List<byte[]> Encode(IEnumerable<X509Certificate> authorities)
            => authorities?.Select(c => c.SubjectDN.GetEncoded()).ToList() ?? new List<byte[]>();
    }

    /// <summary>certificate_authorities (RFC 8446 §4.2.4): DER distinguished names of the CAs the sender trusts.</summary>
    internal class CertificateAuthoritiesExtension : ITlsExtension
    {
        public const ushort Type = 47;

        public CertificateAuthoritiesExtension() { }

        public CertificateAuthoritiesExtension(IEnumerable<byte[]> names)
        {
            Names = names.ToList();
            if (Names.Count == 0)
                throw new ArgumentException("At least one name.", nameof(names));
        }

        public List<byte[]> Names { get; private set; } = new();

        private byte[] Body()
        {
            var list = new TlsWriter();
            foreach (byte[] name in Names)
                list.WriteOpaque16(name);
            return new TlsWriter().WriteOpaque16(list.ToArray()).ToArray();
        }

        public int CalculateLength() => 4 + Body().Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid certificate_authorities extension.");
            var outer = new TlsReader(source.AsSpan(offset + 4, length).ToArray());
            var list = new TlsReader(outer.ReadOpaque16());
            outer.EnsureEnd();
            Names = new List<byte[]>();
            while (list.Remaining > 0)
                Names.Add(list.ReadOpaque16());
            if (Names.Count == 0 || Names.Any(n => n.Length == 0))
                throw new DtlsException(AlertDescription.DecodeError, "Empty certificate_authorities.");
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            byte[] body = Body();
            new TlsWriter().WriteUInt16(Type).WriteOpaque16(body).ToArray().CopyTo(destination, offset);
            return 4 + body.Length;
        }
    }

    /// <summary>signature_algorithms_cert (RFC 8446 §4.2.3): the signature schemes the sender accepts in certificates.</summary>
    internal class SignatureAlgorithmsCertExtension : ITlsExtension
    {
        public const ushort Type = 50;

        public SignatureAlgorithmsCertExtension() { }

        public SignatureAlgorithmsCertExtension(IEnumerable<ushort> schemes)
        {
            Schemes = schemes.ToArray();
            if (Schemes.Length == 0)
                throw new ArgumentException("At least one scheme.", nameof(schemes));
        }

        public ushort[] Schemes { get; private set; } = Array.Empty<ushort>();

        public int CalculateLength() => 6 + 2 * Schemes.Length;

        public int Read(int offset, byte[] source)
        {
            int length = (source[offset + 2] << 8) | source[offset + 3];
            if (source.Length < offset + 4 + length)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid signature_algorithms_cert extension.");
            var reader = new TlsReader(source.AsSpan(offset + 4, length).ToArray());
            Schemes = reader.ReadUInt16List16();
            reader.EnsureEnd();
            if (Schemes.Length == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Empty signature_algorithms_cert.");
            return 4 + length;
        }

        public int Write(int offset, byte[] destination)
        {
            byte[] body = new TlsWriter().WriteUInt16List16(Schemes).ToArray();
            new TlsWriter().WriteUInt16(Type).WriteOpaque16(body).ToArray().CopyTo(destination, offset);
            return 4 + body.Length;
        }
    }
}
