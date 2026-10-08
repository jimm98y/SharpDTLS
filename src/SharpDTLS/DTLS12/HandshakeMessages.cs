using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.DTLS12
{
    /// <summary>Handshake message types (RFC 5246 §7.4, RFC 6347 §4.2.1, RFC 5077).</summary>
    public static class HandshakeType
    {
        public const byte HelloRequest = 0;
        public const byte ClientHello = 1;
        public const byte ServerHello = 2;
        public const byte HelloVerifyRequest = 3;
        public const byte NewSessionTicket = 4;
        public const byte Certificate = 11;
        public const byte ServerKeyExchange = 12;
        public const byte CertificateRequest = 13;
        public const byte ServerHelloDone = 14;
        public const byte CertificateVerify = 15;
        public const byte ClientKeyExchange = 16;
        public const byte Finished = 20;
    }

    /// <summary>Extension factories for the hello messages.</summary>
    internal static class HelloExtensions
    {
        public static ITlsExtension ForClientHello(ushort type) => type switch
        {
            0x000a => new SupportedGroupsExtension(),
            0x000b => new EcPointFormatsExtension(),
            0x000d => new SignatureAlgorithmsExtension(),
            0x000e => new UseSrtpExtension(),
            SrpExtension.Type => new SrpExtension(),
            PwdClearExtension.Type => new PwdClearExtension(),
            0x0016 => new EncryptThenMacExtension(),
            ExtendedMasterSecretExtension.Type => new ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension.Type => new RenegotiationInfoExtension(),
            _ => null,
        };

        public static ITlsExtension ForServerHello(ushort type) => type switch
        {
            0x000b => new ServerEcPointFormatsExtension(),
            0x000e => new ServerUseSrtpExtension(),
            0x0016 => new EncryptThenMacExtension(),
            ExtendedMasterSecretExtension.Type => new ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension.Type => new RenegotiationInfoExtension(),
            _ => null,
        };
    }

    public sealed class ClientHelloMessage
    {
        public ushort ClientVersion { get; set; } = DtlsVersion.Dtls12;
        public byte[] Random { get; set; }
        public byte[] SessionId { get; set; } = Array.Empty<byte>();
        public byte[] Cookie { get; set; } = Array.Empty<byte>();
        public List<ushort> CipherSuites { get; set; } = new List<ushort>();
        public byte[] CompressionMethods { get; set; } = { 0 };
        public List<ITlsExtension> Extensions { get; set; } = new List<ITlsExtension>();

        public T Extension<T>() where T : class, ITlsExtension => Extensions.OfType<T>().FirstOrDefault();

        public byte[] Encode() => new TlsWriter()
            .WriteUInt16(ClientVersion)
            .WriteBytes(Random)
            .WriteOpaque8(SessionId)
            .WriteOpaque8(Cookie)
            .WriteUInt16List16(CipherSuites)
            .WriteOpaque8(CompressionMethods)
            .WriteExtensions(Extensions, omitWhenEmpty: true)
            .ToArray();

        public static ClientHelloMessage Decode(byte[] body)
        {
            var r = new TlsReader(body);
            var m = new ClientHelloMessage
            {
                ClientVersion = r.ReadUInt16(),
                Random = r.ReadBytes(32),
                SessionId = r.ReadOpaque8(),
                Cookie = r.ReadOpaque8(),
                CipherSuites = r.ReadUInt16List16().ToList(),
                CompressionMethods = r.ReadOpaque8(),
            };
            if (m.SessionId.Length > 32 || m.CipherSuites.Count == 0 || m.CompressionMethods.Length == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Invalid ClientHello.");
            m.Extensions = r.ReadExtensions(HelloExtensions.ForClientHello);
            r.EnsureEnd();
            return m;
        }
    }

    public sealed class HelloVerifyRequestMessage
    {
        public ushort ServerVersion { get; set; } = DtlsVersion.Dtls10;
        public byte[] Cookie { get; set; }

        public byte[] Encode() => new TlsWriter().WriteUInt16(ServerVersion).WriteOpaque8(Cookie).ToArray();

        public static HelloVerifyRequestMessage Decode(byte[] body)
        {
            var r = new TlsReader(body);
            var m = new HelloVerifyRequestMessage { ServerVersion = r.ReadUInt16(), Cookie = r.ReadOpaque8() };
            r.EnsureEnd();
            return m;
        }
    }

    public sealed class ServerHelloMessage
    {
        public ushort ServerVersion { get; set; }
        public byte[] Random { get; set; }
        public byte[] SessionId { get; set; } = Array.Empty<byte>();
        public ushort CipherSuite { get; set; }
        public byte CompressionMethod { get; set; }
        public List<ITlsExtension> Extensions { get; set; } = new List<ITlsExtension>();

        public T Extension<T>() where T : class, ITlsExtension => Extensions.OfType<T>().FirstOrDefault();

        public byte[] Encode() => new TlsWriter()
            .WriteUInt16(ServerVersion)
            .WriteBytes(Random)
            .WriteOpaque8(SessionId)
            .WriteUInt16(CipherSuite)
            .WriteUInt8(CompressionMethod)
            .WriteExtensions(Extensions, omitWhenEmpty: true)
            .ToArray();

        public static ServerHelloMessage Decode(byte[] body)
        {
            var r = new TlsReader(body);
            var m = new ServerHelloMessage
            {
                ServerVersion = r.ReadUInt16(),
                Random = r.ReadBytes(32),
                SessionId = r.ReadOpaque8(),
                CipherSuite = r.ReadUInt16(),
                CompressionMethod = r.ReadUInt8(),
            };
            m.Extensions = r.ReadExtensions(HelloExtensions.ForServerHello);
            r.EnsureEnd();
            return m;
        }
    }

    public sealed class CertificateMessage
    {
        public List<byte[]> Chain { get; set; } = new List<byte[]>();

        public byte[] Encode()
        {
            var list = new TlsWriter();
            foreach (var cert in Chain)
                list.WriteOpaque24(cert);
            return new TlsWriter().WriteOpaque24(list.ToArray()).ToArray();
        }

        public static CertificateMessage Decode(byte[] body)
        {
            var r = new TlsReader(body);
            var list = r.ReadNested(r.ReadUInt24());
            r.EnsureEnd();
            var m = new CertificateMessage();
            while (!list.IsEmpty)
            {
                byte[] cert = list.ReadOpaque24();
                if (cert.Length == 0)
                    throw new DtlsException(AlertDescription.DecodeError, "Empty certificate entry.");
                m.Chain.Add(cert);
            }
            return m;
        }
    }

    public sealed class CertificateRequestMessage
    {
        public byte[] CertificateTypes { get; set; } = { 1, 2, 64 }; // rsa_sign, dss_sign, ecdsa_sign
        public ushort[] SignatureAlgorithms { get; set; } = Dtls12Signatures.Supported;
        public List<byte[]> CertificateAuthorities { get; set; } = new List<byte[]>();

        public byte[] Encode(ushort version)
        {
            var w = new TlsWriter().WriteOpaque8(CertificateTypes);
            if (version == DtlsVersion.Dtls12)
                w.WriteUInt16List16(SignatureAlgorithms);
            var authorities = new TlsWriter();
            foreach (var dn in CertificateAuthorities)
                authorities.WriteOpaque16(dn);
            return w.WriteOpaque16(authorities.ToArray()).ToArray();
        }

        public static CertificateRequestMessage Decode(byte[] body, ushort version)
        {
            var r = new TlsReader(body);
            var m = new CertificateRequestMessage { CertificateTypes = r.ReadOpaque8() };
            m.SignatureAlgorithms = version == DtlsVersion.Dtls12 ? r.ReadUInt16List16() : null;
            var authorities = r.ReadNested(r.ReadUInt16());
            while (!authorities.IsEmpty)
                m.CertificateAuthorities.Add(authorities.ReadOpaque16());
            r.EnsureEnd();
            return m;
        }
    }

    public sealed class CertificateVerifyMessage
    {
        public ushort? SignatureScheme { get; set; }
        public byte[] Signature { get; set; }

        public byte[] Encode(ushort version)
        {
            var w = new TlsWriter();
            if (version == DtlsVersion.Dtls12)
                w.WriteUInt16(SignatureScheme.Value);
            return w.WriteOpaque16(Signature).ToArray();
        }

        public static CertificateVerifyMessage Decode(byte[] body, ushort version)
        {
            var r = new TlsReader(body);
            var m = new CertificateVerifyMessage();
            if (version == DtlsVersion.Dtls12)
                m.SignatureScheme = r.ReadUInt16();
            m.Signature = r.ReadOpaque16();
            r.EnsureEnd();
            return m;
        }
    }

    public sealed class NewSessionTicketMessage
    {
        public uint LifetimeHint { get; set; }
        public byte[] Ticket { get; set; } = Array.Empty<byte>();

        public byte[] Encode() => new TlsWriter().WriteUInt32(LifetimeHint).WriteOpaque16(Ticket).ToArray();

        public static NewSessionTicketMessage Decode(byte[] body)
        {
            var r = new TlsReader(body);
            var m = new NewSessionTicketMessage { LifetimeHint = r.ReadUInt32(), Ticket = r.ReadOpaque16() };
            r.EnsureEnd();
            return m;
        }
    }
}
