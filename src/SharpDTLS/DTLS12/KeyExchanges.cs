using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SharpDTLS.DTLS12.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS12
{
    /// <summary>Server half of a key exchange.</summary>
    internal interface IServerKeyExchange
    {
        /// <summary>ServerKeyExchange parameters, or null when this key exchange sends no ServerKeyExchange.</summary>
        byte[] CreateServerParams();

        /// <summary>Whether the parameters are signed with the server certificate's key.</summary>
        bool SignsParams { get; }

        /// <summary>Processes the ClientKeyExchange body and returns the premaster secret.</summary>
        byte[] ProcessClientKeyExchange(byte[] body);

        /// <summary>The negotiated (EC)DH group, or 0.</summary>
        ushort Group { get; }

        /// <summary>
        /// Fixed (EC)DH client authentication (RFC 5246 §7.4.7.2, RFC 8422 §3): the ClientKeyExchange was
        /// empty and the client's certificate key is its key agreement key.
        /// </summary>
        byte[] ProcessFixedClientKeyExchange(AsymmetricKeyParameter clientPublicKey)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "Fixed (EC)DH client authentication needs a static (EC)DH suite.");
    }

    internal enum ServerKeyExchangeRequirement
    {
        None,
        /// <summary>PSK and RSA_PSK: sent only when the server has an identity hint (RFC 4279 §2).</summary>
        Optional,
        Required,
    }

    /// <summary>Client half of a key exchange.</summary>
    internal interface IClientKeyExchange
    {
        ServerKeyExchangeRequirement ServerKeyExchange { get; }
        bool ServerParamsSigned { get; }

        /// <summary>Reads the parameters from the start of the ServerKeyExchange body.</summary>
        void ReadServerParams(TlsReader reader);

        /// <summary>Builds the ClientKeyExchange body and returns the premaster secret.</summary>
        byte[] CreateClientKeyExchange(out byte[] preMasterSecret);

        ushort Group { get; }

        /// <summary>Whether <paramref name="clientKey"/> can be used for fixed (EC)DH client authentication.</summary>
        bool SupportsFixedClientKey(AsymmetricKeyParameter clientKey) => false;

        /// <summary>Fixed (EC)DH: the premaster secret from the client's static key; the ClientKeyExchange is empty.</summary>
        byte[] CreateFixedClientKeyExchange(AsymmetricKeyParameter clientPrivateKey, out byte[] preMasterSecret)
            => throw new DtlsException(AlertDescription.InternalError, "Fixed (EC)DH client authentication needs a static (EC)DH suite.");
    }

    internal sealed class ServerKeyExchangeContext
    {
        public ClientHelloMessage ClientHello { get; init; }
        public AsymmetricKeyParameter ServerPrivateKey { get; init; }
        public byte[] PskIdentityHint { get; init; }
        public Func<byte[], byte[]> PskResolver { get; init; }
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get; init; }
        public Func<string, PwdCredential> PwdCredentialProvider { get; init; }
        public ECPrivateKeyParameters PwdProtectionKey { get; init; }

        /// <summary>ClientHello.random | ServerHello.random, once both are known (TLS-PWD hunting and pecking).</summary>
        public Func<byte[]> PwdContext { get; init; }
    }

    internal sealed class ClientKeyExchangeContext
    {
        public ushort ClientHelloVersion { get; init; }
        public AsymmetricKeyParameter ServerPublicKey { get; init; }
        public int MinimumDhPrimeBits { get; init; }

        /// <summary>Maps the server's identity hint (possibly empty) to the PSK identity and key.</summary>
        public Func<byte[], (byte[] Identity, byte[] Key)> PskProvider { get; init; }

        public byte[] SrpIdentity { get; init; }
        public byte[] SrpPassword { get; init; }

        public string PwdUsername { get; init; }
        public string PwdPassword { get; init; }

        /// <summary>ClientHello.random | ServerHello.random (TLS-PWD hunting and pecking).</summary>
        public Func<byte[]> PwdContext { get; init; }
    }

    internal static class KeyExchanges
    {
        public static IServerKeyExchange CreateServer(CipherSuiteInfo suite, ServerKeyExchangeContext context) => suite.KeyExchange switch
        {
            KeyExchangeAlgorithm.ECDHE_ECDSA or KeyExchangeAlgorithm.ECDHE_RSA => new EcdheServerKeyExchange(context),
            KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_DSS => new DheServerKeyExchange(context),
            KeyExchangeAlgorithm.RSA => new RsaServerKeyExchange(context),
            KeyExchangeAlgorithm.PSK => new PskServerKeyExchange(context, null),
            KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE => new PskServerKeyExchange(context, new DheServerKeyExchange(context)),
            KeyExchangeAlgorithm.ECDHE_PSK => new PskServerKeyExchange(context, new EcdheServerKeyExchange(context)),
            KeyExchangeAlgorithm.RSA_PSK => new PskServerKeyExchange(context, new RsaServerKeyExchange(context)),
            KeyExchangeAlgorithm.DH_anon => new DheServerKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.ECDH_anon => new EcdheServerKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.DH_DSS or KeyExchangeAlgorithm.DH_RSA => new StaticDhServerKeyExchange(context),
            KeyExchangeAlgorithm.ECDH_ECDSA or KeyExchangeAlgorithm.ECDH_RSA => new StaticEcdhServerKeyExchange(context),
            KeyExchangeAlgorithm.SRP_SHA => new SrpServerKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.SRP_SHA_RSA or KeyExchangeAlgorithm.SRP_SHA_DSS => new SrpServerKeyExchange(context, signed: true),
            KeyExchangeAlgorithm.ECCPWD => new EccPwdServerKeyExchange(context, suite),
            _ => throw new DtlsException(AlertDescription.InternalError, $"Key exchange {suite.KeyExchange} is not implemented."),
        };

        public static IClientKeyExchange CreateClient(CipherSuiteInfo suite, ClientKeyExchangeContext context) => suite.KeyExchange switch
        {
            KeyExchangeAlgorithm.ECDHE_ECDSA or KeyExchangeAlgorithm.ECDHE_RSA => new EcdheClientKeyExchange(),
            KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_DSS => new DheClientKeyExchange(context),
            KeyExchangeAlgorithm.RSA => new RsaClientKeyExchange(context),
            KeyExchangeAlgorithm.PSK => new PskClientKeyExchange(context, null),
            KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE => new PskClientKeyExchange(context, new DheClientKeyExchange(context)),
            KeyExchangeAlgorithm.ECDHE_PSK => new PskClientKeyExchange(context, new EcdheClientKeyExchange()),
            KeyExchangeAlgorithm.RSA_PSK => new PskClientKeyExchange(context, new RsaClientKeyExchange(context)),
            KeyExchangeAlgorithm.DH_anon => new DheClientKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.ECDH_anon => new EcdheClientKeyExchange(signed: false),
            KeyExchangeAlgorithm.DH_DSS or KeyExchangeAlgorithm.DH_RSA => new StaticDhClientKeyExchange(context),
            KeyExchangeAlgorithm.ECDH_ECDSA or KeyExchangeAlgorithm.ECDH_RSA => new StaticEcdhClientKeyExchange(context),
            KeyExchangeAlgorithm.SRP_SHA => new SrpClientKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.SRP_SHA_RSA or KeyExchangeAlgorithm.SRP_SHA_DSS => new SrpClientKeyExchange(context, signed: true),
            KeyExchangeAlgorithm.ECCPWD => new EccPwdClientKeyExchange(context, suite),
            _ => throw new DtlsException(AlertDescription.InternalError, $"Key exchange {suite.KeyExchange} is not implemented."),
        };
    }

    // ── ECDHE (RFC 8422) ─────────────────────────────────────────────────────────────────────

    internal sealed class EcdheServerKeyExchange : IServerKeyExchange
    {
        private byte[] _privateKey;

        public EcdheServerKeyExchange(ServerKeyExchangeContext context, bool signed = true)
        {
            SignsParams = signed;
            // RFC 8422 §5.1.1: without supported_groups the client is assumed to support any curve.
            var groups = context.ClientHello.Extension<SupportedGroupsExtension>();
            Group = groups == null ? EcdheGroups.X25519 : EcdheGroups.Supported.FirstOrDefault(g => groups.Groups.Contains(g));
            if (Group == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No elliptic curve in common.");
        }

        public ushort Group { get; }
        public bool SignsParams { get; }

        // ServerECDHParams: curve_type(3 = named_curve) || named_curve || point<1..255>
        public byte[] CreateServerParams()
        {
            (_privateKey, byte[] publicKey) = EcdheGroups.GenerateKeyPair(Group);
            return new TlsWriter().WriteUInt8(3).WriteUInt16(Group).WriteOpaque8(publicKey).ToArray();
        }

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] clientPublicKey = r.ReadOpaque8();
            r.EnsureEnd();
            return EcdheGroups.Agree(Group, _privateKey, clientPublicKey);
        }
    }

    internal sealed class EcdheClientKeyExchange : IClientKeyExchange
    {
        private byte[] _serverPublicKey;

        public EcdheClientKeyExchange(bool signed = true) => ServerParamsSigned = signed;

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.Required;
        public bool ServerParamsSigned { get; }
        public ushort Group { get; private set; }

        public void ReadServerParams(TlsReader reader)
        {
            if (reader.ReadUInt8() != 3)
                throw new DtlsException(AlertDescription.IllegalParameter, "Only named curves are supported.");
            Group = reader.ReadUInt16();
            if (!EcdheGroups.IsSupported(Group))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server selected curve 0x{Group:X4}, which was not offered.");
            _serverPublicKey = reader.ReadOpaque8();
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var (privateKey, publicKey) = EcdheGroups.GenerateKeyPair(Group);
            preMasterSecret = EcdheGroups.Agree(Group, privateKey, _serverPublicKey);
            return new TlsWriter().WriteOpaque8(publicKey).ToArray();
        }
    }

    // ── Finite-field DHE (RFC 5246 §7.4.3, RFC 7919) ─────────────────────────────────────────

    /// <summary>The RFC 7919 FFDHE groups.</summary>
    public static class FfdheGroups
    {
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;

        /// <summary>Groups in preference order (smallest first: all are considered secure, and they are faster).</summary>
        public static readonly ushort[] Supported = { Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192 };

        public static DHParameters Parameters(ushort group) => group switch
        {
            Ffdhe2048 => DHStandardGroups.rfc7919_ffdhe2048,
            Ffdhe3072 => DHStandardGroups.rfc7919_ffdhe3072,
            Ffdhe4096 => DHStandardGroups.rfc7919_ffdhe4096,
            Ffdhe6144 => DHStandardGroups.rfc7919_ffdhe6144,
            Ffdhe8192 => DHStandardGroups.rfc7919_ffdhe8192,
            _ => throw new ArgumentOutOfRangeException(nameof(group)),
        };

        /// <summary>The named group whose prime and generator match, or 0 for custom parameters.</summary>
        public static ushort Identify(BigInteger p, BigInteger g)
            => Supported.FirstOrDefault(id => Parameters(id).P.Equals(p) && Parameters(id).G.Equals(g));
    }

    internal static class DhUtilities
    {
        public static (BigInteger PrivateX, BigInteger PublicY) GenerateKeyPair(DHParameters parameters)
        {
            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
            var pair = generator.GenerateKeyPair();
            return (((DHPrivateKeyParameters)pair.Private).X, ((DHPublicKeyParameters)pair.Public).Y);
        }

        /// <summary>Z = Y^x mod p with leading zero bytes stripped (RFC 5246 §8.1.2). Rejects Y outside 1 &lt; Y &lt; p-1.</summary>
        public static byte[] Agree(DHParameters parameters, BigInteger privateX, BigInteger peerY)
        {
            if (peerY.CompareTo(BigInteger.One) <= 0 || peerY.CompareTo(parameters.P.Subtract(BigInteger.One)) >= 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid Diffie-Hellman public value.");

            var agreement = new DHBasicAgreement();
            agreement.Init(new DHPrivateKeyParameters(privateX, parameters));
            BigInteger z = agreement.CalculateAgreement(new DHPublicKeyParameters(peerY, parameters));
            if (z.Equals(BigInteger.One))
                throw new DtlsException(AlertDescription.IllegalParameter, "Degenerate Diffie-Hellman shared secret.");
            return z.ToByteArrayUnsigned();
        }
    }

    internal sealed class DheServerKeyExchange : IServerKeyExchange
    {
        private readonly DHParameters _parameters;
        private BigInteger _privateX;

        public DheServerKeyExchange(ServerKeyExchangeContext context, bool signed = true)
        {
            SignsParams = signed;
            // RFC 7919 §4: use a named group the client lists; otherwise ffdhe2048, which any DHE client accepts.
            var groups = context.ClientHello.Extension<SupportedGroupsExtension>()?.Groups ?? Array.Empty<ushort>();
            Group = FfdheGroups.Supported.FirstOrDefault(g => groups.Contains(g));
            if (Group == 0)
                Group = FfdheGroups.Ffdhe2048;
            _parameters = FfdheGroups.Parameters(Group);
        }

        public ushort Group { get; }
        public bool SignsParams { get; }

        // ServerDHParams: dh_p<1..2^16-1> || dh_g<1..2^16-1> || dh_Ys<1..2^16-1>
        public byte[] CreateServerParams()
        {
            (_privateX, BigInteger publicY) = DhUtilities.GenerateKeyPair(_parameters);
            return new TlsWriter()
                .WriteOpaque16(_parameters.P.ToByteArrayUnsigned())
                .WriteOpaque16(_parameters.G.ToByteArrayUnsigned())
                .WriteOpaque16(publicY.ToByteArrayUnsigned())
                .ToArray();
        }

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            var clientY = new BigInteger(1, r.ReadOpaque16());
            r.EnsureEnd();
            return DhUtilities.Agree(_parameters, _privateX, clientY);
        }
    }

    internal sealed class DheClientKeyExchange : IClientKeyExchange
    {
        private readonly int _minimumPrimeBits;
        private DHParameters _parameters;
        private BigInteger _serverY;

        public DheClientKeyExchange(ClientKeyExchangeContext context, bool signed = true)
        {
            _minimumPrimeBits = context.MinimumDhPrimeBits;
            ServerParamsSigned = signed;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.Required;
        public bool ServerParamsSigned { get; }
        public ushort Group { get; private set; }

        public void ReadServerParams(TlsReader reader)
        {
            var p = new BigInteger(1, reader.ReadOpaque16());
            var g = new BigInteger(1, reader.ReadOpaque16());
            _serverY = new BigInteger(1, reader.ReadOpaque16());

            if (p.BitLength < _minimumPrimeBits)
                throw new DtlsException(AlertDescription.InsufficientSecurity, $"Diffie-Hellman prime of {p.BitLength} bits is too small.");
            if (!p.TestBit(0) || g.CompareTo(BigInteger.One) <= 0 || g.CompareTo(p.Subtract(BigInteger.One)) >= 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid Diffie-Hellman parameters.");

            // Named groups are known safe primes; custom primes are accepted as sent (as most TLS stacks do).
            Group = FfdheGroups.Identify(p, g);
            _parameters = Group != 0 ? FfdheGroups.Parameters(Group) : new DHParameters(p, g);
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var (x, y) = DhUtilities.GenerateKeyPair(_parameters);
            preMasterSecret = DhUtilities.Agree(_parameters, x, _serverY);
            return new TlsWriter().WriteOpaque16(y.ToByteArrayUnsigned()).ToArray();
        }
    }

    // ── RSA key transport (RFC 5246 §7.4.7.1) ────────────────────────────────────────────────

    internal sealed class RsaServerKeyExchange : IServerKeyExchange
    {
        private readonly ServerKeyExchangeContext _context;

        public RsaServerKeyExchange(ServerKeyExchangeContext context)
        {
            _context = context;
            if (context.ServerPrivateKey is not RsaKeyParameters)
                throw new DtlsException(AlertDescription.InternalError, "RSA key exchange needs an RSA certificate.");
        }

        public ushort Group => 0;
        public bool SignsParams => false;
        public byte[] CreateServerParams() => null;

        /// <summary>
        /// Decrypts EncryptedPreMasterSecret. Padding errors, a wrong length and a wrong version all yield a
        /// random premaster secret without any observable difference (Bleichenbacher countermeasure,
        /// RFC 5246 §7.4.7.1); the handshake then fails at Finished.
        /// </summary>
        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] encrypted = r.ReadOpaque16();
            r.EnsureEnd();

            byte[] random = new byte[48];
            RandomNumberGenerator.Fill(random);

            // Pkcs1Encoding with a fallback returns the fallback, in constant time, on any decoding failure.
            var rsa = new Pkcs1Encoding(new RsaBlindedEngine(), random);
            rsa.Init(false, _context.ServerPrivateKey);
            byte[] decrypted;
            try
            {
                decrypted = rsa.ProcessBlock(encrypted, 0, encrypted.Length);
            }
            catch (InvalidCipherTextException)
            {
                decrypted = random;
            }

            ushort version = _context.ClientHello.ClientVersion;
            int versionOk = decrypted.Length == 48 && decrypted[0] == (byte)(version >> 8) && decrypted[1] == (byte)version ? 1 : 0;

            byte[] result = new byte[48];
            for (int i = 0; i < 48; i++)
            {
                byte d = decrypted.Length == 48 ? decrypted[i] : (byte)0;
                result[i] = (byte)((d & -versionOk) | (random[i] & (versionOk - 1)));
            }
            return result;
        }
    }

    internal sealed class RsaClientKeyExchange : IClientKeyExchange
    {
        private readonly ClientKeyExchangeContext _context;

        public RsaClientKeyExchange(ClientKeyExchangeContext context)
        {
            _context = context;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.None;
        public bool ServerParamsSigned => false;
        public ushort Group => 0;

        public void ReadServerParams(TlsReader reader)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "RSA key exchange has no ServerKeyExchange.");

        // PreMasterSecret = client_version (from ClientHello) || random[46], RSA PKCS #1 v1.5 encrypted.
        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            if (_context.ServerPublicKey is not RsaKeyParameters key)
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "RSA key exchange needs an RSA server certificate.");

            preMasterSecret = new byte[48];
            RandomNumberGenerator.Fill(preMasterSecret);
            preMasterSecret[0] = (byte)(_context.ClientHelloVersion >> 8);
            preMasterSecret[1] = (byte)_context.ClientHelloVersion;

            var rsa = new Pkcs1Encoding(new RsaBlindedEngine());
            rsa.Init(true, new ParametersWithRandom(key, new SecureRandom()));
            return new TlsWriter().WriteOpaque16(rsa.ProcessBlock(preMasterSecret, 0, preMasterSecret.Length)).ToArray();
        }
    }

    // ── Pre-shared keys (RFC 4279, RFC 5489) ─────────────────────────────────────────────────

    internal static class Psk
    {
        /// <summary>premaster_secret = other_secret&lt;0..2^16-1&gt; || psk&lt;0..2^16-1&gt; (RFC 4279 §2).</summary>
        public static byte[] PreMasterSecret(byte[] otherSecret, byte[] psk)
            => new TlsWriter().WriteOpaque16(otherSecret).WriteOpaque16(psk).ToArray();
    }

    /// <summary>
    /// PSK key exchanges. <c>inner</c> is the (EC)DHE or RSA exchange that supplies other_secret, or null for
    /// plain PSK, where other_secret is psk.Length zero bytes.
    /// </summary>
    internal sealed class PskServerKeyExchange : IServerKeyExchange
    {
        private readonly ServerKeyExchangeContext _context;
        private readonly IServerKeyExchange _inner;

        public PskServerKeyExchange(ServerKeyExchangeContext context, IServerKeyExchange inner)
        {
            if (context.PskResolver == null)
                throw new DtlsException(AlertDescription.InternalError, "No PSK resolver configured.");
            _context = context;
            _inner = inner;
        }

        public ushort Group => _inner?.Group ?? 0;
        public bool SignsParams => false;

        // psk_identity_hint<0..2^16-1> [|| ServerDHParams / ServerECDHParams]
        public byte[] CreateServerParams()
        {
            byte[] hint = _context.PskIdentityHint ?? Array.Empty<byte>();
            byte[] innerParams = _inner?.CreateServerParams();

            // RFC 4279 §2: plain PSK and RSA_PSK send ServerKeyExchange only when there is a hint.
            if (innerParams == null && hint.Length == 0)
                return null;

            var w = new TlsWriter().WriteOpaque16(hint);
            if (innerParams != null)
                w.WriteBytes(innerParams);
            return w.ToArray();
        }

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] identity = r.ReadOpaque16();
            byte[] psk = _context.PskResolver(identity)
                ?? throw new DtlsException(AlertDescription.UnknownPskIdentity, "Unknown PSK identity.");

            byte[] otherSecret = _inner == null
                ? new byte[psk.Length]
                : _inner.ProcessClientKeyExchange(r.ReadBytes(r.Remaining));
            if (_inner == null)
                r.EnsureEnd();

            return Psk.PreMasterSecret(otherSecret, psk);
        }
    }

    internal sealed class PskClientKeyExchange : IClientKeyExchange
    {
        private readonly ClientKeyExchangeContext _context;
        private readonly IClientKeyExchange _inner;
        private byte[] _identityHint = Array.Empty<byte>();

        public PskClientKeyExchange(ClientKeyExchangeContext context, IClientKeyExchange inner)
        {
            if (context.PskProvider == null)
                throw new DtlsException(AlertDescription.InternalError, "No pre-shared key configured.");
            _context = context;
            _inner = inner;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange
            => _inner?.ServerKeyExchange == ServerKeyExchangeRequirement.Required
                ? ServerKeyExchangeRequirement.Required
                : ServerKeyExchangeRequirement.Optional;

        public bool ServerParamsSigned => false;
        public ushort Group => _inner?.Group ?? 0;

        public void ReadServerParams(TlsReader reader)
        {
            _identityHint = reader.ReadOpaque16();
            if (_inner?.ServerKeyExchange == ServerKeyExchangeRequirement.Required)
                _inner.ReadServerParams(reader);
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var (identity, psk) = _context.PskProvider(_identityHint);
            if (identity == null || psk == null)
                throw new DtlsException(AlertDescription.InternalError, "No pre-shared key for this server.");

            var w = new TlsWriter().WriteOpaque16(identity);
            byte[] otherSecret;
            if (_inner == null)
            {
                otherSecret = new byte[psk.Length];
            }
            else
            {
                w.WriteBytes(_inner.CreateClientKeyExchange(out otherSecret));
            }

            preMasterSecret = Psk.PreMasterSecret(otherSecret, psk);
            return w.ToArray();
        }
    }

    // ── Static (EC)DH: the server's key agreement key is in its certificate ─────────────────

    /// <summary>DH_DSS / DH_RSA server: Z = Yc^x mod p with the certificate's DH key (RFC 5246 §8.1.2).</summary>
    internal sealed class StaticDhServerKeyExchange : IServerKeyExchange
    {
        private readonly DHPrivateKeyParameters _key;

        public StaticDhServerKeyExchange(ServerKeyExchangeContext context)
        {
            _key = context.ServerPrivateKey as DHPrivateKeyParameters
                ?? throw new DtlsException(AlertDescription.InternalError, "Static DH needs a DH certificate.");
        }

        public ushort Group => FfdheGroups.Identify(_key.Parameters.P, _key.Parameters.G);
        public bool SignsParams => false;
        public byte[] CreateServerParams() => null;

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            var clientY = new BigInteger(1, r.ReadOpaque16());
            r.EnsureEnd();
            return DhUtilities.Agree(_key.Parameters, _key.X, clientY);
        }

        public byte[] ProcessFixedClientKeyExchange(AsymmetricKeyParameter clientPublicKey)
        {
            if (clientPublicKey is not DHPublicKeyParameters client || !client.Parameters.P.Equals(_key.Parameters.P) || !client.Parameters.G.Equals(_key.Parameters.G))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client DH certificate does not use the server's DH parameters.");
            return DhUtilities.Agree(_key.Parameters, _key.X, client.Y);
        }
    }

    internal sealed class StaticDhClientKeyExchange : IClientKeyExchange
    {
        private readonly DHPublicKeyParameters _serverKey;

        public StaticDhClientKeyExchange(ClientKeyExchangeContext context)
        {
            _serverKey = context.ServerPublicKey as DHPublicKeyParameters
                ?? throw new DtlsException(AlertDescription.UnsupportedCertificate, "Static DH needs a DH server certificate.");
            if (_serverKey.Parameters.P.BitLength < context.MinimumDhPrimeBits)
                throw new DtlsException(AlertDescription.InsufficientSecurity, "Server DH prime is too small.");
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.None;
        public bool ServerParamsSigned => false;
        public ushort Group => FfdheGroups.Identify(_serverKey.Parameters.P, _serverKey.Parameters.G);

        public void ReadServerParams(TlsReader reader)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "Static DH has no ServerKeyExchange.");

        // ClientDiffieHellmanPublic, explicit: dh_Yc<1..2^16-1>
        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var (x, y) = DhUtilities.GenerateKeyPair(_serverKey.Parameters);
            preMasterSecret = DhUtilities.Agree(_serverKey.Parameters, x, _serverKey.Y);
            return new TlsWriter().WriteOpaque16(y.ToByteArrayUnsigned()).ToArray();
        }

        public bool SupportsFixedClientKey(AsymmetricKeyParameter clientKey)
            => clientKey is DHKeyParameters dh && dh.Parameters.P.Equals(_serverKey.Parameters.P) && dh.Parameters.G.Equals(_serverKey.Parameters.G);

        // ClientDiffieHellmanPublic, implicit: empty (the client's DH key is in its certificate)
        public byte[] CreateFixedClientKeyExchange(AsymmetricKeyParameter clientPrivateKey, out byte[] preMasterSecret)
        {
            var key = (DHPrivateKeyParameters)clientPrivateKey;
            preMasterSecret = DhUtilities.Agree(_serverKey.Parameters, key.X, _serverKey.Y);
            return Array.Empty<byte>();
        }
    }

    internal static class StaticEcdh
    {
        /// <summary>The x-coordinate of d·Q, padded to the field size (RFC 8422 §5.10).</summary>
        public static byte[] Agree(ECPrivateKeyParameters privateKey, byte[] peerPoint)
        {
            var domain = privateKey.Parameters;
            int fieldLength = (domain.Curve.FieldSize + 7) / 8;
            if (peerPoint == null || peerPoint.Length != 1 + 2 * fieldLength || peerPoint[0] != 0x04)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid EC point encoding.");

            Org.BouncyCastle.Math.EC.ECPoint point;
            try
            {
                point = domain.Curve.DecodePoint(peerPoint);
            }
            catch (ArgumentException ex)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "EC point is not on the curve.", ex);
            }

            var agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey);
            return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(fieldLength,
                agreement.CalculateAgreement(new ECPublicKeyParameters(point, domain)));
        }
    }

    /// <summary>ECDH_ECDSA / ECDH_RSA server: the certificate's EC key is the server's ECDH key (RFC 8422 §2.1).</summary>
    internal sealed class StaticEcdhServerKeyExchange : IServerKeyExchange
    {
        private readonly ECPrivateKeyParameters _key;

        public StaticEcdhServerKeyExchange(ServerKeyExchangeContext context)
        {
            _key = context.ServerPrivateKey as ECPrivateKeyParameters
                ?? throw new DtlsException(AlertDescription.InternalError, "Static ECDH needs an EC certificate.");
        }

        public ushort Group => 0;
        public bool SignsParams => false;
        public byte[] CreateServerParams() => null;

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] point = r.ReadOpaque8();
            r.EnsureEnd();
            return StaticEcdh.Agree(_key, point);
        }

        public byte[] ProcessFixedClientKeyExchange(AsymmetricKeyParameter clientPublicKey)
        {
            if (clientPublicKey is not ECPublicKeyParameters client || !client.Parameters.Equals(_key.Parameters))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client EC certificate is not on the server's curve.");
            return StaticEcdh.Agree(_key, client.Q.GetEncoded(false));
        }
    }

    internal sealed class StaticEcdhClientKeyExchange : IClientKeyExchange
    {
        private readonly ECPublicKeyParameters _serverKey;

        public StaticEcdhClientKeyExchange(ClientKeyExchangeContext context)
        {
            _serverKey = context.ServerPublicKey as ECPublicKeyParameters
                ?? throw new DtlsException(AlertDescription.UnsupportedCertificate, "Static ECDH needs an EC server certificate.");
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.None;
        public bool ServerParamsSigned => false;
        public ushort Group => 0;

        public void ReadServerParams(TlsReader reader)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "Static ECDH has no ServerKeyExchange.");

        public bool SupportsFixedClientKey(AsymmetricKeyParameter clientKey)
            => clientKey is ECKeyParameters ec && ec.Parameters.Equals(_serverKey.Parameters);

        // ClientECDiffieHellmanPublic, implicit: empty (the client's EC key is in its certificate)
        public byte[] CreateFixedClientKeyExchange(AsymmetricKeyParameter clientPrivateKey, out byte[] preMasterSecret)
        {
            preMasterSecret = StaticEcdh.Agree((ECPrivateKeyParameters)clientPrivateKey, _serverKey.Q.GetEncoded(false));
            return Array.Empty<byte>();
        }

        // ClientECDiffieHellmanPublic: an ephemeral key on the server certificate's curve.
        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(_serverKey.Parameters, new SecureRandom()));
            var pair = generator.GenerateKeyPair();
            preMasterSecret = StaticEcdh.Agree((ECPrivateKeyParameters)pair.Private, _serverKey.Q.GetEncoded(false));
            return new TlsWriter().WriteOpaque8(((ECPublicKeyParameters)pair.Public).Q.GetEncoded(false)).ToArray();
        }
    }
}
