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

using SharpDTLS.Protocol12.Messages;
using SharpDTLS.Protocol13;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace SharpDTLS.Protocol12
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
    }

    /// <summary>
    /// A static (EC)DH server key exchange, which also accepts fixed (EC)DH client authentication
    /// (RFC 5246 §7.4.7.2, RFC 8422 §3).
    /// </summary>
    internal interface IFixedDhServerKeyExchange : IServerKeyExchange
    {
        /// <summary>The ClientKeyExchange was empty and the client's certificate key is its key agreement key.</summary>
        byte[] ProcessFixedClientKeyExchange(TlsPublicKey clientPublicKey);
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
    }

    /// <summary>A static (EC)DH client key exchange, which can also authenticate with fixed (EC)DH.</summary>
    internal interface IFixedDhClientKeyExchange : IClientKeyExchange
    {
        /// <summary>Whether <paramref name="clientKey"/> can be used for fixed (EC)DH client authentication.</summary>
        bool SupportsFixedClientKey(TlsPublicKey clientKey);

        /// <summary>Fixed (EC)DH: the premaster secret from the client's static key; the ClientKeyExchange is empty.</summary>
        /// <paramref name="agree"/> is the client key's static (EC)DH with the server's public value.
        byte[] CreateFixedClientKeyExchange(Func<byte[], byte[]> agree, out byte[] preMasterSecret);
    }

    internal sealed class ServerKeyExchangeContext
    {
        public ITlsCrypto Crypto { get; set; } = BouncyCastleTlsCrypto.Default;
        public ClientHelloMessage ClientHello { get; set; }
        /// <summary>The public key of the server's certificate (or raw public key); its private key's operations are below.</summary>
        public TlsPublicKey ServerPublicKey { get; set; }
        public Func<byte[], byte[]> DecryptPreMasterSecret { get; set; }
        public Func<byte[], byte[]> Agree { get; set; }
        public byte[] PskIdentityHint { get; set; }
        public Func<byte[], byte[]> PskResolver { get; set; }
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get; set; }
        public Func<string, PwdCredential> PwdCredentialProvider { get; set; }
        public System.Security.Cryptography.ECParameters? PwdProtectionKey { get; set; }

        /// <summary>ClientHello.random | ServerHello.random, once both are known (TLS-PWD hunting and pecking).</summary>
        public Func<byte[]> PwdContext { get; set; }
    }

    internal sealed class ClientKeyExchangeContext
    {
        public ITlsCrypto Crypto { get; set; } = BouncyCastleTlsCrypto.Default;
        public ushort ClientHelloVersion { get; set; }
        public TlsPublicKey ServerPublicKey { get; set; }
        public int MinimumDhPrimeBits { get; set; }

        /// <summary>Maps the server's identity hint (possibly empty) to the PSK identity and key.</summary>
        public Func<byte[], (byte[] Identity, byte[] Key)> PskProvider { get; set; }

        public byte[] SrpIdentity { get; set; }
        public byte[] SrpPassword { get; set; }

        public string PwdUsername { get; set; }
        public string PwdPassword { get; set; }

        /// <summary>ClientHello.random | ServerHello.random (TLS-PWD hunting and pecking).</summary>
        public Func<byte[]> PwdContext { get; set; }
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
            KeyExchangeAlgorithm.ECDHE_ECDSA or KeyExchangeAlgorithm.ECDHE_RSA => new EcdheClientKeyExchange(context.Crypto),
            KeyExchangeAlgorithm.DHE_RSA or KeyExchangeAlgorithm.DHE_DSS => new DheClientKeyExchange(context),
            KeyExchangeAlgorithm.RSA => new RsaClientKeyExchange(context),
            KeyExchangeAlgorithm.PSK => new PskClientKeyExchange(context, null),
            KeyExchangeAlgorithm.DHE_PSK or KeyExchangeAlgorithm.PSK_DHE => new PskClientKeyExchange(context, new DheClientKeyExchange(context)),
            KeyExchangeAlgorithm.ECDHE_PSK => new PskClientKeyExchange(context, new EcdheClientKeyExchange(context.Crypto)),
            KeyExchangeAlgorithm.RSA_PSK => new PskClientKeyExchange(context, new RsaClientKeyExchange(context)),
            KeyExchangeAlgorithm.DH_anon => new DheClientKeyExchange(context, signed: false),
            KeyExchangeAlgorithm.ECDH_anon => new EcdheClientKeyExchange(context.Crypto, signed: false),
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
        private readonly ITlsCrypto _crypto;
        private ITlsKeyShare _share;

        public EcdheServerKeyExchange(ServerKeyExchangeContext context, bool signed = true)
        {
            _crypto = context.Crypto;
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
            _share = Dtls13Groups.Share(_crypto, Group);
            return new TlsWriter().WriteUInt8(3).WriteUInt16(Group).WriteOpaque8(_share.PublicKey).ToArray();
        }

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] clientPublicKey = r.ReadOpaque8();
            r.EnsureEnd();
            return Dtls13Groups.Agree(_share, clientPublicKey);
        }
    }

    internal sealed class EcdheClientKeyExchange : IClientKeyExchange
    {
        private readonly ITlsCrypto _crypto;
        private byte[] _serverPublicKey;

        public EcdheClientKeyExchange(ITlsCrypto crypto, bool signed = true)
        {
            _crypto = crypto;
            ServerParamsSigned = signed;
        }

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
            var share = Dtls13Groups.Share(_crypto, Group);
            preMasterSecret = Dtls13Groups.Agree(share, _serverPublicKey);
            return new TlsWriter().WriteOpaque8(share.PublicKey).ToArray();
        }
    }

    // ── Finite-field DHE (RFC 5246 §7.4.3, RFC 7919) ─────────────────────────────────────────





    /// <summary>Big-endian unsigned integers as TLS 1.2 carries DH values, compared without a big-integer type.</summary>
    internal static class UnsignedBytes
    {
        public static byte[] Strip(byte[] value)
        {
            int i = 0;
            while (i < value.Length - 1 && value[i] == 0)
                i++;
            return i == 0 ? value : value.AsSpan(i).ToArray();
        }

        public static int BitLength(byte[] value)
        {
            value = Strip(value);
            if (value.Length == 0 || (value.Length == 1 && value[0] == 0))
                return 0;
            int bits = (value.Length - 1) * 8;
            for (int b = value[0]; b != 0; b >>= 1)
                bits++;
            return bits;
        }

        public static int Compare(byte[] a, byte[] b)
        {
            a = Strip(a);
            b = Strip(b);
            if (a.Length != b.Length)
                return a.Length.CompareTo(b.Length);
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    return a[i].CompareTo(b[i]);
            return 0;
        }

        public static bool Equal(byte[] a, byte[] b) => Compare(a, b) == 0;
    }

    internal sealed class DheServerKeyExchange : IServerKeyExchange
    {
        private readonly ITlsCrypto _crypto;
        private ITlsKeyShare _share;

        public DheServerKeyExchange(ServerKeyExchangeContext context, bool signed = true)
        {
            _crypto = context.Crypto;
            SignsParams = signed;
            // RFC 7919 §4: use a named group the client lists; otherwise ffdhe2048, which any DHE client accepts.
            var groups = context.ClientHello.Extension<SupportedGroupsExtension>()?.Groups ?? Array.Empty<ushort>();
            Group = FfdheGroups.Supported.FirstOrDefault(g => groups.Contains(g));
            if (Group == 0)
                Group = FfdheGroups.Ffdhe2048;
        }

        public ushort Group { get; }
        public bool SignsParams { get; }

        // ServerDHParams: dh_p<1..2^16-1> || dh_g<1..2^16-1> || dh_Ys<1..2^16-1>
        public byte[] CreateServerParams()
        {
            byte[] p = FfdheGroups.Prime(Group), g = FfdheGroups.Generator(Group);
            _share = _crypto.CreateDhKeyShare(p, g);
            return new TlsWriter().WriteOpaque16(p).WriteOpaque16(g).WriteOpaque16(_share.PublicKey).ToArray();
        }

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] clientY = r.ReadOpaque16();
            r.EnsureEnd();
            return Dtls13Groups.Agree(_share, clientY);
        }
    }

    internal sealed class DheClientKeyExchange : IClientKeyExchange
    {
        private readonly ITlsCrypto _crypto;
        private readonly int _minimumPrimeBits;
        private byte[] _p, _g, _serverY;

        public DheClientKeyExchange(ClientKeyExchangeContext context, bool signed = true)
        {
            _crypto = context.Crypto;
            _minimumPrimeBits = context.MinimumDhPrimeBits;
            ServerParamsSigned = signed;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.Required;
        public bool ServerParamsSigned { get; }
        public ushort Group { get; private set; }

        public void ReadServerParams(TlsReader reader)
        {
            byte[] p = UnsignedBytes.Strip(reader.ReadOpaque16());
            byte[] g = UnsignedBytes.Strip(reader.ReadOpaque16());
            _serverY = reader.ReadOpaque16();

            int bits = UnsignedBytes.BitLength(p);
            if (bits < _minimumPrimeBits)
                throw new DtlsException(AlertDescription.InsufficientSecurity, $"Diffie-Hellman prime of {bits} bits is too small.");
            // p odd, 1 < g < p - 1 (p - 1 is p with its low bit cleared)
            byte[] pMinusOne = (byte[])p.Clone();
            pMinusOne[pMinusOne.Length - 1] &= 0xFE;
            if ((p[p.Length - 1] & 1) == 0 || UnsignedBytes.Compare(g, new byte[] { 1 }) <= 0 || UnsignedBytes.Compare(g, pMinusOne) >= 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid Diffie-Hellman parameters.");

            // Named groups are known safe primes; custom primes are accepted as sent (as most TLS stacks do).
            Group = FfdheGroups.Identify(p, g);
            (_p, _g) = (p, g);
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var share = _crypto.CreateDhKeyShare(_p, _g);
            preMasterSecret = Dtls13Groups.Agree(share, _serverY);
            return new TlsWriter().WriteOpaque16(share.PublicKey).ToArray();
        }
    }

    // ── RSA key transport (RFC 5246 §7.4.7.1) ────────────────────────────────────────────────

    internal sealed class RsaServerKeyExchange : IServerKeyExchange
    {
        private readonly ServerKeyExchangeContext _context;

        public RsaServerKeyExchange(ServerKeyExchangeContext context)
        {
            _context = context;
            if (context.ServerPublicKey?.Kind != TlsKeyKind.Rsa)
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

            // The crypto returns random bytes in constant time on any decoding failure, or throws.
            byte[] decrypted;
            try
            {
                decrypted = _context.DecryptPreMasterSecret(encrypted) ?? random;
            }
            catch (CryptographicException)
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
            if (_context.ServerPublicKey is not { Kind: TlsKeyKind.Rsa } key)
                throw new DtlsException(AlertDescription.UnsupportedCertificate, "RSA key exchange needs an RSA server certificate.");

            preMasterSecret = new byte[48];
            RandomNumberGenerator.Fill(preMasterSecret);
            preMasterSecret[0] = (byte)(_context.ClientHelloVersion >> 8);
            preMasterSecret[1] = (byte)_context.ClientHelloVersion;

            return new TlsWriter().WriteOpaque16(_context.Crypto.EncryptPreMasterSecret(key.Spki, preMasterSecret)).ToArray();
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
    internal sealed class StaticDhServerKeyExchange : IFixedDhServerKeyExchange
    {
        private readonly TlsPublicKey _key;
        private readonly Func<byte[], byte[]> _agree;

        public StaticDhServerKeyExchange(ServerKeyExchangeContext context)
        {
            _key = context.ServerPublicKey is { Kind: TlsKeyKind.Dh } key ? key
                : throw new DtlsException(AlertDescription.InternalError, "Static DH needs a DH certificate.");
            _agree = context.Agree;
        }

        public ushort Group => FfdheGroups.Identify(_key.DhPrime, _key.DhGenerator);
        public bool SignsParams => false;
        public byte[] CreateServerParams() => null;

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] clientY = r.ReadOpaque16();
            r.EnsureEnd();
            return _agree(clientY);
        }

        public byte[] ProcessFixedClientKeyExchange(TlsPublicKey clientPublicKey)
        {
            if (clientPublicKey is not { Kind: TlsKeyKind.Dh } client || !SameGroup(client, _key))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client DH certificate does not use the server's DH parameters.");
            return _agree(client.DhY);
        }

        internal static bool SameGroup(TlsPublicKey a, TlsPublicKey b)
            => UnsignedBytes.Equal(a.DhPrime, b.DhPrime) && UnsignedBytes.Equal(a.DhGenerator, b.DhGenerator);
    }

    internal sealed class StaticDhClientKeyExchange : IFixedDhClientKeyExchange
    {
        private readonly ITlsCrypto _crypto;
        private readonly TlsPublicKey _serverKey;

        public StaticDhClientKeyExchange(ClientKeyExchangeContext context)
        {
            _crypto = context.Crypto;
            _serverKey = context.ServerPublicKey is { Kind: TlsKeyKind.Dh } key ? key
                : throw new DtlsException(AlertDescription.UnsupportedCertificate, "Static DH needs a DH server certificate.");
            if (UnsignedBytes.BitLength(_serverKey.DhPrime) < context.MinimumDhPrimeBits)
                throw new DtlsException(AlertDescription.InsufficientSecurity, "Server DH prime is too small.");
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.None;
        public bool ServerParamsSigned => false;
        public ushort Group => FfdheGroups.Identify(_serverKey.DhPrime, _serverKey.DhGenerator);

        public void ReadServerParams(TlsReader reader)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "Static DH has no ServerKeyExchange.");

        // ClientDiffieHellmanPublic, explicit: dh_Yc<1..2^16-1>
        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var share = _crypto.CreateKeyShareOnDomainOf(_serverKey.Spki);
            preMasterSecret = Dtls13Groups.Agree(share, _serverKey.DhY);
            return new TlsWriter().WriteOpaque16(share.PublicKey).ToArray();
        }

        public bool SupportsFixedClientKey(TlsPublicKey clientKey)
            => clientKey is { Kind: TlsKeyKind.Dh } && StaticDhServerKeyExchange.SameGroup(clientKey, _serverKey);

        // ClientDiffieHellmanPublic, implicit: empty (the client's DH key is in its certificate)
        public byte[] CreateFixedClientKeyExchange(Func<byte[], byte[]> agree, out byte[] preMasterSecret)
        {
            preMasterSecret = agree(_serverKey.DhY);
            return Array.Empty<byte>();
        }
    }

    /// <summary>ECDH_ECDSA / ECDH_RSA server: the certificate's EC key is the server's ECDH key (RFC 8422 §2.1).</summary>
    internal sealed class StaticEcdhServerKeyExchange : IFixedDhServerKeyExchange
    {
        private readonly TlsPublicKey _key;
        private readonly Func<byte[], byte[]> _agree;

        public StaticEcdhServerKeyExchange(ServerKeyExchangeContext context)
        {
            _key = context.ServerPublicKey is { Kind: TlsKeyKind.Ec } key ? key
                : throw new DtlsException(AlertDescription.InternalError, "Static ECDH needs an EC certificate.");
            _agree = context.Agree;
        }

        public ushort Group => 0;
        public bool SignsParams => false;
        public byte[] CreateServerParams() => null;

        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] point = r.ReadOpaque8();
            r.EnsureEnd();
            return _agree(point);
        }

        public byte[] ProcessFixedClientKeyExchange(TlsPublicKey clientPublicKey)
        {
            if (clientPublicKey is not { Kind: TlsKeyKind.Ec } client || !client.AlgorithmParameters.AsSpan().SequenceEqual(_key.AlgorithmParameters))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client EC certificate is not on the server's curve.");
            return _agree(client.EcPoint);
        }
    }

    internal sealed class StaticEcdhClientKeyExchange : IFixedDhClientKeyExchange
    {
        private readonly ITlsCrypto _crypto;
        private readonly TlsPublicKey _serverKey;

        public StaticEcdhClientKeyExchange(ClientKeyExchangeContext context)
        {
            _crypto = context.Crypto;
            _serverKey = context.ServerPublicKey is { Kind: TlsKeyKind.Ec } key ? key
                : throw new DtlsException(AlertDescription.UnsupportedCertificate, "Static ECDH needs an EC server certificate.");
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.None;
        public bool ServerParamsSigned => false;
        public ushort Group => 0;

        public void ReadServerParams(TlsReader reader)
            => throw new DtlsException(AlertDescription.UnexpectedMessage, "Static ECDH has no ServerKeyExchange.");

        public bool SupportsFixedClientKey(TlsPublicKey clientKey)
            => clientKey is { Kind: TlsKeyKind.Ec } && clientKey.AlgorithmParameters.AsSpan().SequenceEqual(_serverKey.AlgorithmParameters);

        // ClientECDiffieHellmanPublic, implicit: empty (the client's EC key is in its certificate)
        public byte[] CreateFixedClientKeyExchange(Func<byte[], byte[]> agree, out byte[] preMasterSecret)
        {
            preMasterSecret = agree(_serverKey.EcPoint);
            return Array.Empty<byte>();
        }

        // ClientECDiffieHellmanPublic: an ephemeral key on the server certificate's curve.
        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var share = _crypto.CreateKeyShareOnDomainOf(_serverKey.Spki);
            preMasterSecret = Dtls13Groups.Agree(share, _serverKey.EcPoint);
            return new TlsWriter().WriteOpaque8(share.PublicKey).ToArray();
        }
    }
}
