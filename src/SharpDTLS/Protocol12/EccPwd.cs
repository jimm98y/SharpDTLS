using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using SharpDTLS.Protocol12.Messages;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace SharpDTLS.Protocol12
{
    /// <summary>
    /// The dragonfly key exchange of TLS-PWD over elliptic curves (RFC 8492 §4.4, errata 5727).
    /// </summary>
    internal static class EccPwd
    {
        /// <summary>
        /// Hunting-and-pecking always runs at least this many iterations so their number does not
        /// leak the password (RFC 8492 §7 asks for at least 40).
        /// </summary>
        public const int MinimumIterations = 40;

        // Cofactor-1 prime curves (RFC 8492 §3.2.1): secp256r1/384r1/521r1, brainpoolP256r1/384r1/512r1.
        private static readonly (ushort Group, string Name)[] Curves =
        {
            (0x0017, "P-256"), (0x001a, "brainpoolP256r1"), (0x0018, "P-384"),
            (0x001b, "brainpoolP384r1"), (0x0019, "P-521"), (0x001c, "brainpoolP512r1"),
        };

        private static readonly Dictionary<ushort, X9ECParameters> _parameters = Curves.ToDictionary(
            c => c.Group, c => ECNamedCurveTable.GetByName(c.Name));

        /// <summary>Supported groups, in preference order.</summary>
        public static IReadOnlyList<ushort> Groups { get; } = Curves.Select(c => c.Group).ToArray();

        public static X9ECParameters Curve(ushort group) => _parameters[group];

        /// <summary>The first group in the client's order we support; secp256r1 without supported_groups.</summary>
        public static ushort SelectGroup(ClientHelloMessage clientHello)
        {
            var offered = clientHello.Extension<SupportedGroupsExtension>()?.Groups;
            if (offered == null)
                return 0x0017;
            return offered.FirstOrDefault(g => _parameters.ContainsKey(g));
        }

        /// <summary>
        /// RFC 8265 OpaqueString enforcement: non-ASCII spaces map to U+0020, then NFC; control
        /// characters and empty strings are rejected.
        /// </summary>
        public static byte[] PrepareOpaqueString(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException("Usernames and passwords must not be empty.");
            var mapped = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (char.IsControl(c))
                    throw new ArgumentException("Usernames and passwords must not contain control characters.");
                mapped.Append(c != ' ' && CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator ? ' ' : c);
            }
            return Encoding.UTF8.GetBytes(mapped.ToString().Normalize(NormalizationForm.FormC));
        }

        /// <summary>
        /// Protects a username for pwd_protect (RFC 8492 §4.3.1): an ephemeral-static ECDH with the server's
        /// protection key gives k = HKDF(Z.x), and the name is C.x || SIV-encrypt(k, username padded to 128 octets).
        /// </summary>
        public static byte[] ProtectUsername(string username, ECPublicKeyParameters serverKey, SecureRandom random)
        {
            var domain = serverKey.Parameters;
            int pLength = (domain.Curve.FieldSize + 7) / 8;
            byte[] name = PrepareOpaqueString(username);
            byte[] padded = new byte[Math.Max(name.Length, 128)];
            name.CopyTo(padded, 0);
            if (pLength + 16 + padded.Length > 255)
                throw new ArgumentException("The username is too long to protect.", nameof(username));

            BigInteger c = BigIntegers.CreateRandomInRange(BigInteger.Two, domain.N.Subtract(BigInteger.Two), random);
            ECPoint publicC = domain.G.Multiply(c).Normalize();
            ECPoint z = serverKey.Q.Multiply(c).Normalize();
            byte[] u = AesSiv.Encrypt(ProtectionKey(domain, z), padded);
            return BigIntegers.AsUnsignedByteArray(pLength, publicC.AffineXCoord.ToBigInteger()).Concat(u).ToArray();
        }

        /// <summary>Recovers a protected username (RFC 8492 §4.3.2), or null when it cannot be recovered.</summary>
        public static string RecoverUsername(byte[] protectedName, ECPrivateKeyParameters serverKey)
        {
            var domain = serverKey.Parameters;
            int pLength = (domain.Curve.FieldSize + 7) / 8;
            if (protectedName.Length <= pLength + 16)
                return null;

            // Compact representation: either y gives the same Z.x, so decode x as a compressed point.
            ECPoint publicC;
            try
            {
                publicC = domain.Curve.DecodePoint(new byte[] { 0x02 }.Concat(protectedName.AsSpan(0, pLength).ToArray()).ToArray());
            }
            catch (ArgumentException)
            {
                return null;
            }
            if (publicC.IsInfinity || !publicC.IsValid())
                return null;

            ECPoint z = publicC.Multiply(serverKey.D).Normalize();
            if (z.IsInfinity)
                return null;
            byte[] username = AesSiv.Decrypt(ProtectionKey(domain, z), protectedName.AsSpan(pLength).ToArray());
            if (username == null)
                return null;
            int length = Array.IndexOf(username, (byte)0);
            return Encoding.UTF8.GetString(username, 0, length < 0 ? username.Length : length);
        }

        // k = HKDF-expand(HKDF-extract(NULL, Z.x), "", l); SHA-256/384/512 and SIV-128/192/256 by len(p).
        private static byte[] ProtectionKey(ECDomainParameters domain, ECPoint z)
        {
            int pBits = domain.Curve.FieldSize;
            IDigest digest = pBits <= 256 ? new Sha256Digest() : pBits <= 384 ? new Sha384Digest() : new Sha512Digest();
            int keyLength = pBits <= 256 ? 32 : pBits <= 384 ? 48 : 64;
            byte[] zx = BigIntegers.AsUnsignedByteArray((pBits + 7) / 8, z.AffineXCoord.ToBigInteger());

            var hkdf = new HkdfBytesGenerator(digest);
            hkdf.Init(new HkdfParameters(zx, null, Array.Empty<byte>()));
            byte[] key = new byte[keyLength];
            hkdf.GenerateBytes(key, 0, key.Length);
            return key;
        }

        /// <summary>
        /// The client's username from pwd_clear or pwd_protect, or null when a protected name cannot be
        /// recovered (treated as an unknown user, RFC 8492 §4.3.2).
        /// </summary>
        public static string ResolveUsername(ClientHelloMessage clientHello, ECPrivateKeyParameters protectionKey)
        {
            var protect = clientHello.Extension<PwdProtectExtension>();
            if (protect != null && protectionKey != null)
                return RecoverUsername(protect.ProtectedName, protectionKey);
            return clientHello.Extension<PwdClearExtension>()?.Username
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "ECCPWD cipher suite without a pwd_name extension.");
        }

        /// <summary>Whether the server can identify the client: pwd_clear, or pwd_protect with a protection key.</summary>
        public static bool HasUsername(ClientHelloMessage clientHello, ECPrivateKeyParameters protectionKey)
            => clientHello.Extension<PwdClearExtension>() != null
               || (protectionKey != null && clientHello.Extension<PwdProtectExtension>() != null);

        /// <summary>H(x) = HMAC-hash(zero key, x), with the cipher suite's hash (RFC 8492 §3.3).</summary>
        internal static byte[] H(bool sha384, params byte[][] parts)
        {
            var hmac = new HMac(sha384 ? new Sha384Digest() : new Sha256Digest());
            hmac.Init(new KeyParameter(new byte[hmac.GetUnderlyingDigest().GetByteLength()]));
            foreach (byte[] part in parts)
                hmac.BlockUpdate(part, 0, part.Length);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            return result;
        }

        /// <summary>pwd-tmp = PRF(pwd-seed, "TLS-PWD Hunting And Pecking", context)[0..len(p)+64 bits].</summary>
        internal static BigInteger PwdTmp(byte[] seed, byte[] context, BigInteger p, bool sha384)
        {
            int bits = p.BitLength + 64;
            int bytes = (bits + 7) / 8;
            byte[] tmp = Dtls12CryptoUtils.PRF(seed, "TLS-PWD Hunting And Pecking", context, bytes, sha384);
            return new BigInteger(1, tmp).ShiftRight(bytes * 8 - bits);
        }

        /// <summary>
        /// Fixes the password element by hunting and pecking (RFC 8492 §4.4.1). <paramref name="context"/>
        /// is ClientHello.random | ServerHello.random.
        /// </summary>
        public static ECPoint PasswordElement(X9ECParameters curve, byte[] passwordBase, byte[] context, bool sha384, SecureRandom random,
            int iterations = MinimumIterations)
        {
            BigInteger p = curve.Curve.Field.Characteristic;
            byte[] pBytes = BigIntegers.AsUnsignedByteArray((p.BitLength + 7) / 8, p);
            BigInteger pMinusOne = p.Subtract(BigInteger.One);
            var (qr, qnr) = ResidueAndNonResidue(p, random);

            BigInteger x = null;
            byte[] save = null;
            byte[] currentBase = passwordBase;
            for (int counter = 1; ; counter++)
            {
                if (counter > 255)
                    throw new DtlsException(AlertDescription.InternalError, "No TLS-PWD password element found.");

                byte[] seed = H(sha384, currentBase, new[] { (byte)counter }, pBytes);
                BigInteger value = PwdTmp(seed, context, p, sha384).Mod(pMinusOne).Add(BigInteger.One);
                if (IsQuadraticResidue(RightHandSide(curve, value), p, qr, qnr, random) && x == null)
                {
                    x = value;
                    save = seed;
                    currentBase = SecureRandom.GetNextBytes(random, passwordBase.Length);
                }

                if (x != null && counter > iterations)
                    break;
            }

            BigInteger y = curve.Curve.FromBigInteger(RightHandSide(curve, x)).Sqrt().ToBigInteger();
            if (y.TestBit(0) != ((save[save.Length - 1] & 1) == 1))
                y = p.Subtract(y);
            return curve.Curve.ValidatePoint(x, y);
        }

        private static BigInteger RightHandSide(X9ECParameters curve, BigInteger x)
        {
            BigInteger p = curve.Curve.Field.Characteristic;
            return x.ModPow(BigInteger.Three, p)
                .Add(curve.Curve.A.ToBigInteger().Multiply(x))
                .Add(curve.Curve.B.ToBigInteger())
                .Mod(p);
        }

        private static int Legendre(BigInteger a, BigInteger p)
        {
            BigInteger r = a.ModPow(p.Subtract(BigInteger.One).ShiftRight(1), p);
            return r.SignValue == 0 ? 0 : r.Equals(BigInteger.One) ? 1 : -1;
        }

        private static BigInteger RandomBelow(BigInteger p, SecureRandom random)
            => BigIntegers.CreateRandomInRange(BigInteger.One, p.Subtract(BigInteger.One), random);

        private static (BigInteger Qr, BigInteger Qnr) ResidueAndNonResidue(BigInteger p, SecureRandom random)
        {
            BigInteger qr, qnr;
            do qr = RandomBelow(p, random); while (Legendre(qr, p) != 1);
            do qnr = RandomBelow(p, random); while (Legendre(qnr, p) != -1);
            return (qr, qnr);
        }

        /// <summary>Blinded quadratic residuosity test (RFC 8492 §4.4.1), so the test does not leak the value.</summary>
        private static bool IsQuadraticResidue(BigInteger value, BigInteger p, BigInteger qr, BigInteger qnr, SecureRandom random)
        {
            BigInteger r = RandomBelow(p, random);
            BigInteger num = value.Multiply(r).Multiply(r).Mod(p);
            return r.TestBit(0)
                ? Legendre(num.Multiply(qr).Mod(p), p) == 1
                : Legendre(num.Multiply(qnr).Mod(p), p) == -1;
        }

        /// <summary>
        /// The commitment (RFC 8492 §4.4.4): scalar = (private + mask) mod q, Element = -(mask * PE).
        /// Pass <paramref name="privateValue"/> and <paramref name="mask"/> only to reproduce test vectors.
        /// </summary>
        public static (BigInteger Private, BigInteger Scalar, ECPoint Element) Commit(X9ECParameters curve, ECPoint passwordElement,
            SecureRandom random, BigInteger privateValue = null, BigInteger mask = null)
        {
            BigInteger q = curve.N;
            while (true)
            {
                BigInteger priv = privateValue ?? BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), random);
                BigInteger m = mask ?? BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), random);
                BigInteger scalar = priv.Add(m).Mod(q);
                if (scalar.CompareTo(BigInteger.One) > 0)
                    return (priv, scalar, passwordElement.Multiply(m).Negate().Normalize());
                if (privateValue != null)
                    throw new ArgumentException("private + mask must exceed 1 modulo q.");
            }
        }

        /// <summary>Decodes and validates a peer commitment (RFC 8492 §4.5.1.2.2, §4.5.1.3.2).</summary>
        public static (BigInteger Scalar, ECPoint Element) ReadCommit(X9ECParameters curve, byte[] element, byte[] scalar)
        {
            var s = new BigInteger(1, scalar);
            if (s.CompareTo(BigInteger.One) <= 0 || s.CompareTo(curve.N) >= 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "TLS-PWD scalar out of range.");

            ECPoint point;
            try
            {
                point = curve.Curve.DecodePoint(element).Normalize();
            }
            catch (ArgumentException)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "TLS-PWD element is not on the curve.");
            }
            if (point.IsInfinity || !point.IsValid())
                throw new DtlsException(AlertDescription.IllegalParameter, "TLS-PWD element is not on the curve.");
            return (s, point);
        }

        /// <summary>
        /// z = F(private * (peer_Element + peer_scalar * PE)) (RFC 8492 §4.6); the premaster secret is z
        /// without leading zero bytes.
        /// </summary>
        public static byte[] PreMasterSecret(ECPoint passwordElement, BigInteger privateValue, BigInteger peerScalar, ECPoint peerElement)
        {
            ECPoint k = peerElement.Add(passwordElement.Multiply(peerScalar)).Multiply(privateValue).Normalize();
            if (k.IsInfinity)
                throw new DtlsException(AlertDescription.IllegalParameter, "TLS-PWD shared secret is the point at infinity.");
            return BigIntegers.AsUnsignedByteArray(k.AffineXCoord.ToBigInteger());
        }

        public static byte[] EncodeScalar(X9ECParameters curve, BigInteger scalar)
            => BigIntegers.AsUnsignedByteArray((curve.N.BitLength + 7) / 8, scalar);

        /// <summary>
        /// Reads salt or scalar, which RFC 8492 declares as opaque&lt;1..2^8-1&gt;. The Appendix A example
        /// encodes them with a 16-bit length instead; a valid 8-bit length is never 0, so a leading zero
        /// byte can only start a 16-bit length, and both encodings are accepted.
        /// </summary>
        public static byte[] ReadOpaque(TlsReader reader)
        {
            byte[] value = reader.PeekUInt8() == 0 ? reader.ReadOpaque16() : reader.ReadOpaque8();
            if (value.Length == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Empty TLS-PWD field.");
            return value;
        }
    }

    /// <summary>ECCPWD server (RFC 8492 §4.5.1.2).</summary>
    internal sealed class EccPwdServerKeyExchange : IServerKeyExchange
    {
        private readonly ServerKeyExchangeContext _context;
        private readonly PwdCredential _credential;
        private readonly bool _simulated;
        private readonly bool _sha384;
        private readonly X9ECParameters _curve;
        private readonly SecureRandom _random = new();
        private ECPoint _passwordElement;
        private BigInteger _private;
        private BigInteger _scalar;
        private ECPoint _element;

        public EccPwdServerKeyExchange(ServerKeyExchangeContext context, CipherSuiteInfo suite)
        {
            string username = EccPwd.ResolveUsername(context.ClientHello, context.PwdProtectionKey);
            Group = EccPwd.SelectGroup(context.ClientHello);
            if (Group == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No TLS-PWD group in common.");

            _context = context;
            _curve = EccPwd.Curve(Group);
            _sha384 = suite.Prf == PrfHashAlgorithm.Sha384;

            // RFC 8492 §4.5.1.1: hide unknown users by running the protocol with a random salt and base;
            // the client's Finished then fails like a wrong password, and hunting and pecking costs the same.
            _credential = username == null ? null : context.PwdCredentialProvider?.Invoke(username);
            _simulated = _credential == null;
            _credential ??= new PwdCredential(Dtls12CryptoUtils.GenerateRandom(32), Dtls12CryptoUtils.GenerateRandom(32));
        }

        public bool SignsParams => false;
        public ushort Group { get; }

        // ServerECPWDParams: salt<1..2^8-1> ECParameters(named_curve) ECPoint ec_selement ec_sscalar<1..2^8-1>
        public byte[] CreateServerParams()
        {
            _passwordElement = EccPwd.PasswordElement(_curve, _credential.Base, _context.PwdContext(), _sha384, _random);
            (_private, _scalar, _element) = EccPwd.Commit(_curve, _passwordElement, _random);
            return new TlsWriter()
                .WriteOpaque8(_credential.Salt)
                .WriteUInt8(3).WriteUInt16(Group)
                .WriteOpaque8(_element.GetEncoded(false))
                .WriteOpaque8(EccPwd.EncodeScalar(_curve, _scalar))
                .ToArray();
        }

        // ClientECPWDParams: ECPoint ec_celement ec_cscalar<1..2^8-1>
        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            byte[] element = r.ReadOpaque8();
            byte[] scalar = EccPwd.ReadOpaque(r);
            r.EnsureEnd();

            var (peerScalar, peerElement) = EccPwd.ReadCommit(_curve, element, scalar);
            if (peerScalar.Equals(_scalar) || peerElement.Equals(_element))
                throw new DtlsException(AlertDescription.IllegalParameter, "Client reflected the server's TLS-PWD commitment.");

            byte[] preMasterSecret = EccPwd.PreMasterSecret(_passwordElement, _private, peerScalar, peerElement);
            return _simulated ? Dtls12CryptoUtils.GenerateRandom(preMasterSecret.Length) : preMasterSecret;
        }
    }

    internal sealed class EccPwdClientKeyExchange : IClientKeyExchange
    {
        private readonly ClientKeyExchangeContext _context;
        private readonly bool _sha384;
        private X9ECParameters _curve;
        private byte[] _salt;
        private BigInteger _peerScalar;
        private ECPoint _peerElement;

        public EccPwdClientKeyExchange(ClientKeyExchangeContext context, CipherSuiteInfo suite)
        {
            if (context.PwdUsername == null || context.PwdPassword == null)
                throw new DtlsException(AlertDescription.InternalError, "No TLS-PWD credentials configured.");
            _context = context;
            _sha384 = suite.Prf == PrfHashAlgorithm.Sha384;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.Required;
        public bool ServerParamsSigned => false;
        public ushort Group { get; private set; }

        public void ReadServerParams(TlsReader reader)
        {
            _salt = EccPwd.ReadOpaque(reader);
            if (reader.ReadUInt8() != 3)
                throw new DtlsException(AlertDescription.IllegalParameter, "TLS-PWD requires a named curve.");
            Group = reader.ReadUInt16();
            if (!EccPwd.Groups.Contains(Group))
                throw new DtlsException(AlertDescription.IllegalParameter, $"Server chose unsupported TLS-PWD group 0x{Group:X4}.");
            _curve = EccPwd.Curve(Group);
            byte[] element = reader.ReadOpaque8();
            byte[] scalar = EccPwd.ReadOpaque(reader);
            (_peerScalar, _peerElement) = EccPwd.ReadCommit(_curve, element, scalar);
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var random = new SecureRandom();
            byte[] passwordBase = PwdCredential.ComputeBase(_salt, _context.PwdUsername, _context.PwdPassword);
            ECPoint passwordElement = EccPwd.PasswordElement(_curve, passwordBase, _context.PwdContext(), _sha384, random);
            var (privateValue, scalar, element) = EccPwd.Commit(_curve, passwordElement, random);
            preMasterSecret = EccPwd.PreMasterSecret(passwordElement, privateValue, _peerScalar, _peerElement);
            return new TlsWriter()
                .WriteOpaque8(element.GetEncoded(false))
                .WriteOpaque8(EccPwd.EncodeScalar(_curve, scalar))
                .ToArray();
        }
    }
}
