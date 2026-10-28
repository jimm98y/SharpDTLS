using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Linq;

namespace SharpDTLS.Protocol12
{
    // ── SRP (RFC 5054) ───────────────────────────────────────────────────────────────────────

    /// <summary>SRP_SHA (unsigned) and SRP_SHA_RSA / SRP_SHA_DSS (signed) server.</summary>
    internal sealed class SrpServerKeyExchange : IServerKeyExchange
    {
        private readonly SrpVerifier _verifier;
        private readonly Srp6Server _server = new();

        public SrpServerKeyExchange(ServerKeyExchangeContext context, bool signed)
        {
            byte[] identity = context.ClientHello.Extension<SrpExtension>()?.Identity
                ?? throw new DtlsException(AlertDescription.HandshakeFailure, "SRP cipher suite without the srp extension.");
            // RFC 5054 §2.5.1.3: an unknown user aborts the handshake with unknown_psk_identity.
            _verifier = context.SrpVerifierProvider?.Invoke(identity)
                ?? throw new DtlsException(AlertDescription.UnknownPskIdentity, "Unknown SRP identity.");
            SignsParams = signed;
        }

        public bool SignsParams { get; }
        public ushort Group => 0;

        // ServerSRPParams: srp_N<1..2^16-1> srp_g<1..2^16-1> srp_s<1..2^8-1> srp_B<1..2^16-1>
        public byte[] CreateServerParams()
        {
            _server.Init(_verifier.Group, _verifier.Verifier, new Sha1Digest(), new SecureRandom());
            BigInteger b = _server.GenerateServerCredentials();
            return new TlsWriter()
                .WriteOpaque16(BigIntegers.AsUnsignedByteArray(_verifier.Group.N))
                .WriteOpaque16(BigIntegers.AsUnsignedByteArray(_verifier.Group.G))
                .WriteOpaque8(_verifier.Salt)
                .WriteOpaque16(BigIntegers.AsUnsignedByteArray(b))
                .ToArray();
        }

        // ClientSRPPublic: srp_A<1..2^16-1>; the premaster secret is S without leading zeros (RFC 5054 §2.6)
        public byte[] ProcessClientKeyExchange(byte[] body)
        {
            var r = new TlsReader(body);
            var a = new BigInteger(1, r.ReadOpaque16());
            r.EnsureEnd();
            try
            {
                return BigIntegers.AsUnsignedByteArray(_server.CalculateSecret(a));
            }
            catch (CryptoException)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid SRP client public value.");
            }
        }
    }

    internal sealed class SrpClientKeyExchange : IClientKeyExchange
    {
        private readonly ClientKeyExchangeContext _context;
        private Srp6GroupParameters _group;
        private byte[] _salt;
        private BigInteger _b;

        public SrpClientKeyExchange(ClientKeyExchangeContext context, bool signed)
        {
            if (context.SrpIdentity == null || context.SrpPassword == null)
                throw new DtlsException(AlertDescription.InternalError, "No SRP credentials configured.");
            _context = context;
            ServerParamsSigned = signed;
        }

        public ServerKeyExchangeRequirement ServerKeyExchange => ServerKeyExchangeRequirement.Required;
        public bool ServerParamsSigned { get; }
        public ushort Group => 0;

        public void ReadServerParams(TlsReader reader)
        {
            var n = new BigInteger(1, reader.ReadOpaque16());
            var g = new BigInteger(1, reader.ReadOpaque16());
            _salt = reader.ReadOpaque8();
            _b = new BigInteger(1, reader.ReadOpaque16());

            // RFC 5054 §2.5.3: only accept known-good groups, as checking N and g is impractical.
            _group = SrpVerifier.StandardGroups.FirstOrDefault(s => s.N.Equals(n) && s.G.Equals(g))
                ?? throw new DtlsException(AlertDescription.InsufficientSecurity, "Server sent an unknown SRP group.");
            if (n.BitLength < _context.MinimumDhPrimeBits)
                throw new DtlsException(AlertDescription.InsufficientSecurity, $"SRP group of {n.BitLength} bits is below the configured minimum.");
            if (_salt.Length == 0)
                throw new DtlsException(AlertDescription.DecodeError, "Empty SRP salt.");
        }

        public byte[] CreateClientKeyExchange(out byte[] preMasterSecret)
        {
            var client = new Srp6Client();
            client.Init(_group, new Sha1Digest(), new SecureRandom());
            BigInteger a = client.GenerateClientCredentials(_salt, _context.SrpIdentity, _context.SrpPassword);
            try
            {
                preMasterSecret = BigIntegers.AsUnsignedByteArray(client.CalculateSecret(_b));
            }
            catch (CryptoException)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid SRP server public value.");
            }
            return new TlsWriter().WriteOpaque16(BigIntegers.AsUnsignedByteArray(a)).ToArray();
        }
    }
}
