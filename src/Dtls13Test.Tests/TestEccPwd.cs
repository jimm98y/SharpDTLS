using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using SharpDTLS;
using SharpDTLS.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// TLS-PWD (RFC 8492). No other DTLS implementation supports it, so the dragonfly math is checked against
    /// the Appendix A example as corrected by verified errata 5727 (brainpoolP256r1, SHA-256).
    /// </summary>
    [TestClass]
    public sealed class TestEccPwd
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private const ushort BrainpoolP256r1 = 0x001a;

        private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));
        private static BigInteger Int(string hex) => new BigInteger(1, Hex(hex));

        private static readonly byte[] Salt = Hex("963c77cdc13a2a8d75cdddd1e0449929 843711c21d47ce6e6383cdda37e47da3");
        private static readonly byte[] Base = Hex("6e7c79821b9f8e8021e9e7e826e9ed28 c4a18aefc8750c726f74c70961d70075");
        private static readonly byte[] ClientRandom = Hex("528fbf52175de2c869845fdbfa8344f7 d732712ebfa679d8643cd31a880e043d");
        private static readonly byte[] ServerRandom = Hex("528fbf524378a1b13b8d2cbd24709072 1369f8bfa3ceeb3cfcd85cbfcdd58eaa");
        private static byte[] Context => ClientRandom.Concat(ServerRandom).ToArray();

        private static readonly BigInteger ServerPrivate = Int("21d99d341c9797b3ae72dfd289971f1b 74ce9de68ad4b9abf54888d8f6c5043c");
        private static readonly BigInteger ServerMask = Int("0d96ab624d082c71255be3648dcd303f 6ab0ca61a95034a553e3308d1d3744e5");
        private static readonly BigInteger ClientPrivate = Int("171de8caa5352d36ee96a39979b5b72f a189ae7a6a09c77f7b438af16df4a88b");
        private static readonly BigInteger ClientMask = Int("4f745bdfc295d3b38429f7eb3025a488 83728b07d88605c0ee202316a072d1bd");

        private static readonly byte[] ServerElement = Hex(
            "047bdea77c038edcd566169981c58707 fadba8a8d83ec90c37e3c0666a5a6799 1140d6851a6c81a5017564d526b157db cd97a6427cb0e47ee5caa4396633e051 31");
        private static readonly BigInteger ServerScalar = Int("2f704896699fc424d3cec33717644f5a df7f68483424ee51492bb96613fc4921");
        private static readonly byte[] ClientElement = Hex(
            "048907f20ca8ff2badbfa63edec5934d f1ecff10753f7aa4f750ba8a2dbd9263 333daff943a21cd079d77507b92782ee 779891 98b90ad778de3846c319c7bcd2 45");
        private static readonly BigInteger ClientScalar = Int("669244aa67cb00ea72c09b84a9db5bb8 24fc3982428fcd406963ae080e677a48");

        private static readonly byte[] PreMasterSecret = Hex("a13e9ea0d356ab1d9755a0f7339ef1c1 21b343f52ff2e67faa4c35713bedafb1");
        private static readonly byte[] MasterSecret = Hex(
            "f773ba1ddca9894c8b7131485af95fdd 06835e181326ddb78f3603ef787567fb 01e9adba7de0d60e89280b43748d2f53");

        [TestMethod]
        public void Base_IsSaltedHmacOfUsernameAndPassword()
            => CollectionAssert.AreEqual(Base, PwdCredential.ComputeBase(Salt, "fred", "barney"));

        [TestMethod]
        public void HuntingAndPecking_FirstRoundMatchesErrata()
        {
            var curve = EccPwd.Curve(BrainpoolP256r1);
            BigInteger p = curve.Curve.Field.Characteristic;
            byte[] seed = EccPwd.H(false, Base, new byte[] { 1 }, BigIntegers.AsUnsignedByteArray(32, p));

            BigInteger tmp = EccPwd.PwdTmp(seed, Context, p, sha384: false);
            Assert.AreEqual(Int("ae8044fe9a027fa3260cb24d26fbecfb 0cd31a28e0087998476f48248428aa1b a14c253ce300cfe5"), tmp);
            Assert.AreEqual(Int("00686b0d3fc49894dd621ec04f925e02 9b2b1528ededca46007254281e9a6edc"), tmp.Mod(p.Subtract(BigInteger.One)).Add(BigInteger.One));
        }

        [TestMethod]
        public void PasswordElement_MatchesErrata()
        {
            var pe = EccPwd.PasswordElement(EccPwd.Curve(BrainpoolP256r1), Base, Context, sha384: false, new SecureRandom());
            Assert.AreEqual(Int("00686b0d3fc49894dd621ec04f925e02 9b2b1528ededca46007254281e9a6edc"), pe.AffineXCoord.ToBigInteger());
        }

        [TestMethod]
        public void CommitmentsAndSecrets_MatchErrata()
        {
            var curve = EccPwd.Curve(BrainpoolP256r1);
            var random = new SecureRandom();
            var pe = EccPwd.PasswordElement(curve, Base, Context, sha384: false, random);

            var server = EccPwd.Commit(curve, pe, random, ServerPrivate, ServerMask);
            Assert.AreEqual(ServerScalar, server.Scalar);
            CollectionAssert.AreEqual(ServerElement, server.Element.GetEncoded(false));

            var client = EccPwd.Commit(curve, pe, random, ClientPrivate, ClientMask);
            Assert.AreEqual(ClientScalar, client.Scalar);
            CollectionAssert.AreEqual(ClientElement, client.Element.GetEncoded(false));

            CollectionAssert.AreEqual(PreMasterSecret, EccPwd.PreMasterSecret(pe, ServerPrivate, client.Scalar, client.Element));
            CollectionAssert.AreEqual(PreMasterSecret, EccPwd.PreMasterSecret(pe, ClientPrivate, server.Scalar, server.Element));
            CollectionAssert.AreEqual(MasterSecret, Dtls12CryptoUtils.PRF(PreMasterSecret, "master secret", Context, 48));
        }

        [TestMethod]
        public void ServerKeyExchange_FromTheExample_IsParsed()
        {
            // The example encodes salt and scalar with 16-bit lengths, unlike the 8-bit lengths of
            // RFC 8492 §4.5.1.2; both forms are accepted.
            byte[] body = new byte[] { 0x00, 0x20 }.Concat(Salt).Concat(Hex("03001a41")).Concat(ServerElement)
                .Concat(Hex("0020")).Concat(BigIntegers.AsUnsignedByteArray(32, ServerScalar)).ToArray();
            Assert.HasCount(0x89, body);

            var client = new EccPwdClientKeyExchange(new ClientKeyExchangeContext
            {
                PwdUsername = "fred", PwdPassword = "barney", PwdContext = () => Context,
            }, CipherSuites.Get(0xC0B0));
            var reader = new TlsReader(body);
            client.ReadServerParams(reader);
            Assert.AreEqual(0, reader.Remaining);
            Assert.AreEqual(BrainpoolP256r1, client.Group);
        }

        [TestMethod]
        public void InvalidCommitments_AreRejected()
        {
            var curve = EccPwd.Curve(BrainpoolP256r1);
            byte[] scalar = BigIntegers.AsUnsignedByteArray(32, ServerScalar);
            byte[] offCurve = (byte[])ServerElement.Clone();
            offCurve[^1] ^= 1;

            Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => EccPwd.ReadCommit(curve, offCurve, scalar)).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => EccPwd.ReadCommit(curve, ServerElement, new byte[] { 1 })).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter,
                Assert.ThrowsExactly<DtlsException>(() => EccPwd.ReadCommit(curve, ServerElement, BigIntegers.AsUnsignedByteArray(curve.N))).Alert);
        }

        [DataRow((ushort)0x0017)]
        [DataRow((ushort)0x0018)]
        [DataRow((ushort)0x0019)] // P-521: pwd-tmp is 585 bits, not a whole number of bytes
        [DataRow((ushort)0x001a)]
        [DataRow((ushort)0x001b)]
        [DataRow((ushort)0x001c)]
        [TestMethod]
        public void EveryGroup_BothSidesAgree(ushort group)
        {
            var curve = EccPwd.Curve(group);
            var random = new SecureRandom();
            byte[] passwordBase = PwdCredential.ComputeBase(Salt, "fred", "barney");

            // The extra iterations use a random base, so the PE must not depend on them.
            var pe = EccPwd.PasswordElement(curve, passwordBase, Context, sha384: true, random);
            Assert.AreEqual(pe, EccPwd.PasswordElement(curve, passwordBase, Context, sha384: true, random));
            Assert.IsTrue(pe.IsValid());

            var server = EccPwd.Commit(curve, pe, random);
            var client = EccPwd.Commit(curve, pe, random);
            var (serverScalar, serverElement) = EccPwd.ReadCommit(curve, server.Element.GetEncoded(false), EccPwd.EncodeScalar(curve, server.Scalar));
            var (clientScalar, clientElement) = EccPwd.ReadCommit(curve, client.Element.GetEncoded(false), EccPwd.EncodeScalar(curve, client.Scalar));
            CollectionAssert.AreEqual(
                EccPwd.PreMasterSecret(pe, server.Private, clientScalar, clientElement),
                EccPwd.PreMasterSecret(pe, client.Private, serverScalar, serverElement));
        }

        [TestMethod]
        public void OpaqueString_MapsSpacesAndNormalizes()
        {
            CollectionAssert.AreEqual(Encoding.UTF8.GetBytes("a bé"), EccPwd.PrepareOpaqueString("a bé"));
            Assert.ThrowsExactly<ArgumentException>(() => EccPwd.PrepareOpaqueString("a\u0007"));
        }

        private static (Dtls12Client Client, Dtls12Server Server) Pair(ushort suite, string username, string password)
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { CipherSuites = new List<ushort> { suite }, PwdCredentialProvider = TestCredentials.ResolvePwd };
            var client = new Dtls12Client(pair.Client) { CipherSuites = new List<ushort> { suite }, PwdUsername = username, PwdPassword = password };
            client.InitialRetransmitTimeout = server.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(5);
            return (client, server);
        }

        private static Exception Run(Dtls12Client client)
        {
            var result = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => result.TrySetResult(null);
            client.Failed += (_, ex) => result.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(result.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return result.Task.Result;
        }

        [DataRow("fred", "wrong")]
        [DataRow("mallory", "barney")]
        [TestMethod]
        public void WrongPasswordAndUnknownUser_FailAlike(string username, string password)
        {
            // Unknown users are simulated (RFC 8492 §4.5.1.1): both cases end with the client's Finished
            // failing its MAC, being dropped, and the client giving up after retransmitting.
            var (client, server) = Pair(0xC0B0, username, password);
            Assert.IsInstanceOfType<TimeoutException>(Run(client));
            Assert.IsEmpty(server.Connections.Where(c => c.IsHandshakeComplete));
        }

        [TestMethod]
        public void SupportedGroups_PickTheClientsFirstPwdGroup()
        {
            var (client, _) = Pair(0xC0B1, TestCredentials.PwdUsername, TestCredentials.PwdPassword);
            Assert.IsNull(Run(client));
            Assert.AreEqual(EcdheGroups.Secp256r1, client.NamedGroup, "secp256r1 is the client's first TLS-PWD capable group");
        }
    }
}
