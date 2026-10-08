using Org.BouncyCastle.Crypto.Parameters;
using SharpDTLS;
using SharpDTLS.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>SRP (RFC 5054) failure handling; successful handshakes are covered by the cipher suite matrices.</summary>
    [TestClass]
    public sealed class TestSrp
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private const ushort Suite = 0xC01D; // TLS_SRP_SHA_WITH_AES_128_CBC_SHA

        private static (Dtls12Client Client, Dtls12Server Server) Pair(Func<byte[], SrpVerifier> verifiers, byte[] identity, byte[] password)
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { CipherSuites = new List<ushort> { Suite }, SrpVerifierProvider = verifiers };
            var client = new Dtls12Client(pair.Client) { CipherSuites = new List<ushort> { Suite }, SrpIdentity = identity, SrpPassword = password };
            return (client, server);
        }

        private static DtlsException Fail(Dtls12Client client)
        {
            var result = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => result.TrySetResult(null);
            client.Failed += (_, ex) => result.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(result.Task.Wait(Timeout), "the handshake neither completed nor failed");
            Assert.IsNotNull(result.Task.Result, "the handshake must fail");
            return result.Task.Result as DtlsException;
        }

        [TestMethod]
        public void UnknownUser_IsRejectedWithUnknownPskIdentity()
        {
            var (client, _) = Pair(TestCredentials.ResolveSrp, Encoding.ASCII.GetBytes("mallory"), TestCredentials.SrpPassword);
            Assert.AreEqual(AlertDescription.UnknownPskIdentity, Fail(client)?.Alert);
        }

        [TestMethod]
        public void WrongPassword_NeverCompletes()
        {
            // Both sides derive different keys: the client's Finished fails its MAC and is dropped (RFC 6347
            // §4.1.2.7), so the client retransmits until it gives up.
            var (client, server) = Pair(TestCredentials.ResolveSrp, TestCredentials.SrpIdentity, Encoding.ASCII.GetBytes("wrong"));
            client.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(5);
            server.InitialRetransmitTimeout = TimeSpan.FromMilliseconds(5);
            Fail(client);
            Assert.IsEmpty(server.Connections.Where(c => c.IsHandshakeComplete));
        }

        [TestMethod]
        public void NonStandardGroup_IsRejectedByTheClient()
        {
            // The FFDHE2048 prime is a safe prime, but not one of the RFC 5054 groups a client may trust.
            var ffdhe = FfdheGroups.Parameters(FfdheGroups.Ffdhe2048);
            var group = new Srp6GroupParameters(ffdhe.P, ffdhe.G);
            var generator = new Org.BouncyCastle.Crypto.Agreement.Srp.Srp6VerifierGenerator();
            generator.Init(group, new Org.BouncyCastle.Crypto.Digests.Sha1Digest());
            byte[] salt = { 1, 2, 3, 4 };
            var verifier = new SrpVerifier(group, salt, generator.GenerateVerifier(salt, TestCredentials.SrpIdentity, TestCredentials.SrpPassword));

            var (client, _) = Pair(_ => verifier, TestCredentials.SrpIdentity, TestCredentials.SrpPassword);
            Assert.AreEqual(AlertDescription.InsufficientSecurity, Fail(client)?.Alert);
        }

        [TestMethod]
        public void ClientWithoutSrpCredentials_DoesNotOfferSrp()
        {
            var pair = new ScriptedTransportPair();
            var server = new Dtls12Server(pair.Server) { SrpVerifierProvider = TestCredentials.ResolveSrp };
            var client = new Dtls12Client(pair.Client);
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.Failed += (_, ex) => done.TrySetException(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.IsFalse(client.CipherSuite.RequiresSrp);
        }
    }
}
