using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>One in-memory handshake with either engine, exposing both ends through <see cref="TlsConnectionBase"/>.</summary>
    internal sealed class EngineRun
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;

        public readonly ScriptedTransportPair Pair = new();
        public TlsConnectionBase Client;
        public Func<TlsConnectionBase> ServerConnection;
        public Exception Error;

        public static EngineRun Connect(int version, ushort[] srtpProfiles = null, byte[] clientMki = null, bool disableMki = false,
            (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate)? clientCredentials = null, Action<ScriptedTransportPair> configurePair = null)
        {
            var r = new EngineRun();
            configurePair?.Invoke(r.Pair);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            Action begin;

            if (version == 12)
            {
                var server = new Dtls12Server(r.Pair.Server) { SrtpProtectionProfiles = srtpProfiles, SrtpDisableMki = disableMki, RequireClientCertificate = clientCredentials != null };
                var client = new Dtls12Client(r.Pair.Client) { SrtpProtectionProfiles = srtpProfiles, SrtpMasterKeyIdentifier = clientMki };
                if (clientCredentials != null)
                    (client.ClientCertificateKeyPair, client.ClientCertificate) = clientCredentials.Value;
                client.HandshakeFinished += (_, _) => done.TrySetResult(null);
                r.Client = client;
                r.ServerConnection = () => server.Connections.SingleOrDefault();
                begin = client.BeginHandshake;
            }
            else
            {
                var server = new Dtls13Server(r.Pair.Server) { SrtpProtectionProfiles = srtpProfiles, SrtpDisableMki = disableMki, RequireClientCertificate = clientCredentials != null };
                var client = new Dtls13Client(r.Pair.Client) { SrtpProtectionProfiles = srtpProfiles, SrtpMasterKeyIdentifier = clientMki };
                if (clientCredentials != null)
                    (client.ClientCertificateKeyPair, client.ClientCertificate) = clientCredentials.Value;
                client.HandshakeFinished += (_, _) => done.TrySetResult(null);
                r.Client = client;
                r.ServerConnection = () => server.Connections.SingleOrDefault();
                begin = client.BeginHandshake;
            }

            r.Client.Failed += (_, ex) => done.TrySetResult(ex);
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            r.Error = done.Task.Result;
            if (r.Error == null)
                Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerConnection()?.IsHandshakeComplete == true, Timeout), "the server did not complete the handshake");
            return r;
        }
    }

    /// <summary>SRTP Master Key Identifier negotiation with use_srtp (RFC 5764 §4.1.1) in both engines.</summary>
    [TestClass]
    public sealed class TestSrtpMki
    {
        private static readonly ushort[] Profiles = { DtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80 };
        private static readonly byte[] Mki = { 0xA1, 0xB2, 0xC3, 0xD4 };

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void ClientMki_IsEchoedAndPartOfTheKeys(int version)
        {
            var r = EngineRun.Connect(version, Profiles, Mki);
            Assert.IsNull(r.Error, r.Error?.ToString());

            var server = r.ServerConnection();
            CollectionAssert.AreEqual(Mki, r.Client.SelectedSrtpMki);
            CollectionAssert.AreEqual(Mki, server.SelectedSrtpMki);

            var clientKeys = r.Client.GetSrtpKeys();
            var serverKeys = server.GetSrtpKeys();
            CollectionAssert.AreEqual(Mki, clientKeys.Mki);
            CollectionAssert.AreEqual(Mki, serverKeys.Mki);
            CollectionAssert.AreEqual(clientKeys.ClientWriteKey, serverKeys.ClientWriteKey);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void SrtpDisableMki_AnswersWithAnEmptyMki(int version)
        {
            var r = EngineRun.Connect(version, Profiles, Mki, disableMki: true);
            Assert.IsNull(r.Error, r.Error?.ToString());

            Assert.IsEmpty(r.Client.SelectedSrtpMki);
            Assert.IsEmpty(r.ServerConnection().SelectedSrtpMki);
            Assert.IsEmpty(r.Client.GetSrtpKeys().Mki);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void WithoutClientMki_NoMkiIsUsed(int version)
        {
            var r = EngineRun.Connect(version, Profiles);
            Assert.IsNull(r.Error, r.Error?.ToString());

            Assert.IsEmpty(r.Client.SelectedSrtpMki);
            Assert.IsEmpty(r.ServerConnection().SelectedSrtpMki);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void WithoutUseSrtp_MkiIsNull(int version)
        {
            var r = EngineRun.Connect(version, srtpProfiles: null, clientMki: Mki);
            Assert.IsNull(r.Error, r.Error?.ToString());

            Assert.IsNull(r.Client.SelectedSrtpProtectionProfile);
            Assert.IsNull(r.Client.SelectedSrtpMki);
            Assert.IsNull(r.ServerConnection().SelectedSrtpMki);
        }

        [TestMethod]
        public void Dtls12_ServerMkiOtherThanOffered_IsIllegalParameter()
        {
            // The ServerHello travels in plaintext: change the echoed MKI's last byte.
            var r = EngineRun.Connect(12, Profiles, Mki, configurePair: pair => pair.ServerToClient = d =>
            {
                var copy = (byte[])d.Clone();
                int at = copy.AsSpan().IndexOf(new byte[] { (byte)Mki.Length }.Concat(Mki).ToArray());
                if (at >= 0)
                    copy[at + Mki.Length] ^= 0xFF;
                return new[] { copy };
            });

            Assert.AreEqual(AlertDescription.IllegalParameter, (r.Error as DtlsException)?.Alert, r.Error?.ToString());
        }

        [TestMethod]
        public void AcceptServerMki_FollowsRfc5764()
        {
            CollectionAssert.AreEqual(Mki, DtlsSrtp.AcceptServerMki(Mki, Mki), "echoed");
            Assert.IsEmpty(DtlsSrtp.AcceptServerMki(Mki, Array.Empty<byte>()), "declined by the server");
            Assert.IsEmpty(DtlsSrtp.AcceptServerMki(null, null), "none offered");
            var error = Assert.ThrowsExactly<DtlsException>(() => DtlsSrtp.AcceptServerMki(Mki, new byte[] { 1 }));
            Assert.AreEqual(AlertDescription.IllegalParameter, error.Alert);
            Assert.ThrowsExactly<DtlsException>(() => DtlsSrtp.AcceptServerMki(null, new byte[] { 1 }));
        }

        [TestMethod]
        public void MkiLongerThan255Bytes_IsRejected()
        {
            var client = new Dtls12Client(new ScriptedTransportPair().Client);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.SrtpMasterKeyIdentifier = new byte[256]);
            client.SrtpMasterKeyIdentifier = new byte[255];
        }
    }

    /// <summary>The version-independent negotiated parameters on <see cref="TlsConnectionBase"/>.</summary>
    [TestClass]
    public sealed class TestNegotiatedParameters
    {
        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void BothSides_ReportTheSameParameters(int version)
        {
            var clientCredentials = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            var r = EngineRun.Connect(version, clientCredentials: clientCredentials);
            Assert.IsNull(r.Error, r.Error?.ToString());
            var client = r.Client;
            var server = r.ServerConnection();

            ushort expectedVersion = version == 12 ? DtlsVersion.Dtls12 : DtlsVersion.Dtls13;
            Assert.AreEqual(expectedVersion, client.NegotiatedVersion);
            Assert.AreEqual(expectedVersion, server.NegotiatedVersion);

            Assert.AreNotEqual((ushort)0, client.NegotiatedCipherSuite);
            Assert.AreEqual(client.NegotiatedCipherSuite, server.NegotiatedCipherSuite);

            Assert.AreEqual(32, client.ClientRandom?.Length);
            Assert.AreEqual(32, client.ServerRandom?.Length);
            CollectionAssert.AreEqual(client.ClientRandom, server.ClientRandom);
            CollectionAssert.AreEqual(client.ServerRandom, server.ServerRandom);

            Assert.IsTrue(client.IsExtendedMasterSecret);
            Assert.IsTrue(server.IsExtendedMasterSecret);
            Assert.IsFalse(client.IsResumed);
            Assert.IsFalse(server.IsResumed);

            Assert.AreEqual(clientCredentials.certificate, client.LocalCertificate);
            Assert.AreEqual(clientCredentials.certificate, server.PeerCertificate);
            Assert.IsNotNull(server.LocalCertificate);
            Assert.AreEqual(server.LocalCertificate, client.PeerCertificate);
        }
    }
}
