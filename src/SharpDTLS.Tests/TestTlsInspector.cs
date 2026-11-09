using SharpDTLS;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary><see cref="TlsInspector"/>: what it sees of each version's handshake, and messages it replaces.</summary>
    [TestClass]
    [DoNotParallelize] // the inspector is process-wide
    public sealed class TestTlsInspector
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;

        private sealed class Recorder : TlsInspector
        {
            public readonly List<(bool IsClient, bool Sent, byte Type, int MessageSeq)> Messages = new();
            public readonly HashSet<(bool IsClient, string Name)> Secrets = new();
            public readonly Dictionary<(bool IsClient, string Name), byte[]> SecretValues = new();
            public readonly List<(bool IsClient, ushort Group, byte[] Private, byte[] Public)> KeyPairs = new();
            public int Records;
            public Func<bool, byte[], byte[]> Edit;

            public override byte[] OnHandshakeSending(TlsConnectionBase connection, bool isClient, int messageSeq, byte[] message)
            {
                lock (this) Messages.Add((isClient, true, message[0], messageSeq));
                return Edit?.Invoke(isClient, message) ?? message;
            }

            public override void OnHandshakeReceived(TlsConnectionBase connection, bool isClient, int messageSeq, ReadOnlySpan<byte> message)
            {
                lock (this) Messages.Add((isClient, false, message[0], messageSeq));
            }

            public override void OnSecret(TlsConnectionBase connection, bool isClient, string name, ReadOnlySpan<byte> value)
            {
                Assert.IsTrue(value.Length > 0, name);
                lock (this)
                {
                    Secrets.Add((isClient, name));
                    SecretValues[(isClient, name)] = value.ToArray();
                }
            }

            public override void OnKeyExchange(TlsConnectionBase connection, bool isClient, ushort group, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
            {
                lock (this) KeyPairs.Add((isClient, group, privateKey.ToArray(), publicKey.ToArray()));
            }

            public int[] Sequences(bool isClient, bool sent)
            {
                lock (this) return Messages.Where(m => m.IsClient == isClient && m.Sent == sent).Select(m => m.MessageSeq).ToArray();
            }

            public override void OnProtectedRecord(TlsConnectionBase connection, bool isClient, bool sent, byte contentType, ulong epoch, ulong sequenceNumber, ReadOnlySpan<byte> content)
                => Interlocked.Increment(ref Records);

            public byte[] Types(bool isClient, bool sent)
            {
                lock (this) return Messages.Where(m => m.IsClient == isClient && m.Sent == sent).Select(m => m.Type).ToArray();
            }
        }

        [TestCleanup]
        public void Cleanup() => TlsInspector.Current = null;

        /// <summary>
        /// Inserts an unknown (GREASE, RFC 8701) extension first in a ClientHello: the server ignores it, and the handshake
        /// succeeds only when both transcripts hold the edited message.
        /// </summary>
        private static byte[] AddGrease(bool isClient, byte[] message, bool datagram)
        {
            if (!isClient || message[0] != 1)
                return message;
            int p = 4 + 2 + 32;
            p += 1 + message[p];                     // legacy_session_id
            if (datagram)
                p += 1 + message[p];                 // legacy_cookie
            p += 2 + ((message[p] << 8) | message[p + 1]);  // cipher_suites
            p += 1 + message[p];                     // legacy_compression_methods
            var edited = message.Take(p + 2).Concat(new byte[] { 0x0a, 0x0a, 0, 0 }).Concat(message.Skip(p + 2)).ToArray();
            int extensions = ((message[p] << 8) | message[p + 1]) + 4;
            edited[p] = (byte)(extensions >> 8); edited[p + 1] = (byte)extensions;
            int length = edited.Length - 4;
            edited[1] = (byte)(length >> 16); edited[2] = (byte)(length >> 8); edited[3] = (byte)length;
            return edited;
        }

        private static Exception Wait(Action<Action<Exception>> start)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            start(ex => done.TrySetResult(ex));
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            return done.Task.Result;
        }

        private static Exception DtlsHandshake(ushort version)
        {
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new DtlsServer(serverTransport);
            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, serverTransport.LocalEndpoint.Port));
            var client = new DtlsClient(clientTransport) { MinimumVersion = version, MaximumVersion = version };
            return Wait(done =>
            {
                client.HandshakeFinished += (_, _) => done(null);
                client.Failed += (_, ex) => done(ex);
                client.BeginHandshake();
            });
        }

        private static Exception TlsHandshake(ushort version) => TlsHandshake(version, null, out _);

        private static Exception TlsHandshake(ushort version, Action<TlsServer> configure, out TlsConnectionBase clientConnection)
        {
            using var server = new TlsServer();
            configure?.Invoke(server);
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            using var tcp = new TcpClient();
            tcp.Connect(server.LocalEndpoint);
            var client = new TlsClient(tcp.GetStream()) { MinimumVersion = version, MaximumVersion = version };
            clientConnection = null;
            var error = Wait(done =>
            {
                client.HandshakeFinished += (_, _) => done(null);
                client.Failed += (_, ex) => done(ex);
                client.BeginHandshake();
            });
            // The server's last messages may still be processed after the client finished.
            SpinWait.SpinUntil(() => server.Connections.Any(c => c.IsHandshakeComplete), Timeout);
            clientConnection = client.Connection;
            return error;
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Dtls13_ReportsMessagesSecretsAndRecords(bool edit)
        {
            var recorder = new Recorder { Edit = edit ? (c, m) => AddGrease(c, m, datagram: true) : null };
            TlsInspector.Current = recorder;
            Assert.IsNull(DtlsHandshake(DtlsVersion.Dtls13));
            Assert.IsTrue(SpinWait.SpinUntil(() => recorder.Types(false, false).Contains((byte)20), Timeout));

            // The server's stateless cookie exchange: ClientHello, HelloRetryRequest, ClientHello again.
            CollectionAssert.AreEqual(new byte[] { 1, 1, 20 }, recorder.Types(true, true));
            CollectionAssert.AreEqual(new byte[] { 2, 2, 8, 11, 15, 20 }, recorder.Types(true, false).Take(6).ToArray());
            CollectionAssert.AreEqual(new byte[] { 2, 2, 8, 11, 15, 20 }, recorder.Types(false, true).Take(6).ToArray());
            CollectionAssert.AreEqual(new byte[] { 1, 1, 20 }, recorder.Types(false, false));
            foreach (bool isClient in new[] { true, false })
                foreach (string name in new[] { TlsInspector.SharedSecret, TlsInspector.HelloHash, TlsInspector.HandshakeSecret, TlsInspector.ClientHandshakeKey,
                                                TlsInspector.ServerHandshakeSnKey, TlsInspector.MasterSecret, TlsInspector.ServerApplicationIv, TlsInspector.ExporterMasterSecret })
                    Assert.IsTrue(recorder.Secrets.Contains((isClient, name)), $"{name} ({(isClient ? "client" : "server")})");
            Assert.IsTrue(recorder.Records >= 8);
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Dtls12_ReportsMessagesAndSecrets(bool edit)
        {
            var recorder = new Recorder { Edit = edit ? (c, m) => AddGrease(c, m, datagram: true) : null };
            TlsInspector.Current = recorder;
            Assert.IsNull(DtlsHandshake(DtlsVersion.Dtls12));
            // HelloVerifyRequest (3) asks for the ClientHello again with the cookie.
            CollectionAssert.AreEqual(new byte[] { 1, 1, 16, 20 }, recorder.Types(true, true));
            CollectionAssert.AreEqual(new byte[] { 3, 2, 11, 12, 14, 4, 20 }, recorder.Types(true, false));
            CollectionAssert.AreEqual(new byte[] { 3, 2, 11, 12, 14, 4, 20 }, recorder.Types(false, true));
            foreach (string name in new[] { TlsInspector.PreMasterSecret, TlsInspector.MasterSecret, TlsInspector.KeyBlock })
                Assert.IsTrue(recorder.Secrets.Contains((false, name)), name);
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Tls13_ReportsMessagesAndSecrets(bool edit)
        {
            var recorder = new Recorder { Edit = edit ? (c, m) => AddGrease(c, m, datagram: false) : null };
            TlsInspector.Current = recorder;
            Assert.IsNull(TlsHandshake(TlsVersion.Tls13));

            CollectionAssert.AreEqual(new byte[] { 1, 20 }, recorder.Types(true, true));
            CollectionAssert.AreEqual(new byte[] { 2, 8, 11, 15, 20 }, recorder.Types(true, false).Take(5).ToArray());
            Assert.IsTrue(recorder.Secrets.Contains((true, TlsInspector.ClientApplicationTrafficSecret)));
            Assert.IsFalse(recorder.Secrets.Contains((true, TlsInspector.ClientHandshakeSnKey)), "TLS has no record number encryption");
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Tls12_ReportsMessagesAndSecrets(bool edit)
        {
            var recorder = new Recorder { Edit = edit ? (c, m) => AddGrease(c, m, datagram: false) : null };
            TlsInspector.Current = recorder;
            Assert.IsNull(TlsHandshake(TlsVersion.Tls12));

            byte[] sent = recorder.Types(true, true);
            CollectionAssert.AreEqual(new byte[] { 1, 16, 20 }, sent);
            CollectionAssert.AreEqual(new byte[] { 2, 11, 12, 14 }, recorder.Types(true, false).Take(4).ToArray());
            foreach (string name in new[] { TlsInspector.PreMasterSecret, TlsInspector.MasterSecret, TlsInspector.KeyBlock })
                Assert.IsTrue(recorder.Secrets.Contains((true, name)), name);
            Assert.IsTrue(recorder.Records >= 2, "the Finished messages are protected");
        }

        [TestMethod]
        public void TamperedFinished_FailsTheHandshake()
        {
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, message) =>
                {
                    if (!isClient || message[0] != 20)
                        return message;
                    var edited = (byte[])message.Clone();
                    edited[4] ^= 1;
                    return edited;
                },
            };
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new DtlsServer(serverTransport);
            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, serverTransport.LocalEndpoint.Port));
            var client = new DtlsClient(clientTransport);
            var alert = new TaskCompletionSource<AlertDescription>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.AlertReceived += (_, description) => alert.TrySetResult(description);
            client.BeginHandshake();
            Assert.IsTrue(alert.Task.Wait(Timeout), "the server rejects the client Finished");
            Assert.AreEqual(AlertDescription.DecryptError, alert.Task.Result);
        }

        // ── Key exchange reports ─────────────────────────────────────────────────────────────

        private static byte[] X25519(byte[] privateKey, byte[] peerPublic)
        {
            var agreement = new Org.BouncyCastle.Crypto.Agreement.X25519Agreement();
            agreement.Init(new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(privateKey));
            byte[] secret = new byte[32];
            agreement.CalculateAgreement(new Org.BouncyCastle.Crypto.Parameters.X25519PublicKeyParameters(peerPublic), secret, 0);
            return secret;
        }

        [DataRow((ushort)0x0304)]
        [DataRow((ushort)0x0303)]
        [TestMethod]
        public void KeyExchange_ReportsEphemeralKeysThatReproduceTheSharedSecret(ushort version)
        {
            var recorder = new Recorder();
            TlsInspector.Current = recorder;
            // x25519 alone, so each side generates exactly one key pair.
            Assert.IsNull(TlsHandshake(version, s => s.SupportedGroups = new List<ushort> { NamedGroups.X25519 }, out _));

            // A TLS 1.3 client also shares X25519MLKEM768 by default: its x25519 component is a second x25519 pair.
            var server = recorder.KeyPairs.Single(k => !k.IsClient && k.Group == NamedGroups.X25519);
            string secret = version == 0x0304 ? TlsInspector.SharedSecret : TlsInspector.PreMasterSecret;
            var client = recorder.KeyPairs.Single(k => k.IsClient && k.Group == NamedGroups.X25519
                && X25519(k.Private, server.Public).AsSpan().SequenceEqual(recorder.SecretValues[(true, secret)]));
            Assert.AreEqual(32, client.Private.Length);
            CollectionAssert.AreEqual(recorder.SecretValues[(false, secret)], X25519(server.Private, client.Public));
        }

        [TestMethod]
        public void KeyExchange_ReportsBothPartsOfAHybridShare()
        {
            var recorder = new Recorder();
            TlsInspector.Current = recorder;
            Assert.IsNull(TlsHandshake(TlsVersion.Tls13, s => s.SupportedGroups = new List<ushort> { NamedGroups.X25519MlKem768 }, out _));
            Assert.IsTrue(recorder.KeyPairs.Any(k => k.IsClient && k.Group == NamedGroups.MlKem768 && k.Public.Length == 1184));
            var server = recorder.KeyPairs.Single(k => !k.IsClient && k.Group == NamedGroups.X25519);
            // X25519MLKEM768: shared secret = ML-KEM secret (32) || X25519 secret (32); the hybrid's x25519 pair gives the second half.
            byte[] ecdhPart = recorder.SecretValues[(true, TlsInspector.SharedSecret)].AsSpan(32).ToArray();
            Assert.IsTrue(recorder.KeyPairs.Any(k => k.IsClient && k.Group == NamedGroups.X25519 && X25519(k.Private, server.Public).AsSpan().SequenceEqual(ecdhPart)));
        }

        [TestMethod]
        public void Dtls12_ReportsMessageSequenceNumbers()
        {
            var recorder = new Recorder();
            TlsInspector.Current = recorder;
            Assert.IsNull(DtlsHandshake(DtlsVersion.Dtls12));
            // ClientHello, ClientHello with the cookie, ClientKeyExchange, Finished.
            CollectionAssert.AreEqual(new[] { 0, 1, 2, 3 }, recorder.Sequences(true, true));
        }

        [TestMethod]
        public void Tls_ReportsNoMessageSequenceNumbers()
        {
            var recorder = new Recorder();
            TlsInspector.Current = recorder;
            Assert.IsNull(TlsHandshake(TlsVersion.Tls13));
            Assert.IsTrue(recorder.Sequences(true, true).Concat(recorder.Sequences(true, false)).All(s => s == -1));
        }

        // ── Edits the engines follow ─────────────────────────────────────────────────────────

        /// <summary>A copy of a hello (TLS form) with bytes replaced at <paramref name="offset"/>.</summary>
        private static byte[] Patch(byte[] message, int offset, params byte[] value)
        {
            var edited = (byte[])message.Clone();
            value.CopyTo(edited, offset);
            return edited;
        }

        private const int RandomOffset = 4 + 2;            // after the header and legacy_version
        private const int SessionIdOffset = 4 + 2 + 32;    // its length byte

        private static int SuiteOffset(byte[] serverHello) => SessionIdOffset + 1 + serverHello[SessionIdOffset];

        /// <summary>A copy of a hello with its legacy_session_id replaced (lengths fixed up).</summary>
        private static byte[] WithSessionId(byte[] hello, byte[] sessionId)
        {
            int old = hello[SessionIdOffset];
            var edited = hello.Take(SessionIdOffset).Append((byte)sessionId.Length).Concat(sessionId).Concat(hello.Skip(SessionIdOffset + 1 + old)).ToArray();
            int length = edited.Length - 4;
            edited[1] = (byte)(length >> 16); edited[2] = (byte)(length >> 8); edited[3] = (byte)length;
            return edited;
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Tls12_EditedRandomIsAdopted(bool client)
        {
            byte[] random = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) => isClient == client && m[0] == (client ? 1 : 2) ? Patch(m, RandomOffset, random) : m,
            };
            // The randoms feed the master secret and key block in TLS 1.2: both sides must use the edited one.
            Assert.IsNull(TlsHandshake(TlsVersion.Tls12, null, out var connection));
            CollectionAssert.AreEqual(random, client ? connection.ClientRandom : connection.ServerRandom);
        }

        [TestMethod]
        public void Tls12_EditedServerSuiteIsAdopted()
        {
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) => !isClient && m[0] == 2 ? Patch(m, SuiteOffset(m), 0xC0, 0x30) : m,
            };
            // ECDHE_RSA_WITH_AES_128_GCM_SHA256 to ECDHE_RSA_WITH_AES_256_GCM_SHA384: same key exchange, other keys and PRF.
            Assert.IsNull(TlsHandshake(TlsVersion.Tls12, s => s.CipherSuites = new List<ushort> { 0xC02F }, out var connection));
            Assert.AreEqual((ushort)0xC030, connection.NegotiatedCipherSuite);
        }

        [TestMethod]
        public void Tls12_RemovedExtendedMasterSecretIsAdopted()
        {
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) =>
                {
                    if (isClient || m[0] != 2)
                        return m;
                    // Find extended_master_secret (type 23, empty) in the ServerHello extensions and drop it.
                    int p = SuiteOffset(m) + 3, end = p + 2 + ((m[p] << 8) | m[p + 1]);
                    for (int q = p + 2; q < end; q += 4 + ((m[q + 2] << 8) | m[q + 3]))
                    {
                        if (m[q] == 0 && m[q + 1] == 23)
                        {
                            var edited = m.Take(q).Concat(m.Skip(q + 4)).ToArray();
                            int extensions = end - p - 2 - 4, length = edited.Length - 4;
                            edited[p] = (byte)(extensions >> 8); edited[p + 1] = (byte)extensions;
                            edited[1] = (byte)(length >> 16); edited[2] = (byte)(length >> 8); edited[3] = (byte)length;
                            return edited;
                        }
                    }
                    return m;
                },
            };
            Assert.IsNull(TlsHandshake(TlsVersion.Tls12, null, out var connection));
            Assert.IsFalse(connection.IsExtendedMasterSecret);
        }

        [TestMethod]
        public void Tls13_EditedServerSuiteIsAdopted()
        {
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) => !isClient && m[0] == 2 ? Patch(m, SuiteOffset(m), 0x13, 0x02) : m,
            };
            // TLS_AES_128_GCM_SHA256 to TLS_AES_256_GCM_SHA384: the key schedule switches to SHA-384.
            Assert.IsNull(TlsHandshake(TlsVersion.Tls13, s => s.CipherSuites = new List<ushort> { 0x1301 }, out var connection));
            Assert.AreEqual((ushort)0x1302, connection.NegotiatedCipherSuite);
        }

        [TestMethod]
        public void Tls13_EditedSessionIdIsAdopted()
        {
            // A TLS 1.3 server echoes legacy_session_id, and the client checks the echo against what it sent.
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) => isClient && m[0] == 1 ? WithSessionId(m, Enumerable.Repeat((byte)0x11, 32).ToArray()) : m,
            };
            Assert.IsNull(TlsHandshake(TlsVersion.Tls13, null, out _));
        }

        [TestMethod]
        public void Tls13_EditedKeyShareIsNotFollowed()
        {
            // The engine cannot follow a key share it has no private key for: the peers compute different secrets.
            TlsInspector.Current = new Recorder
            {
                Edit = (isClient, m) =>
                {
                    if (isClient || m[0] != 2)
                        return m;
                    var edited = (byte[])m.Clone();
                    edited[^1] ^= 1; // the last byte of the server's key share (key_share is the last extension)
                    return edited;
                },
            };
            Assert.IsNotNull(TlsHandshake(TlsVersion.Tls13, s => s.SupportedGroups = new List<ushort> { NamedGroups.X25519 }, out _));
        }
    }
}
