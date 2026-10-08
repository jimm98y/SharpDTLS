using SharpDTLS;
using SharpDTLS.DTLS13;
using SharpDTLS.DTLS13.Messages;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// In-memory transport pair whose links can drop, reorder or duplicate datagrams.
    /// Delivery is synchronous, like <see cref="MockTransportPair"/>.
    /// </summary>
    internal sealed class ScriptedTransportPair
    {
        public static readonly EndPoint ClientEndpoint = IPEndPoint.Parse("127.0.0.1:49152");

        public readonly ServerSide Server;
        public readonly ClientSide Client;

        /// <summary>Called for every datagram; return the datagrams to actually deliver (empty to drop).</summary>
        public Func<byte[], IEnumerable<byte[]>> ClientToServer = d => new[] { d };
        public Func<byte[], IEnumerable<byte[]>> ServerToClient = d => new[] { d };

        public readonly List<byte[]> ClientSent = new();
        public readonly List<byte[]> ServerSent = new();

        /// <summary>The address the client's datagrams arrive from (change it to simulate NAT rebinding).</summary>
        public EndPoint ClientAddress = ClientEndpoint;

        /// <summary>The address of every datagram the server sent.</summary>
        public readonly List<EndPoint> ServerSentTo = new();

        public ScriptedTransportPair()
        {
            Server = new ServerSide(this);
            Client = new ClientSide(this);
        }

        public sealed class ServerSide : IServerTransport
        {
            private readonly ScriptedTransportPair _pair;
            public ServerSide(ScriptedTransportPair pair) => _pair = pair;
            public event EventHandler<byte[]> OnDataReceived;

            public void Send(EndPoint endpoint, byte[] buf)
            {
                lock (_pair.ServerSent) { _pair.ServerSent.Add(buf); _pair.ServerSentTo.Add(endpoint); }
                foreach (var d in _pair.ServerToClient(buf).ToList())
                    _pair.Client.Deliver(d);
            }

            public void Deliver(byte[] data) => OnDataReceived?.Invoke(_pair.ClientAddress, data);

            /// <summary>Delivers a datagram as if it came from another client (e.g. an attacker replaying one).</summary>
            public void Deliver(EndPoint from, byte[] data) => OnDataReceived?.Invoke(from, data);
        }

        public sealed class ClientSide : IClientTransport
        {
            private readonly ScriptedTransportPair _pair;
            public ClientSide(ScriptedTransportPair pair) => _pair = pair;
            public event EventHandler<byte[]> OnDataReceived;

            public void Send(byte[] buf)
            {
                lock (_pair.ClientSent) _pair.ClientSent.Add(buf);
                foreach (var d in _pair.ClientToServer(buf).ToList())
                    _pair.Server.Deliver(d);
            }

            public void Deliver(byte[] data) => OnDataReceived?.Invoke(null, data);
        }
    }

    [TestClass]
    public sealed class TestDtls13Protocol
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private sealed class Harness
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public TaskCompletionSource<bool> ServerDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public TaskCompletionSource<bool> ClientDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public List<string> ServerReceived = new();
            public List<string> ClientReceived = new();
            public List<Exception> ClientErrors = new();
            public List<Exception> ServerErrors = new();

            public Harness(Action<Dtls13Server> configureServer = null, Action<Dtls13Client> configureClient = null)
            {
                Server = new Dtls13Server(Pair.Server) { InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
                Client = new Dtls13Client(Pair.Client) { InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
                configureServer?.Invoke(Server);
                configureClient?.Invoke(Client);

                Server.HandshakeFinished += (_, args) =>
                {
                    var connection = ((Dtls13ConnectionEventArgs)args).Connection;
                    connection.Failed += (_, ex) => { lock (ServerErrors) ServerErrors.Add(ex); };
                    ServerDone.TrySetResult(true);
                };
                Server.ApplicationDataReceived += (_, e) => { lock (ServerReceived) ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
                Client.HandshakeFinished += (_, _) => ClientDone.TrySetResult(true);
                Client.ApplicationDataReceived += (_, data) => { lock (ClientReceived) ClientReceived.Add(Encoding.UTF8.GetString(data)); };
                Client.Failed += (_, ex) => { lock (ClientErrors) ClientErrors.Add(ex); ClientDone.TrySetException(ex); };
            }

            public void Handshake()
            {
                Client.BeginHandshake();
                Assert.IsTrue(Task.WhenAll(ClientDone.Task, ServerDone.Task).Wait(Timeout), "Handshake did not complete in time");
            }

            public Tls13ServerConnection ServerConnection => Server.GetConnection(ScriptedTransportPair.ClientEndpoint);
        }

        [DataRow((ushort)0x1301)]
        [DataRow((ushort)0x1302)]
        [DataRow((ushort)0x1303)]
        [DataRow((ushort)0x1304)]
        [DataRow((ushort)0x1305)]
        [DataRow((ushort)0x1306)]
        [DataRow((ushort)0x1307)]
        [DataRow((ushort)0xC0B4)]
        [DataRow((ushort)0xC0B5)]
        [TestMethod]
        public void Handshake_WithHelloRetryRequest_EachCipherSuite(ushort suite)
        {
            var h = new Harness(
                configureServer: s => s.CipherSuites = new List<ushort> { suite },
                configureClient: c => c.CipherSuites = new List<ushort> { suite });
            h.Handshake();

            Assert.AreEqual(suite, h.Client.Session.CipherSuite.Id);
            Assert.AreEqual(suite, h.ServerConnection.Session.CipherSuite.Id);

            // the first ClientHello must have been answered with a HelloRetryRequest
            byte[] first = h.Pair.ServerSent[0];
            Assert.IsTrue(first.AsSpan(27, 32).SequenceEqual(HelloRetryRequest.HelloRetryRequestRandom), "Expected a HelloRetryRequest");

            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes("pong"));
            CollectionAssert.AreEqual(new[] { "ping" }, h.ServerReceived);
            CollectionAssert.AreEqual(new[] { "pong" }, h.ClientReceived);
        }

        [DataRow((ushort)0x1304)]
        [DataRow((ushort)0x1305)]
        [DataRow((ushort)0x1306)]
        [DataRow((ushort)0x1307)]
        [DataRow((ushort)0xC0B4)]
        [DataRow((ushort)0xC0B5)]
        [TestMethod]
        public void RecordLayer_ShortRecordsManyRecordsAndKeyUpdates_EachAdditionalSuite(ushort suite)
        {
            var h = new Harness(
                configureServer: s => { s.CipherSuites = new List<ushort> { suite }; s.ShouldSendHelloRetry = false; },
                configureClient: c => c.CipherSuites = new List<ushort> { suite });
            h.Handshake();

            // One-byte records stay at least 16 bytes of ciphertext (padded for CCM_8's 8-byte tag).
            for (int i = 0; i < 300; i++)
            {
                h.Client.SendApplicationData(Encoding.UTF8.GetBytes(((char)('a' + i % 26)).ToString()));
                h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes($"s{i}"));
            }
            Assert.HasCount(300, h.ServerReceived);
            Assert.AreEqual("s299", h.ClientReceived[^1]);

            h.Client.SendKeyUpdate(requestUpdate: true);
            for (int i = 0; i < 4; i++)
                h.Server.SendKeyUpdate(ScriptedTransportPair.ClientEndpoint);
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("after-update"));
            h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes("after-update"));
            Assert.AreEqual("after-update", h.ServerReceived[^1]);
            Assert.AreEqual("after-update", h.ClientReceived[^1]);
        }

        [DataRow((ushort)0xC0B4, 32)]
        [DataRow((ushort)0xC0B5, 48)]
        [TestMethod]
        public void IntegrityOnly_SendsPlaintextAndClearRecordNumbers(ushort suite, int tagLength)
        {
            var h = new Harness(
                configureServer: s => { s.CipherSuites = new List<ushort> { suite }; s.ShouldSendHelloRetry = false; },
                configureClient: c => c.CipherSuites = new List<ushort> { suite });
            h.Handshake();

            int before = h.Pair.ClientSent.Count;
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("visible-on-the-wire"));
            byte[] record = h.Pair.ClientSent.Skip(before).Single();

            // RFC 9150: DTLSInnerPlaintext || HMAC, with the 16-bit record number in the clear (§9).
            Assert.AreEqual(0x2C, record[0] & 0xFC, "unified header with 16-bit sequence number and length");
            ulong sequenceNumber = (ulong)((record[1] << 8) | record[2]);
            Assert.AreEqual(h.Client.Session.WriteKeys.ClientKeyUseCounter - 1, sequenceNumber);
            Assert.AreEqual("visible-on-the-wire\u0017", Encoding.ASCII.GetString(record, 5, record.Length - 5 - tagLength));
            CollectionAssert.AreEqual(new[] { "visible-on-the-wire" }, h.ServerReceived);
            Assert.IsTrue(Dtls13CipherSuite.Get(suite).IsIntegrityOnly);
        }

        [TestMethod]
        public void DefaultSuites_AreGcmAndChaCha20Only()
        {
            CollectionAssert.AreEqual(new ushort[] { 0x1301, 0x1302, 0x1303 }, Dtls13CipherSuite.Supported);
            Assert.HasCount(9, Dtls13CipherSuite.All);
        }

        [TestMethod]
        public void Handshake_ServerPrefersItsOwnCipherSuiteOrder()
        {
            var h = new Harness(
                configureServer: s => s.CipherSuites = new List<ushort> { 0x1303, 0x1301 },
                configureClient: c => c.CipherSuites = new List<ushort> { 0x1301, 0x1302, 0x1303 });
            h.Handshake();
            Assert.AreEqual((ushort)0x1303, h.Client.Session.CipherSuite.Id);
        }

        [TestMethod]
        public void Handshake_NoCommonCipherSuite_FailsWithHandshakeFailure()
        {
            var h = new Harness(
                configureServer: s => s.CipherSuites = new List<ushort> { 0x1301 },
                configureClient: c => c.CipherSuites = new List<ushort> { 0x1303 });

            h.Client.BeginHandshake();

            Assert.IsFalse(h.Client.IsHandshakeComplete);
            Assert.IsTrue(h.Client.IsClosed, "Client should close after the server's alert");
            var error = h.ClientErrors.OfType<DtlsException>().Single();
            Assert.AreEqual(AlertDescription.HandshakeFailure, error.Alert);
        }

        [TestMethod]
        public void ApplicationData_ManyRecords_NonceIsCorrectBeyond256Records()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();

            for (int i = 0; i < 700; i++)
            {
                h.Client.SendApplicationData(Encoding.UTF8.GetBytes($"c{i}"));
                h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes($"s{i}"));
            }

            Assert.HasCount(700, h.ServerReceived);
            Assert.HasCount(700, h.ClientReceived);
            Assert.AreEqual("c699", h.ServerReceived[^1]);
            Assert.AreEqual("s699", h.ClientReceived[^1]);
        }

        [TestMethod]
        public void KeyUpdate_BothDirections_AdvancesEpochsAndKeepsDataFlowing()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();

            ulong clientEpoch = h.Client.Session.WriteKeys.Epoch;
            ulong serverEpoch = h.ServerConnection.Session.WriteKeys.Epoch;

            h.Client.SendKeyUpdate(requestUpdate: true);

            Assert.AreEqual(clientEpoch + 1, h.Client.Session.WriteKeys.Epoch, "client write epoch should advance once its KeyUpdate is ACKed");
            Assert.AreEqual(serverEpoch + 1, h.ServerConnection.Session.WriteKeys.Epoch, "server should update in response to update_requested");

            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("after-update"));
            h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes("after-update"));
            CollectionAssert.AreEqual(new[] { "after-update" }, h.ServerReceived);
            CollectionAssert.AreEqual(new[] { "after-update" }, h.ClientReceived);

            // several more updates, including wrap-around of the 2-bit epoch field
            for (int i = 0; i < 5; i++)
                h.Server.SendKeyUpdate(ScriptedTransportPair.ClientEndpoint);
            h.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes("epoch-wrap"));
            Assert.AreEqual("epoch-wrap", h.ClientReceived[^1]);
        }

        [TestMethod]
        public void LostServerFlight_IsRetransmitted()
        {
            // Without tickets, so a NewSessionTicket does not count as a retransmission.
            var h = new Harness(configureServer: s => { s.ShouldSendHelloRetry = false; s.TicketKeys = null; });
            int serverDatagrams = 0;
            h.Pair.ServerToClient = d => Interlocked.Increment(ref serverDatagrams) == 3 ? Array.Empty<byte[]>() : new[] { d };

            h.Handshake();
            Assert.IsGreaterThan(6, h.Pair.ServerSent.Count, "Server flight should have been retransmitted");
        }

        [TestMethod]
        public void LostClientFinished_IsRetransmittedUntilAcked()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            int clientDatagrams = 0;
            // datagram 1 = ClientHello, datagram 2 = client Finished
            h.Pair.ClientToServer = d => Interlocked.Increment(ref clientDatagrams) == 2 ? Array.Empty<byte[]>() : new[] { d };

            h.Handshake();
            Assert.IsTrue(h.ServerConnection.IsHandshakeComplete);
        }

        [TestMethod]
        public void LostHelloRetryRequest_ClientRetransmitsClientHello()
        {
            var h = new Harness();
            int serverDatagrams = 0;
            h.Pair.ServerToClient = d => Interlocked.Increment(ref serverDatagrams) == 1 ? Array.Empty<byte[]>() : new[] { d };

            h.Handshake();
        }

        [TestMethod]
        public void FragmentedClientHello_IsReassembledByServer()
        {
            // Small path MTU: every ClientHello is split into several records, delivered in one datagram
            // or in separate datagrams.
            var h = new Harness();
            int count = 0;
            h.Pair.ClientToServer = d =>
            {
                if (d[0] != 0x16 || d[13] != 0x01) return new[] { d };
                int seq = 0;
                var fragments = HandshakeFragmenter.FragmentUnencryptedRecord((byte[])d.Clone(), 120, ref seq);
                Assert.IsGreaterThan(1, fragments.Count);
                return Interlocked.Increment(ref count) == 1 ? new[] { fragments.SelectMany(f => f).ToArray() } : fragments.ToArray();
            };

            h.Handshake();
        }

        [TestMethod]
        public void DuplicatedHelloRetryRequest_IsIgnored()
        {
            // A retransmitted ClientHello1 makes the stateless server send the HelloRetryRequest again.
            // Dropping the first ClientHello2 keeps the client waiting for a ServerHello when the duplicate arrives.
            var h = new Harness();
            int serverCount = 0, clientCount = 0;
            h.Pair.ServerToClient = d => Interlocked.Increment(ref serverCount) == 1 ? new[] { d, d } : new[] { d };
            h.Pair.ClientToServer = d => Interlocked.Increment(ref clientCount) == 2 ? Array.Empty<byte[]>() : new[] { d };

            h.Handshake();
        }

        [TestMethod]
        public void ReorderedServerFlight_IsProcessedInMessageOrder()
        {
            // long timeouts: reordering alone must complete the handshake, without retransmission
            var h = new Harness(
                configureServer: s => { s.ShouldSendHelloRetry = false; s.TicketKeys = null; s.InitialRetransmitTimeout = TimeSpan.FromSeconds(30); },
                configureClient: c => c.InitialRetransmitTimeout = TimeSpan.FromSeconds(30));
            var held = new List<byte[]>();
            int count = 0;
            h.Pair.ServerToClient = d =>
            {
                int n = Interlocked.Increment(ref count);
                if (n == 1) return new[] { d };                // ServerHello
                if (n >= 2 && n <= 4) { held.Add(d); return Array.Empty<byte[]>(); }
                if (n == 5) { held.Add(d); held.Reverse(); return held.ToArray(); } // deliver Finished, CertificateVerify, Certificate, EncryptedExtensions
                return new[] { d };
            };

            h.Handshake();
            Assert.HasCount(6, h.Pair.ServerSent, "Reordered flight should complete without retransmission (5 flight records + ACK)");
        }

        [TestMethod]
        public void ReplayedApplicationRecord_IsDeliveredOnce()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();

            h.Pair.ClientToServer = d => new[] { d, d };
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("once"));

            CollectionAssert.AreEqual(new[] { "once" }, h.ServerReceived);
        }

        [TestMethod]
        public void SeveralRecordsInOneDatagram_AreAllProcessed()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();

            var buffered = new List<byte[]>();
            h.Pair.ClientToServer = d =>
            {
                buffered.Add(d);
                if (buffered.Count < 3) return Array.Empty<byte[]>();
                return new[] { buffered.SelectMany(b => b).ToArray() };
            };

            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("a"));
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("b"));
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("c"));

            CollectionAssert.AreEqual(new[] { "a", "b", "c" }, h.ServerReceived);
        }

        [TestMethod]
        public void ClientCertificateRequired_WithHelloRetry_SucceedsWithCertificate()
        {
            var (kp, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            var h = new Harness(
                configureServer: s => s.RequireClientCertificate = true,
                configureClient: c => { c.ClientCertificate = cert; c.ClientCertificateKeyPair = kp; });
            h.Handshake();

            Assert.IsNotNull(h.ServerConnection.ClientCertificate);
            Assert.AreEqual(cert, h.ServerConnection.ClientCertificate);
        }

        [TestMethod]
        public void ClientCertificateRequired_WithoutCertificate_FailsWithCertificateRequired()
        {
            var h = new Harness(configureServer: s => { s.RequireClientCertificate = true; s.ShouldSendHelloRetry = false; });
            h.Client.BeginHandshake();

            Assert.IsTrue(h.Client.IsClosed, "Client should receive the server's fatal alert");
            var error = h.ClientErrors.OfType<DtlsException>().Single();
            Assert.AreEqual(AlertDescription.CertificateRequired, error.Alert);
            Assert.IsNull(h.ServerConnection, "Failed connection should be removed from the server");
        }

        [TestMethod]
        public void UseSrtp_IsNegotiatedInEncryptedExtensions()
        {
            var h = new Harness(configureClient: c => c.SrtpProtectionProfiles = new ushort[] { 0x0001 });
            h.Handshake();
            Assert.AreEqual((ushort)0x0001, h.ServerConnection.SelectedSrtpProtectionProfile);
        }

        [TestMethod]
        public void TamperedRecord_IsDiscardedWithoutClosingTheConnection()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();

            h.Pair.ClientToServer = d => { var copy = (byte[])d.Clone(); copy[^1] ^= 0xFF; return new[] { copy }; };
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("tampered"));
            h.Pair.ClientToServer = d => new[] { d };
            h.Client.SendApplicationData(Encoding.UTF8.GetBytes("ok"));

            CollectionAssert.AreEqual(new[] { "ok" }, h.ServerReceived);
            Assert.IsFalse(h.ServerConnection.IsClosed);
        }

        [TestMethod]
        public void Close_SendsCloseNotify_AndPeerCloses()
        {
            var h = new Harness(configureServer: s => s.ShouldSendHelloRetry = false);
            h.Handshake();
            var connection = h.ServerConnection;

            h.Client.Close();

            Assert.IsTrue(h.Client.IsClosed);
            Assert.IsTrue(connection.IsClosed);
        }

        [TestMethod]
        public void ClientHello_WithUnknownExtensionsAndMultipleKeyShares_IsAccepted()
        {
            var (_, pub) = Dtls13CryptoUtils.CreateX25519KeyPair();
            var clientHello = new ClientHelloDatagram(pub.GetEncoded()) { ClientRandom = Dtls13CryptoUtils.GenerateRandom(32) };
            clientHello.Extensions.Add(new UnknownExtension(0xFE0D, new byte[] { 1, 2, 3 }));

            byte[] bytes = clientHello.ToBytes();
            var parsed = new ClientHelloDatagram();
            parsed.FromBytes(bytes);

            Assert.IsTrue(parsed.Extensions.OfType<UnknownExtension>().Any(e => e.ExtensionType == 0xFE0D));
            CollectionAssert.AreEqual(bytes, parsed.ToBytes());
        }
    }

    [TestClass]
    public sealed class TestDtls13RecordLayer
    {
        [TestMethod]
        public void RecordWindow_DetectsReplays()
        {
            var window = new RecordWindow();
            Assert.IsFalse(window.IsDuplicate(5));
            window.Mark(5);
            Assert.IsTrue(window.IsDuplicate(5));
            Assert.IsFalse(window.IsDuplicate(4));
            window.Mark(4);
            window.Mark(100);
            Assert.IsTrue(window.IsDuplicate(4), "older than the window is treated as a replay");
            Assert.IsFalse(window.IsDuplicate(99));
            Assert.IsTrue(window.IsDuplicate(100));
        }

        [DataRow(0UL, 0UL, 16, 0UL)]
        [DataRow(0x1FFFFUL, 0x0001UL, 16, 0x20001UL)]   // wrapped forward
        [DataRow(0x20005UL, 0xFFFEUL, 16, 0x1FFFEUL)]   // late record from before the wrap
        [DataRow(0x2FFUL, 0x02UL, 8, 0x302UL)]
        [TestMethod]
        public void RecordWindow_ReconstructsClosestSequenceNumber(ulong highest, ulong truncated, int bits, ulong expected)
        {
            var window = new RecordWindow();
            if (highest > 0 || truncated > 0)
                window.Mark(highest);
            Assert.AreEqual(expected, window.Reconstruct(truncated, bits));
        }

        [TestMethod]
        public void ChaCha20Block_MatchesRfc8439TestVector()
        {
            // RFC 8439 §2.3.2
            byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = Convert.FromHexString("000000090000004a00000000");
            byte[] block = ChaCha20Block.Compute(key, 1, nonce);
            Assert.AreEqual(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
                Convert.ToHexString(block).ToLowerInvariant());
        }

        [TestMethod]
        public void Protect_Unprotect_RoundTrip_AllSuites_HighSequenceNumbers()
        {
            foreach (ushort id in Dtls13CipherSuite.Supported)
            {
                var suite = Dtls13CipherSuite.Get(id);
                var keys = Dtls13CryptoUtils.CalculateApplicationKeys(new byte[32], new byte[suite.HashLength], new byte[suite.HashLength], suite);

                foreach (ulong seq in new ulong[] { 0, 255, 256, 65535, 65536, 1UL << 40 })
                {
                    var receiver = Dtls13CryptoUtils.CalculateApplicationKeys(new byte[32], new byte[suite.HashLength], new byte[suite.HashLength], suite);
                    if (seq > 0) receiver.ClientRecords.Mark(seq - 1);

                    byte[] inner = Encoding.UTF8.GetBytes("hello\x17");
                    byte[] record = Dtls13RecordProtection.Protect(keys, true, 3, seq, inner);
                    var result = Dtls13RecordProtection.Unprotect(receiver, true, record);

                    Assert.AreEqual(seq, result.SequenceNumber, $"suite 0x{id:X4} seq {seq}");
                    CollectionAssert.AreEqual(inner, result.InnerPlaintext);
                }
            }
        }

        [TestMethod]
        public void Reassembler_OverlappingFragments_DoNotCompleteEarly()
        {
            var reassembler = new HandshakeReassembler();
            byte[] Fragment(int offset, int length)
            {
                byte[] f = new byte[12 + length + 1];
                f[0] = 0x0b; f[3] = 100; // total length 100
                f[8] = (byte)offset; f[11] = (byte)length;
                for (int i = 0; i < length; i++) f[12 + i] = (byte)(offset + i + 1);
                f[^1] = 0x16;
                return f;
            }

            Assert.IsFalse(reassembler.TryAddFragment(Fragment(0, 60), out _));
            Assert.IsFalse(reassembler.TryAddFragment(Fragment(0, 60), out _), "a retransmitted fragment must not count twice");
            Assert.IsFalse(reassembler.TryAddFragment(Fragment(30, 60), out _));
            Assert.IsTrue(reassembler.TryAddFragment(Fragment(90, 10), out byte[] complete));
            for (int i = 0; i < 100; i++)
                Assert.AreEqual((byte)(i + 1), complete[12 + i]);
        }

        [TestMethod]
        public void Reassembler_FragmentBeyondMessageLength_IsRejected()
        {
            var reassembler = new HandshakeReassembler();
            byte[] f = new byte[12 + 10 + 1];
            f[0] = 0x0b; f[3] = 20; f[8] = 15; f[11] = 10; f[^1] = 0x16;
            Assert.ThrowsExactly<DtlsException>(() => reassembler.TryAddFragment(f, out _));
        }
    }
}
