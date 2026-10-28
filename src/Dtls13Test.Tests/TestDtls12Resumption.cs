using SharpDTLS;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.0/1.2 session resumption by session ID and ticket (RFC 5246 §7.3, RFC 5077, RFC 7627 §5.3).</summary>
    [TestClass]
    public sealed class TestDtls12Resumption
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls12ServerBase Server;
            public Tls12ClientConnection Client;
            public Tls12ServerConnection ServerConnection => Server.GetConnection(ScriptedTransportPair.ClientEndpoint);
            public List<string> ServerReceived = new();
            public List<string> ClientReceived = new();
        }

        private static Run Connect(ushort version, IDtls12SessionCache cache, Dtls12SessionState resume, ushort? suite = null,
            Action<ScriptedTransportPair> configureLink = null, SessionTicketKeys ticketKeys = null)
        {
            var r = new Run();
            configureLink?.Invoke(r.Pair);
            var timeout = TimeSpan.FromMilliseconds(20);
            var suites = suite.HasValue ? new List<ushort> { suite.Value } : null;
            if (version == DtlsVersion.Dtls12)
            {
                var server = new Dtls12Server(r.Pair.Server) { SessionCache = cache, TicketKeys = ticketKeys, InitialRetransmitTimeout = timeout, CipherSuites = suites };
                server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
                r.Server = server;
                r.Client = new Dtls12Client(r.Pair.Client) { ResumptionSession = resume, InitialRetransmitTimeout = timeout, CipherSuites = suites, UseSessionTickets = ticketKeys != null };
            }
            else
            {
                var server = new Dtls12Server(r.Pair.Server) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, SessionCache = cache, TicketKeys = ticketKeys, InitialRetransmitTimeout = timeout, CipherSuites = suites };
                server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
                r.Server = server;
                r.Client = new Dtls12Client(r.Pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, ResumptionSession = resume, InitialRetransmitTimeout = timeout, CipherSuites = suites, UseSessionTickets = ticketKeys != null };
            }
            r.Client.ApplicationDataReceived += (_, data) => { lock (r.ClientReceived) r.ClientReceived.Add(Encoding.UTF8.GetString(data)); };

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => done.TrySetException(ex);
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "handshake did not complete");
            Assert.IsTrue(SpinWait(() => r.ServerConnection?.IsHandshakeComplete == true), "server did not complete");
            return r;
        }

        private static bool SpinWait(Func<bool> condition)
            => System.Threading.SpinWait.SpinUntil(condition, Timeout);

        private static void ExchangeData(Run r)
        {
            r.Client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
            r.Server.SendApplicationData(ScriptedTransportPair.ClientEndpoint, Encoding.UTF8.GetBytes("pong"));
            Assert.IsTrue(SpinWait(() => r.ServerReceived.Contains("ping") && r.ClientReceived.Contains("pong")));
        }

        [DataRow(DtlsVersion.Dtls12, (ushort)0xC02F)] // ECDHE_RSA AES-128-GCM
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC027)] // ECDHE_RSA AES-128-CBC-SHA256 with encrypt-then-MAC
        [DataRow(DtlsVersion.Dtls10, (ushort)0xC013)] // ECDHE_RSA AES-128-CBC-SHA
        [TestMethod]
        public void SessionId_IsResumedWithAnAbbreviatedHandshake(ushort version, ushort suite)
        {
            var cache = new Dtls12SessionCache();
            var first = Connect(version, cache, null, suite);

            Assert.IsFalse(first.Client.IsResumed);
            var session = first.Client.SessionState;
            Assert.IsNotNull(session, "a full handshake with EMS yields a resumable session");
            Assert.HasCount(32, session.SessionId);
            Assert.AreEqual(1, cache.Count);
            int fullHandshakeDatagrams = first.Pair.ServerSent.Count;

            var second = Connect(version, cache, session, suite);
            Assert.IsTrue(second.Client.IsResumed);
            Assert.IsTrue(second.ServerConnection.IsResumed);
            Assert.AreSame(session, second.Client.SessionState);
            Assert.AreEqual(suite, second.Client.CipherSuite.Id);
            Assert.AreEqual(version, second.Client.NegotiatedVersion);
            Assert.AreEqual(session.EncryptThenMac, second.Client.EncryptThenMacNegotiated);
            Assert.IsLessThan(fullHandshakeDatagrams, second.Pair.ServerSent.Count, "no Certificate or key exchange");

            // Same master secret, new randoms: new keys.
            CollectionAssert.AreNotEqual(first.Client.ExportKeyingMaterial("EXPERIMENTAL test", null, 32),
                                         second.Client.ExportKeyingMaterial("EXPERIMENTAL test", null, 32));
            CollectionAssert.AreEqual(second.Client.ExportKeyingMaterial("EXPERIMENTAL test", null, 32),
                                      second.ServerConnection.ExportKeyingMaterial("EXPERIMENTAL test", null, 32));
            ExchangeData(second);
        }

        [TestMethod]
        public void UnknownOrExpiredSession_FallsBackToAFullHandshakeWithANewSession()
        {
            var cache = new Dtls12SessionCache();
            var session = Connect(DtlsVersion.Dtls12, cache, null).Client.SessionState;

            var otherServer = Connect(DtlsVersion.Dtls12, new Dtls12SessionCache(), session);
            Assert.IsFalse(otherServer.Client.IsResumed);
            Assert.IsNotNull(otherServer.Client.SessionState);
            CollectionAssert.AreNotEqual(session.SessionId, otherServer.Client.SessionState.SessionId);

            cache.Lifetime = TimeSpan.Zero;
            Assert.IsFalse(Connect(DtlsVersion.Dtls12, cache, session).Client.IsResumed);
        }

        [TestMethod]
        public void DisabledCache_GivesNoSessionId()
        {
            var r = Connect(DtlsVersion.Dtls12, cache: null, resume: null);
            Assert.IsNull(r.Client.SessionState);
        }

        [TestMethod]
        public void SuiteNoLongerOffered_IsNotResumed()
        {
            var cache = new Dtls12SessionCache();
            var session = Connect(DtlsVersion.Dtls12, cache, null, 0xC02F).Client.SessionState;
            var r = Connect(DtlsVersion.Dtls12, cache, session, 0xC030);
            Assert.IsFalse(r.Client.IsResumed);
            Assert.AreEqual((ushort)0xC030, r.Client.CipherSuite.Id);
        }

        [TestMethod]
        public void VersionMismatch_IsNotResumed()
        {
            var cache = new Dtls12SessionCache();
            var session = Connect(DtlsVersion.Dtls10, cache, null).Client.SessionState;
            Assert.IsFalse(Connect(DtlsVersion.Dtls12, cache, session).Client.IsResumed);
        }

        // Abbreviated handshake datagrams — client: 1 ClientHello, 2 ClientHello with cookie, 3 ChangeCipherSpec,
        // 4 Finished; server: 1 HelloVerifyRequest, 2 ServerHello, 3 ChangeCipherSpec, 4 Finished.
        [DataRow(true, 4)]  // server Finished lost: the server's timer resends its flight
        [DataRow(true, 2)]  // ServerHello lost
        [DataRow(false, 4)] // client Finished lost: the server retransmits, the client resends its final flight
        [DataRow(false, 3)] // client ChangeCipherSpec lost
        [TestMethod]
        public void AbbreviatedHandshake_RecoversFromLoss(bool serverToClient, int dropIndex)
        {
            var cache = new Dtls12SessionCache();
            var session = Connect(DtlsVersion.Dtls12, cache, null).Client.SessionState;

            var r = Connect(DtlsVersion.Dtls12, cache, session, configureLink: pair =>
            {
                int count = 0;
                Func<byte[], IEnumerable<byte[]>> drop = d => ++count == dropIndex ? Array.Empty<byte[]>() : new[] { d };
                if (serverToClient)
                    pair.ServerToClient = drop;
                else
                    pair.ClientToServer = drop;
            });
            Assert.IsTrue(r.Client.IsResumed);
            ExchangeData(r);
        }

        // ── RFC 5077 session tickets ─────────────────────────────────────────────────────────

        [DataRow(DtlsVersion.Dtls12, (ushort)0xC02F)]
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC027)]
        [DataRow(DtlsVersion.Dtls10, (ushort)0xC013)]
        [TestMethod]
        public void Ticket_IsResumedStatelessly(ushort version, ushort suite)
        {
            var cache = new Dtls12SessionCache();
            var keys = new SessionTicketKeys();
            var first = Connect(version, cache, null, suite, ticketKeys: keys);
            var session = first.Client.SessionState;
            Assert.IsNotNull(session?.Ticket, "the server issues a ticket during the full handshake");
            Assert.IsEmpty(session.SessionId);
            Assert.AreEqual(0, cache.Count, "ticket sessions need no server state");
            Assert.AreEqual((uint)keys.Lifetime.TotalSeconds, session.TicketLifetimeHint);

            var second = Connect(version, new Dtls12SessionCache(), session, suite, ticketKeys: keys);
            Assert.IsTrue(second.Client.IsResumed);
            Assert.IsTrue(second.ServerConnection.IsResumed);
            Assert.AreSame(session, second.Client.SessionState, "tickets under the current key are not renewed");
            ExchangeData(second);
        }

        [TestMethod]
        public void Ticket_FromAnotherServerKey_FallsBackToAFullHandshakeWithANewTicket()
        {
            var session = Connect(DtlsVersion.Dtls12, null, null, ticketKeys: new SessionTicketKeys()).Client.SessionState;
            var r = Connect(DtlsVersion.Dtls12, null, session, ticketKeys: new SessionTicketKeys());
            Assert.IsFalse(r.Client.IsResumed);
            Assert.IsNotNull(r.Client.SessionState.Ticket);
            CollectionAssert.AreNotEqual(session.Ticket, r.Client.SessionState.Ticket);
        }

        [TestMethod]
        public void Ticket_AfterKeyRotation_IsResumedAndRenewedKeepingItsAge()
        {
            var keys = new SessionTicketKeys();
            var session = Connect(DtlsVersion.Dtls12, null, null, ticketKeys: keys).Client.SessionState;
            keys.Rotate();

            var r = Connect(DtlsVersion.Dtls12, null, session, ticketKeys: keys);
            Assert.IsTrue(r.Client.IsResumed);
            var renewed = r.Client.SessionState;
            CollectionAssert.AreNotEqual(session.Ticket, renewed.Ticket);

            keys.Rotate(); // the original key is gone, the renewed ticket still works
            Assert.IsTrue(Connect(DtlsVersion.Dtls12, null, renewed, ticketKeys: keys).Client.IsResumed);
            Assert.IsFalse(Connect(DtlsVersion.Dtls12, null, session, ticketKeys: keys).Client.IsResumed);
        }

        [TestMethod]
        public void Ticket_ExpiredOrTampered_IsNotResumed()
        {
            var keys = new SessionTicketKeys();
            var session = Connect(DtlsVersion.Dtls12, null, null, ticketKeys: keys).Client.SessionState;

            byte[] tampered = (byte[])session.Ticket.Clone();
            tampered[^1] ^= 1;
            var forged = new Dtls12SessionState(session.SessionId, session.Version, session.CipherSuite, session.MasterSecret,
                session.EncryptThenMac, session.PeerCertificate, session.CreatedUtc, tampered, 0);
            Assert.IsFalse(Connect(DtlsVersion.Dtls12, null, forged, ticketKeys: keys).Client.IsResumed);

            keys.Lifetime = TimeSpan.Zero;
            Assert.IsFalse(Connect(DtlsVersion.Dtls12, null, session, ticketKeys: keys).Client.IsResumed);
        }

        [TestMethod]
        public void ClientWithoutTickets_GetsASessionId()
        {
            var cache = new Dtls12SessionCache();
            var r = Connect(DtlsVersion.Dtls12, cache, null);
            Assert.IsNull(r.Client.SessionState.Ticket);
            Assert.HasCount(32, r.Client.SessionState.SessionId);
            Assert.AreEqual(1, cache.Count);
        }

        // Full handshake with a ticket — server: 1 HelloVerifyRequest, 2 ServerHello, 3 Certificate, 4 ServerKeyExchange,
        // 5 ServerHelloDone, 6 NewSessionTicket, 7 ChangeCipherSpec, 8 Finished. Abbreviated with a renewed ticket:
        // 1 HelloVerifyRequest, 2 ServerHello, 3 NewSessionTicket, 4 ChangeCipherSpec, 5 Finished.
        [DataRow(false, 6)]
        [DataRow(true, 3)]
        [TestMethod]
        public void LostNewSessionTicket_IsRetransmitted(bool resumption, int dropIndex)
        {
            var keys = new SessionTicketKeys();
            Dtls12SessionState session = null;
            if (resumption)
            {
                session = Connect(DtlsVersion.Dtls12, null, null, ticketKeys: keys).Client.SessionState;
                keys.Rotate(); // forces a renewed ticket in the abbreviated handshake
            }

            var r = Connect(DtlsVersion.Dtls12, null, session, ticketKeys: keys, configureLink: pair =>
            {
                int count = 0;
                pair.ServerToClient = d => ++count == dropIndex ? Array.Empty<byte[]>() : new[] { d };
            });
            Assert.AreEqual(resumption, r.Client.IsResumed);
            Assert.IsNotNull(r.Client.SessionState.Ticket);
            ExchangeData(r);
        }
    }
}
