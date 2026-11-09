using SharpDTLS;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>DTLS 1.3 0-RTT early data (RFC 8446 §2.3, §4.2.10, §8; RFC 9147 §5.6, §6.1).</summary>
    [TestClass]
    public sealed class TestDtls13EarlyData
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public List<string> EarlyData = new();
            public List<string> ServerReceived = new();
            public Tls13ServerConnection ServerConnection => Server.GetConnection(ScriptedTransportPair.ClientEndpoint);
        }

        private static Run Connect(SessionTicketKeys keys, Dtls13SessionTicket ticket, byte[] earlyData, uint maxEarlyData = 1024, bool helloRetry = false)
        {
            var r = new Run();
            r.Server = new Dtls13Server(r.Pair.Server)
            {
                TicketKeys = keys, MaxEarlyDataSize = maxEarlyData, ShouldSendHelloRetry = helloRetry,
                InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50),
            };
            r.Server.EarlyDataReceived += (_, e) => { lock (r.EarlyData) r.EarlyData.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Client = new Dtls13Client(r.Pair.Client) { ResumptionTicket = ticket, EarlyData = earlyData, InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => done.TrySetException(ex);
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerConnection?.IsHandshakeComplete == true, Timeout));
            return r;
        }

        private static Dtls13SessionTicket Ticket(SessionTicketKeys keys, uint maxEarlyData = 1024)
        {
            var first = Connect(keys, null, null, maxEarlyData);
            Assert.IsTrue(SpinWait.SpinUntil(() => first.Client.SessionTicket != null, Timeout));
            return first.Client.SessionTicket;
        }

        [TestMethod]
        public void EarlyData_IsAcceptedInEpoch1()
        {
            var keys = new SessionTicketKeys();
            var ticket = Ticket(keys);
            Assert.AreEqual(1024u, ticket.MaxEarlyDataSize, "the ticket carries max_early_data_size");

            var r = Connect(keys, ticket, Encoding.UTF8.GetBytes("GET /status"));
            Assert.IsTrue(r.Client.IsResumed);
            Assert.IsTrue(r.Client.EarlyDataAccepted);
            Assert.IsTrue(r.ServerConnection.EarlyDataAccepted);
            CollectionAssert.AreEqual(new[] { "GET /status" }, r.EarlyData);
            Assert.IsEmpty(r.ServerReceived, "early data is not reported as regular application data");

            // The second client datagram is the 0-RTT record: unified header, epoch bits 1.
            byte[] early = r.Pair.ClientSent[1];
            Assert.AreEqual(0x20, early[0] & 0xE0);
            Assert.AreEqual(1, early[0] & 0x03);

            r.Client.SendApplicationData(Encoding.UTF8.GetBytes("after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerReceived.Contains("after"), Timeout));
        }

        [TestMethod]
        public void ReplayedClientHello_GetsNoEarlyData()
        {
            var keys = new SessionTicketKeys();
            var r = Connect(keys, Ticket(keys), Encoding.UTF8.GetBytes("transfer 10"));
            Assert.HasCount(1, r.EarlyData);

            // An attacker replays the ClientHello and the 0-RTT record from another address to the same server.
            var attacker = IPEndPoint.Parse("127.0.0.1:50000");
            r.Pair.Server.Deliver(attacker, r.Pair.ClientSent[0]);
            r.Pair.Server.Deliver(attacker, r.Pair.ClientSent[1]);
            Thread.Sleep(200);
            Assert.HasCount(1, r.EarlyData, "the replayed early data must not be delivered");
            var replayed = r.Server.GetConnection(attacker);
            Assert.IsNotNull(replayed);
            Assert.IsTrue(replayed.IsResumed, "the replayed ticket and binder are valid, so only the ClientHello record stops the replay");
            Assert.IsFalse(replayed.EarlyDataAccepted);
        }

        [TestMethod]
        public void ServerWithoutEarlyData_IssuesTicketsWithoutIt()
        {
            var keys = new SessionTicketKeys();
            var ticket = Ticket(keys, maxEarlyData: 0);
            Assert.AreEqual(0u, ticket.MaxEarlyDataSize);

            var r = Connect(keys, ticket, Encoding.UTF8.GetBytes("early"), maxEarlyData: 0);
            Assert.IsTrue(r.Client.IsResumed);
            Assert.IsFalse(r.Client.EarlyDataAccepted);
            Assert.IsEmpty(r.EarlyData);
        }

        [TestMethod]
        public void ServerThatStoppedAcceptingEarlyData_DeclinesIt()
        {
            var keys = new SessionTicketKeys();
            var ticket = Ticket(keys);

            // Offered and sent, but declined: the epoch 1 record is dropped and the handshake still completes.
            var r = Connect(keys, ticket, Encoding.UTF8.GetBytes("early"), maxEarlyData: 0);
            Assert.IsTrue(r.Client.IsResumed);
            Assert.IsFalse(r.Client.EarlyDataAccepted);
            Assert.IsEmpty(r.EarlyData);
            Assert.AreEqual(1, r.Pair.ClientSent[1][0] & 0x03, "the client did send early data");
        }

        [TestMethod]
        public void HelloRetryRequest_DiscardsEarlyData()
        {
            var keys = new SessionTicketKeys();
            var r = Connect(keys, Ticket(keys), Encoding.UTF8.GetBytes("early"), helloRetry: true);
            Assert.IsTrue(r.Client.IsResumed, "resumption still works after the HelloRetryRequest");
            Assert.IsFalse(r.Client.EarlyDataAccepted);
            Assert.IsEmpty(r.EarlyData);
        }

        [TestMethod]
        public void StaleTicketAge_GetsNoEarlyData()
        {
            var keys = new SessionTicketKeys();
            var ticket = Ticket(keys);
            // A client clock (age) 60 s off the server's view is outside the 10 s freshness window.
            var skewed = new Dtls13SessionTicket(ticket.Ticket, ticket.LifetimeSeconds, unchecked(ticket.AgeAdd + 60000), ticket.CipherSuite,
                ticket.Psk, ticket.ServerCertificate, ticket.MaxEarlyDataSize);

            var r = Connect(keys, skewed, Encoding.UTF8.GetBytes("early"));
            Assert.IsTrue(r.Client.IsResumed);
            Assert.IsFalse(r.Client.EarlyDataAccepted);
            Assert.IsEmpty(r.EarlyData);
        }

        [TestMethod]
        public void EarlyDataLargerThanTheTicketAllows_IsNotOffered()
        {
            var keys = new SessionTicketKeys();
            var r = Connect(keys, Ticket(keys, maxEarlyData: 4), Encoding.UTF8.GetBytes("too long"), maxEarlyData: 4);
            Assert.IsTrue(r.Client.IsResumed);
            Assert.IsFalse(r.Client.EarlyDataAccepted);
            Assert.AreNotEqual(1, r.Pair.ClientSent[1][0] & 0x03, "no 0-RTT record was sent");
        }
    }
}
