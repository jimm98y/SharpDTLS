using SharpDTLS;
using SharpDTLS.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.2 connection IDs (RFC 9146).</summary>
    [TestClass]
    public sealed class TestDtls12ConnectionId
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly EndPoint Rebound = IPEndPoint.Parse("198.51.100.7:40000");

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls12Server Server;
            public Dtls12Client Client;
            public List<string> ServerReceived = new();
            public List<string> ClientReceived = new();
            public List<(EndPoint Old, EndPoint New)> AddressChanges = new();
            public Tls12ServerConnection Connection => Server.Connections.Single();
        }

        private static Run Connect(bool serverCids = true, bool clientCid = true, int clientCidLength = 0, ushort suite = 0xC02F,
            Dtls12SessionState resume = null, SessionTicketKeys keys = null)
        {
            var r = new Run();
            r.Server = new Dtls12Server(r.Pair.Server) { UseConnectionIds = serverCids, CipherSuites = new List<ushort> { suite }, TicketKeys = keys };
            r.Server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Server.HandshakeFinished += (_, _) =>
                r.Connection.PeerAddressChanged += (_, change) => { lock (r.AddressChanges) r.AddressChanges.Add(change); };
            r.Client = new Dtls12Client(r.Pair.Client)
            {
                UseConnectionId = clientCid, ConnectionIdLength = clientCidLength, CipherSuites = new List<ushort> { suite }, ResumptionSession = resume,
            };
            r.Client.ApplicationDataReceived += (_, d) => { lock (r.ClientReceived) r.ClientReceived.Add(Encoding.UTF8.GetString(d)); };

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => done.TrySetException(ex);
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.Server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            return r;
        }

        private static void Exchange(Run r, string text)
        {
            r.Client.SendApplicationData(Encoding.UTF8.GetBytes(text));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerReceived.Contains(text), Timeout), $"server did not get {text}");
            r.Server.SendApplicationData(r.Connection.RemoteEndPoint, Encoding.UTF8.GetBytes("re:" + text));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ClientReceived.Contains("re:" + text), Timeout), $"client did not get re:{text}");
        }

        [DataRow((ushort)0xC02F)] // AES-GCM
        [DataRow((ushort)0xCCA8)] // ChaCha20-Poly1305
        [DataRow((ushort)0xC027)] // CBC with encrypt-then-MAC
        [DataRow((ushort)0x003B)] // NULL with HMAC
        [TestMethod]
        public void ClientToServerCid_IsSentInTls12CidRecords(ushort suite)
        {
            var r = Connect(suite: suite);
            byte[] serverCid = r.Connection.ConnectionId;
            Assert.HasCount(8, serverCid);
            CollectionAssert.AreEqual(serverCid, r.Client.PeerConnectionId);
            Assert.IsNull(r.Client.ConnectionId, "the client asked for no CID of its own");

            int before = r.Pair.ClientSent.Count;
            Exchange(r, "ping");
            byte[] record = r.Pair.ClientSent[before];
            Assert.AreEqual(25, record[0], "tls12_cid content type");
            CollectionAssert.AreEqual(serverCid, record.AsSpan(11, 8).ToArray());
            Assert.AreNotEqual(25, r.Pair.ServerSent.Last()[0], "no CID towards a client that asked for none");
        }

        [TestMethod]
        public void BothDirections()
        {
            var r = Connect(clientCidLength: 4);
            Assert.HasCount(4, r.Client.ConnectionId);
            CollectionAssert.AreEqual(r.Client.ConnectionId, r.Connection.PeerConnectionId);
            Exchange(r, "both");
            Assert.AreEqual(25, r.Pair.ServerSent.Last()[0]);
        }

        [TestMethod]
        public void ClientAddressChange_FollowsTheConnectionId()
        {
            var r = Connect();
            Exchange(r, "before");

            r.Pair.ClientAddress = Rebound; // NAT rebinding
            Exchange(r, "after");
            Assert.AreEqual(Rebound, r.Connection.RemoteEndPoint);
            Assert.AreEqual(Rebound, r.Pair.ServerSentTo.Last(), "replies go to the new address");
            CollectionAssert.AreEqual(new[] { (ScriptedTransportPair.ClientEndpoint, Rebound) }, r.AddressChanges);
            Assert.AreSame(r.Connection, r.Server.GetConnection(Rebound));
        }

        [TestMethod]
        public void ReplayedOldRecordFromAnotherAddress_DoesNotMoveTheConnection()
        {
            var r = Connect();
            int before = r.Pair.ClientSent.Count;
            Exchange(r, "one");
            byte[] old = r.Pair.ClientSent[before];
            Exchange(r, "two");

            // An attacker replays the older record from its own address: it is not newer, so the address stays.
            r.Pair.Server.Deliver(Rebound, old);
            Thread.Sleep(100);
            Assert.AreEqual(ScriptedTransportPair.ClientEndpoint, r.Connection.RemoteEndPoint);
            Assert.IsEmpty(r.AddressChanges);
        }

        [TestMethod]
        public void WithoutCids_ANewAddressIsAStranger()
        {
            var r = Connect(serverCids: false);
            Assert.IsNull(r.Client.PeerConnectionId);
            r.Pair.ClientAddress = Rebound;
            r.Client.SendApplicationData(Encoding.UTF8.GetBytes("lost"));
            Thread.Sleep(100);
            Assert.IsEmpty(r.ServerReceived);
        }

        [TestMethod]
        public void ServerWithoutCids_IgnoresTheOffer()
        {
            var r = Connect(serverCids: false);
            Assert.IsNull(r.Connection.ConnectionId);
            Exchange(r, "plain");
            Assert.AreNotEqual(25, r.Pair.ClientSent.Last()[0]);
        }

        [TestMethod]
        public void Resumption_NegotiatesCidsAfresh()
        {
            var keys = new SessionTicketKeys();
            var first = Connect(keys: keys);
            var r = Connect(resume: first.Client.SessionState, keys: keys);
            Assert.IsTrue(r.Client.IsResumed);
            CollectionAssert.AreNotEqual(first.Connection.ConnectionId, r.Connection.ConnectionId);
            Exchange(r, "resumed");
        }
    }
}
