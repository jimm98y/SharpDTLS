using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.3 connection IDs (RFC 9147 §9) and the peer address policy of both engines.</summary>
    [TestClass]
    public sealed class TestDtls13ConnectionId
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly EndPoint Rebound = IPEndPoint.Parse("198.51.100.7:40000");

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public List<string> ServerReceived = new();
            public List<string> ClientReceived = new();
            public List<(EndPoint Old, EndPoint New)> Changes = new();
            public Dtls13ServerConnection Connection => Server.Connections.Single();
        }

        private static Run Connect(bool serverCids = true, int clientCidLength = 0, bool autoUpdate = false, bool helloRetry = true)
        {
            var r = new Run();
            r.Server = new Dtls13Server(r.Pair.Server)
            {
                UseConnectionIds = serverCids, AutoUpdatePeerAddress = autoUpdate, ShouldSendHelloRetry = helloRetry,
                InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50),
            };
            r.Server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Server.HandshakeFinished += (_, e) =>
                ((Dtls13ConnectionEventArgs)e).Connection.PeerAddressChanged += (_, c) => { lock (r.Changes) r.Changes.Add(c); };
            r.Client = new Dtls13Client(r.Pair.Client) { UseConnectionId = true, ConnectionIdLength = clientCidLength, InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
            r.Client.ApplicationDataReceived += (_, d) => { lock (r.ClientReceived) r.ClientReceived.Add(Encoding.UTF8.GetString(d)); };

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => done.TrySetException(ex);
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.Server.Connections.Any(c => c.IsHandshakeComplete), Timeout));
            return r;
        }

        private static void ClientSends(Run r, string text)
        {
            r.Client.SendApplicationData(Encoding.UTF8.GetBytes(text));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerReceived.Contains(text), Timeout), $"server did not get {text}");
        }

        private static void ServerReplies(Run r, string text)
        {
            r.Connection.SendApplicationData(Encoding.UTF8.GetBytes(text));
            Assert.IsTrue(SpinWait.SpinUntil(() => r.ClientReceived.Contains(text), Timeout), $"client did not get {text}");
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void ClientToServerCid_InUnifiedHeaders(bool helloRetry)
        {
            var r = Connect(helloRetry: helloRetry);
            byte[] cid = r.Connection.ConnectionId;
            Assert.HasCount(8, cid);
            CollectionAssert.AreEqual(cid, r.Client.PeerConnectionId);
            Assert.IsNull(r.Client.ConnectionId);

            int before = r.Pair.ClientSent.Count;
            ClientSends(r, "ping");
            byte[] record = r.Pair.ClientSent[before];
            Assert.AreEqual(0x30, record[0] & 0xF0, "unified header with the C bit");
            CollectionAssert.AreEqual(cid, record.AsSpan(1, 8).ToArray());
            ServerReplies(r, "pong");
            Assert.AreEqual(0, r.Pair.ServerSent.Last()[0] & 0x10, "no CID towards a client that asked for none");
        }

        [TestMethod]
        public void BothDirections_IncludingTheHandshakeEpoch()
        {
            var r = Connect(clientCidLength: 5);
            CollectionAssert.AreEqual(r.Client.ConnectionId, r.Connection.PeerConnectionId);
            // The server's encrypted flight (EncryptedExtensions onwards) already carries the client's CID.
            Assert.IsTrue(r.Pair.ServerSent.Where(d => (d[0] & 0xE0) == 0x20).All(d => (d[0] & 0x10) != 0));
            ClientSends(r, "a");
            ServerReplies(r, "b");
        }

        [TestMethod]
        public void NewAddress_IsPendingUntilConfirmed()
        {
            var r = Connect();
            ClientSends(r, "before");

            r.Pair.ClientAddress = Rebound;
            ClientSends(r, "after"); // data still arrives
            Assert.AreEqual(ScriptedTransportPair.ClientEndpoint, r.Connection.RemoteEndPoint, "RFC 9147 §11: no move without a check");
            Assert.AreEqual(Rebound, r.Connection.PendingPeerAddress);
            CollectionAssert.AreEqual(new[] { (ScriptedTransportPair.ClientEndpoint, Rebound) }, r.Changes);

            r.Connection.ConfirmPeerAddress(Rebound);
            ServerReplies(r, "confirmed");
            Assert.AreEqual(Rebound, r.Pair.ServerSentTo.Last());
            Assert.IsNull(r.Connection.PendingPeerAddress);
            Assert.AreSame(r.Connection, r.Server.GetConnection(Rebound));
        }

        [TestMethod]
        public void AutoUpdate_FollowsAtOnce()
        {
            var r = Connect(autoUpdate: true);
            r.Pair.ClientAddress = Rebound;
            ClientSends(r, "moved");
            ServerReplies(r, "followed");
            Assert.AreEqual(Rebound, r.Pair.ServerSentTo.Last());
        }

        [TestMethod]
        public void ReplayFromAnotherAddress_IsIgnored()
        {
            var r = Connect(autoUpdate: true);
            int before = r.Pair.ClientSent.Count;
            ClientSends(r, "one");
            byte[] old = r.Pair.ClientSent[before];
            ClientSends(r, "two");
            r.Pair.Server.Deliver(Rebound, old);
            Thread.Sleep(100);
            Assert.AreEqual(ScriptedTransportPair.ClientEndpoint, r.Connection.RemoteEndPoint);
            Assert.IsEmpty(r.Changes);
        }

        [TestMethod]
        public void ServerWithoutCids_IgnoresTheOffer()
        {
            var r = Connect(serverCids: false);
            Assert.IsNull(r.Client.PeerConnectionId);
            ClientSends(r, "plain");
            Assert.AreEqual(0, r.Pair.ClientSent.Last()[0] & 0x10);
        }

        [TestMethod]
        public void Dtls12_ManualPolicy_KeepsTheOldAddressUntilConfirmed()
        {
            var pair = new ScriptedTransportPair();
            var received = new List<string>();
            var server = new Dtls12Server(pair.Server) { UseConnectionIds = true, AutoUpdatePeerAddress = false };
            server.ApplicationDataReceived += (_, e) => { lock (received) received.Add(Encoding.UTF8.GetString(e.Data)); };
            var client = new Dtls12Client(pair.Client) { UseConnectionId = true };
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout));

            pair.ClientAddress = Rebound;
            client.SendApplicationData(Encoding.UTF8.GetBytes("moved"));
            Assert.IsTrue(SpinWait.SpinUntil(() => received.Contains("moved"), Timeout));
            var connection = server.Connections.Single();
            Assert.AreEqual(ScriptedTransportPair.ClientEndpoint, connection.RemoteEndPoint);
            Assert.AreEqual(Rebound, connection.PendingPeerAddress);

            connection.ConfirmPeerAddress(Rebound);
            Assert.AreEqual(Rebound, connection.RemoteEndPoint);
            Assert.AreSame(connection, server.GetConnection(Rebound));
        }
    }
}
