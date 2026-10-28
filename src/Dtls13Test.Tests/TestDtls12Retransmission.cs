using SharpDTLS;
using SharpDTLS.Protocol12.DTLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Handshake retransmission for DTLS 1.0 and 1.2 (RFC 6347 §4.2.4) over a lossy in-memory link.
    /// Datagram order without loss — server: 1 HelloVerifyRequest, 2 ServerHello, 3 Certificate,
    /// 4 ServerKeyExchange, 5 ServerHelloDone, 6 ChangeCipherSpec, 7 Finished;
    /// client: 1 ClientHello, 2 ClientHello with cookie, 3 ClientKeyExchange, 4 ChangeCipherSpec, 5 Finished.
    /// </summary>
    [TestClass]
    public sealed class TestDtls12Retransmission
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private sealed class Endpoints
        {
            public ScriptedTransportPair Pair = new();
            public Action Begin;
            public Action<string> ClientSend;
            public TaskCompletionSource<bool> ClientDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public TaskCompletionSource<bool> ServerDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public List<string> ServerReceived = new();
        }

        private static Endpoints Create(int version)
        {
            var e = new Endpoints();
            var timeout = TimeSpan.FromMilliseconds(50);

            if (version == 12)
            {
                var server = new Dtls12Server(e.Pair.Server) { InitialRetransmitTimeout = timeout };
                var client = new Dtls12Client(e.Pair.Client) { InitialRetransmitTimeout = timeout };
                server.HandshakeFinished += (_, _) => e.ServerDone.TrySetResult(true);
                server.ApplicationDataReceived += (_, a) => { lock (e.ServerReceived) e.ServerReceived.Add(Encoding.UTF8.GetString(a.Data)); };
                client.HandshakeFinished += (_, _) => e.ClientDone.TrySetResult(true);
                client.Failed += (_, ex) => e.ClientDone.TrySetException(ex);
                e.Begin = client.BeginHandshake;
                e.ClientSend = text => client.SendApplicationData(Encoding.UTF8.GetBytes(text));
            }
            else
            {
                var server = new Dtls12Server(e.Pair.Server) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, InitialRetransmitTimeout = timeout };
                var client = new Dtls12Client(e.Pair.Client) { MinimumVersion = DtlsVersion.Dtls10, MaximumVersion = DtlsVersion.Dtls10, InitialRetransmitTimeout = timeout };
                server.HandshakeFinished += (_, _) => e.ServerDone.TrySetResult(true);
                server.ApplicationDataReceived += (_, a) => { lock (e.ServerReceived) e.ServerReceived.Add(Encoding.UTF8.GetString(a.Data)); };
                client.HandshakeFinished += (_, _) => e.ClientDone.TrySetResult(true);
                client.Failed += (_, ex) => e.ClientDone.TrySetException(ex);
                e.Begin = client.BeginHandshake;
                e.ClientSend = text => client.SendApplicationData(Encoding.UTF8.GetBytes(text));
            }

            return e;
        }

        private static Func<byte[], IEnumerable<byte[]>> DropNth(int n)
        {
            int count = 0;
            return d => Interlocked.Increment(ref count) == n ? Array.Empty<byte[]>() : new[] { d };
        }

        private static void Complete(Endpoints e)
        {
            e.Begin();
            Assert.IsTrue(Task.WhenAll(e.ClientDone.Task, e.ServerDone.Task).Wait(Timeout), "Handshake did not complete in time");

            e.ClientSend("after-loss");
            Assert.IsTrue(SpinWait.SpinUntil(() => { lock (e.ServerReceived) return e.ServerReceived.Contains("after-loss"); }, Timeout));
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void LostClientHello_IsRetransmitted(int version)
        {
            var e = Create(version);
            e.Pair.ClientToServer = DropNth(1);
            Complete(e);
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void LostHelloVerifyRequest_ClientRetransmits(int version)
        {
            var e = Create(version);
            e.Pair.ServerToClient = DropNth(1);
            Complete(e);
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void LostServerCertificate_ServerFlightIsRetransmitted(int version)
        {
            var e = Create(version);
            e.Pair.ServerToClient = DropNth(3);
            Complete(e);
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void LostClientFinished_ClientFlightIsRetransmitted(int version)
        {
            var e = Create(version);
            e.Pair.ClientToServer = DropNth(5);
            Complete(e);
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void LostServerFinished_IsResentWhenClientRetransmits(int version)
        {
            var e = Create(version);
            e.Pair.ServerToClient = DropNth(7);
            Complete(e);
        }

        [DataRow(10)]
        [DataRow(12)]
        [TestMethod]
        public void DuplicatedDatagrams_AreHarmless(int version)
        {
            var e = Create(version);
            e.Pair.ClientToServer = d => new[] { d, d };
            e.Pair.ServerToClient = d => new[] { d, d };
            Complete(e);
            lock (e.ServerReceived) Assert.HasCount(1, e.ServerReceived, "application data must not be delivered twice");
        }
    }
}
