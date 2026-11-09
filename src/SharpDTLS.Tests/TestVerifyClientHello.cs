using SharpDTLS;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>
    /// <see cref="DtlsServer.VerifyClientHello"/>: stateless address validation on one server instance, the handshake on another.
    /// </summary>
    [TestClass]
    public sealed class TestVerifyClientHello
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;
        private static readonly EndPoint ClientEndpoint = IPEndPoint.Parse("127.0.0.1:49152");

        private sealed class ServerPipe : IServerTransport
        {
            public Action<byte[]> ToClient = _ => { };
            public readonly List<byte[]> Sent = new();
            public event EventHandler<byte[]> OnDataReceived;
            public void Send(EndPoint endpoint, byte[] buf) { lock (Sent) Sent.Add(buf); ToClient(buf); }
            public void Deliver(byte[] datagram) => OnDataReceived?.Invoke(ClientEndpoint, datagram);
        }

        private sealed class ClientPipe : IClientTransport
        {
            public Action<byte[]> ToServer = _ => { };
            public event EventHandler<byte[]> OnDataReceived;
            public void Send(byte[] buf) => ToServer(buf);
            public void Deliver(byte[] datagram) => OnDataReceived?.Invoke(null, datagram);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void VerifiedOnOneInstance_HandshakesOnAnother(int version)
        {
            var verifierPipe = new ServerPipe();
            var serverPipe = new ServerPipe();
            var clientPipe = new ClientPipe();
            var verifier = new DtlsServer(verifierPipe);
            var server = new DtlsServer(serverPipe);
            var client = new DtlsClient(clientPipe) { MaximumVersion = version == 12 ? DtlsVersion.Dtls12 : DtlsVersion.Dtls13 };

            var results = new List<bool>();
            bool verified = false;
            // Delivery is synchronous: ClientHello2 is verified inside the call verifying ClientHello1.
            clientPipe.ToServer = d =>
            {
                bool wasVerified = verified;
                bool ok = wasVerified || verifier.VerifyClientHello(ClientEndpoint, d);
                if (!wasVerified)
                {
                    lock (results) results.Add(ok);
                    verified |= ok;
                }
                if (ok)
                    serverPipe.Deliver(d);
            };
            verifierPipe.ToClient = clientPipe.Deliver;
            serverPipe.ToClient = clientPipe.Deliver;

            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            Assert.IsNull(done.Task.Result, done.Task.Result?.ToString());

            CollectionAssert.AreEquivalent(new[] { false, true }, results, "the first ClientHello is answered with a cookie, the second carries it");
            Assert.HasCount(1, verifierPipe.Sent, "the verifier sends only the HelloVerifyRequest/HelloRetryRequest");
            Assert.IsEmpty(verifier.Connections, "verifying creates no connection");
            Assert.IsTrue(SpinWait.SpinUntil(() => server.GetConnection(ClientEndpoint)?.IsHandshakeComplete == true, Timeout));
            Assert.AreEqual(version == 12 ? DtlsVersion.Dtls12 : DtlsVersion.Dtls13, client.NegotiatedVersion);
        }

        [TestMethod]
        public void NotAClientHello_IsDroppedSilently()
        {
            var pipe = new ServerPipe();
            var verifier = new DtlsServer(pipe);

            Assert.IsFalse(verifier.VerifyClientHello(ClientEndpoint, new byte[] { 0x17, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0 }));
            Assert.IsFalse(verifier.VerifyClientHello(ClientEndpoint, Array.Empty<byte>()));
            Assert.IsEmpty(pipe.Sent);
            Assert.IsEmpty(verifier.Connections);
        }
    }
}
