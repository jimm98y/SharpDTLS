using SharpDTLS.UDP;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>The DTLS example of the README, over UDP on loopback: it has to keep working as written there.</summary>
    [TestClass]
    public sealed class TestReadmeExample
    {
        private static readonly TimeSpan Timeout = TestTimeouts.InProcess;

        [TestMethod]
        public void DtlsExample_HandshakesAndExchangesData()
        {
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new DtlsServer(serverTransport);
            var serverReceived = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (sender, e) =>
            {
                serverReceived.TrySetResult(Encoding.UTF8.GetString(e.Data));
                e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("Hello from server!"));
            };

            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, serverTransport.LocalEndpoint.Port));
            var client = new DtlsClient(clientTransport);
            var clientReceived = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (sender, e) => client.SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
            client.ApplicationDataReceived += (sender, data) => clientReceived.TrySetResult(Encoding.UTF8.GetString(data));
            client.Failed += (sender, ex) => clientReceived.TrySetException(ex);
            client.BeginHandshake();

            Assert.IsTrue(serverReceived.Task.Wait(Timeout), "the server received nothing");
            Assert.AreEqual("Hello from client!", serverReceived.Task.Result);
            Assert.IsTrue(clientReceived.Task.Wait(Timeout), "the client received nothing");
            Assert.AreEqual("Hello from server!", clientReceived.Task.Result);
            Assert.AreEqual(DtlsVersion.Dtls13, client.NegotiatedVersion);
            client.Close();
        }
    }
}
