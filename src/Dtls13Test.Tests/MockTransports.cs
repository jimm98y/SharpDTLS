using SharpSRTP.UDP;
using System;
using System.Net;

namespace Dtls13Test.Tests
{
    // In-memory transport pair for unit testing DTLS handshakes without real sockets.
    // Wire up with MockTransportPair.Create() and pass Server/Client to the DTLS constructors.
    public class MockServerTransport : IServerTransport
    {
        public event EventHandler<byte[]> OnDataReceived;
        public MockClientTransport ConnectedClient { get; set; }
        public static readonly EndPoint FakeClientEndpoint = IPEndPoint.Parse("127.0.0.1:49152");

        public void Send(EndPoint endpoint, byte[] buf)
            => ConnectedClient.InjectFromServer(buf);

        // Simulate the DTLS client sending to the server.
        public void InjectFromClient(byte[] data)
            => OnDataReceived?.Invoke(FakeClientEndpoint, data);
    }

    public class MockClientTransport : IClientTransport
    {
        public event EventHandler<byte[]> OnDataReceived;
        public MockServerTransport ConnectedServer { get; set; }

        public void Send(byte[] buf)
            => ConnectedServer.InjectFromClient(buf);

        // Called by MockServerTransport.Send to deliver bytes to the client.
        public void InjectFromServer(byte[] data)
            => OnDataReceived?.Invoke(null, data);
    }

    public static class MockTransportPair
    {
        public static (MockServerTransport server, MockClientTransport client) Create()
        {
            var server = new MockServerTransport();
            var client = new MockClientTransport();
            server.ConnectedClient = client;
            client.ConnectedServer = server;
            return (server, client);
        }
    }
}
