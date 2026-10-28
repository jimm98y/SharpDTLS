using SharpDTLS;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>TLS 1.3 0-RTT (RFC 8446 §4.2.10) with EndOfEarlyData (§4.5).</summary>
    [TestClass]
    public sealed class TestTls13EarlyData
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static Dtls13SessionTicket Ticket(IPEndPoint endpoint)
        {
            var client = TestTls13.Connect(endpoint);
            Assert.IsTrue(SpinWait.SpinUntil(() => client.SessionTicket != null, Timeout), "no ticket");
            client.Close();
            return client.SessionTicket;
        }

        [TestMethod]
        public void EarlyData_IsAccepted_ThenTheConnectionContinues()
        {
            using var server = new Tls13Server { MaxEarlyDataSize = 1024 };
            var early = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var data = new System.Collections.Concurrent.ConcurrentQueue<string>();
            server.EarlyDataReceived += (_, e) => early.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.ApplicationDataReceived += (_, e) => data.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            var ticket = Ticket(server.LocalEndpoint);
            Assert.AreEqual(1024u, ticket.MaxEarlyDataSize);
            var client = TestTls13.Connect(server.LocalEndpoint, c => { c.ResumptionTicket = ticket; c.EarlyData = Encoding.UTF8.GetBytes("zero rtt"); });
            Assert.IsTrue(client.EarlyDataAccepted);
            Assert.IsTrue(SpinWait.SpinUntil(() => early.Contains("zero rtt"), Timeout));
            client.SendApplicationData(Encoding.UTF8.GetBytes("after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => data.Contains("after"), Timeout));
        }

        [TestMethod]
        public void DeclinedEarlyData_IsSkipped()
        {
            using var server = new Tls13Server { MaxEarlyDataSize = 1024 };
            var early = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var data = new System.Collections.Concurrent.ConcurrentQueue<string>();
            server.EarlyDataReceived += (_, e) => early.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.ApplicationDataReceived += (_, e) => data.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            var ticket = Ticket(server.LocalEndpoint);
            server.MaxEarlyDataSize = 0; // the client still offers it from the ticket
            var client = TestTls13.Connect(server.LocalEndpoint, c => { c.ResumptionTicket = ticket; c.EarlyData = Encoding.UTF8.GetBytes("zero rtt"); });
            Assert.IsFalse(client.EarlyDataAccepted);
            Assert.IsTrue(client.IsResumed);
            client.SendApplicationData(Encoding.UTF8.GetBytes("after"));
            Assert.IsTrue(SpinWait.SpinUntil(() => data.Contains("after"), Timeout));
            Assert.IsEmpty(early);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void SharpTlsClient_SendsEarlyDataToOpenSsl()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Ecdsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);
            using var server = OpenSslProcess.StartServer(p => $"s_server -tls1_3 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath} -early_data", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
            var endpoint = new IPEndPoint(IPAddress.Loopback, port);

            var ticket = Ticket(endpoint);
            Assert.IsGreaterThan(0u, ticket.MaxEarlyDataSize, "s_server -early_data advertises 0-RTT in its tickets");
            var client = TestTls13.Connect(endpoint, c => { c.ResumptionTicket = ticket; c.EarlyData = Encoding.UTF8.GetBytes("zero rtt to openssl\n"); });
            Assert.IsTrue(client.EarlyDataAccepted, server.Output);
            Assert.IsTrue(server.WaitForOutput("zero rtt to openssl", Timeout), server.Output);
            client.SendApplicationData(Encoding.UTF8.GetBytes("after the handshake\n"));
            Assert.IsTrue(server.WaitForOutput("after the handshake", Timeout), server.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSslClient_SendsEarlyDataToSharpTlsServer()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            using var server = new Tls13Server { MaxEarlyDataSize = 16384 };
            var early = new System.Collections.Concurrent.ConcurrentQueue<string>();
            server.EarlyDataReceived += (_, e) => early.Enqueue(Encoding.UTF8.GetString(e.Data));
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            string session = Path.Combine(dir, "session.pem");
            string earlyFile = Path.Combine(dir, "early.txt");
            File.WriteAllText(earlyFile, "zero rtt from openssl\n");
            using (var first = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_out {session}", dir))
                Assert.IsTrue(SpinWait.SpinUntil(() => File.Exists(session) && new FileInfo(session).Length > 0, Timeout), first.Output);
            using var second = new OpenSslProcess($"s_client -tls1_3 -connect 127.0.0.1:{server.LocalEndpoint.Port} -sess_in {session} -early_data {earlyFile}", dir);
            Assert.IsTrue(SpinWait.SpinUntil(() => early.Any(e => e.Contains("zero rtt from openssl")), Timeout), second.Output);
            Assert.IsTrue(second.WaitForOutput("Early data was accepted", Timeout), second.Output);
        }
    }
}
