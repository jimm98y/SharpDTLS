using SharpDTLS;
using SharpDTLS.DTLS13;
using SharpDTLS.DTLS13.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS 1.3 PSK resumption with session tickets (RFC 8446 §2.2, §4.2.11, §4.6.1; RFC 9147).</summary>
    [TestClass]
    public sealed class TestDtls13Resumption
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private sealed class Run
        {
            public ScriptedTransportPair Pair = new();
            public Dtls13Server Server;
            public Dtls13Client Client;
            public Exception ClientError;
            public Tls13ServerConnection ServerConnection => Server.GetConnection(ScriptedTransportPair.ClientEndpoint);
            public List<string> ServerReceived = new();
        }

        private static Run Connect(SessionTicketKeys keys, Dtls13SessionTicket resume, bool helloRetry = true,
            IList<ushort> serverSuites = null, Action<Dtls13Server> configureServer = null, Action<Dtls13Client> configureClient = null,
            bool expectSuccess = true)
        {
            var r = new Run();
            r.Server = new Dtls13Server(r.Pair.Server) { TicketKeys = keys, ShouldSendHelloRetry = helloRetry, InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
            if (serverSuites != null)
                r.Server.CipherSuites = serverSuites;
            configureServer?.Invoke(r.Server);
            r.Server.ApplicationDataReceived += (_, e) => { lock (r.ServerReceived) r.ServerReceived.Add(Encoding.UTF8.GetString(e.Data)); };
            r.Client = new Dtls13Client(r.Pair.Client) { ResumptionTicket = resume, InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50) };
            configureClient?.Invoke(r.Client);

            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            r.Client.HandshakeFinished += (_, _) => done.TrySetResult(true);
            r.Client.Failed += (_, ex) => { r.ClientError = ex; done.TrySetResult(false); };
            r.Client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            if (expectSuccess)
            {
                Assert.IsTrue(done.Task.Result, "handshake failed: " + r.ClientError);
                Assert.IsTrue(SpinWait.SpinUntil(() => r.ServerConnection?.IsHandshakeComplete == true, Timeout));
            }
            return r;
        }

        private static Dtls13SessionTicket WaitForTicket(Run r)
        {
            Assert.IsTrue(SpinWait.SpinUntil(() => r.Client.SessionTicket != null, Timeout), "no ticket was issued");
            return r.Client.SessionTicket;
        }

        [DataRow(true)]
        [DataRow(false)]
        [TestMethod]
        public void Ticket_IsResumedWithAPskHandshake(bool helloRetry)
        {
            var keys = new SessionTicketKeys();
            var first = Connect(keys, null, helloRetry);
            Assert.IsFalse(first.Client.IsResumed);
            var ticket = WaitForTicket(first);
            Assert.AreEqual(first.Client.Session.CipherSuite.Id, ticket.CipherSuite);
            CollectionAssert.AreEqual(first.Client.Session.PeerCertificate, ticket.ServerCertificate);

            var second = Connect(keys, ticket, helloRetry);
            Assert.IsTrue(second.Client.IsResumed);
            Assert.IsTrue(second.ServerConnection.IsResumed);
            Assert.IsNotNull(second.Client.ServerCertificate, "the server certificate carries over from the ticket");

            // PSK handshake: no Certificate/CertificateVerify, so the server flight is smaller.
            Assert.IsLessThan(first.Pair.ServerSent.Sum(d => d.Length), second.Pair.ServerSent.Sum(d => d.Length));

            second.Client.SendApplicationData(Encoding.UTF8.GetBytes("resumed"));
            Assert.IsTrue(SpinWait.SpinUntil(() => second.ServerReceived.Contains("resumed"), Timeout));
            CollectionAssert.AreEqual(second.Client.ExportKeyingMaterial("EXPERIMENTAL x", null, 16), second.ServerConnection.ExportKeyingMaterial("EXPERIMENTAL x", null, 16));

            // The resumed connection issues a fresh ticket, which resumes again.
            var next = WaitForTicket(second);
            CollectionAssert.AreNotEqual(ticket.Ticket, next.Ticket);
            Assert.IsTrue(Connect(keys, next, helloRetry).Client.IsResumed);
        }

        [TestMethod]
        public void HelloRetryWithAnIncompatibleHash_DropsThePsk()
        {
            var keys = new SessionTicketKeys();
            var ticket = WaitForTicket(Connect(keys, null, serverSuites: new List<ushort> { 0x1301 }));

            // The server prefers a SHA-384 suite: the HelloRetryRequest selects it and the SHA-256 PSK is dropped.
            var r = Connect(keys, ticket, serverSuites: new List<ushort> { 0x1302, 0x1301 });
            Assert.IsFalse(r.Client.IsResumed);
            Assert.AreEqual((ushort)0x1302, r.Client.Session.CipherSuite.Id);
        }

        [TestMethod]
        public void TicketFromOtherKeysOrExpired_FallsBackToAFullHandshake()
        {
            var keys = new SessionTicketKeys();
            var ticket = WaitForTicket(Connect(keys, null));

            Assert.IsFalse(Connect(new SessionTicketKeys(), ticket).Client.IsResumed);

            keys.Lifetime = TimeSpan.Zero;
            Assert.IsFalse(Connect(keys, ticket).Client.IsResumed);
        }

        [TestMethod]
        public void WrongPsk_FailsTheBinderWithDecryptError()
        {
            var keys = new SessionTicketKeys();
            var ticket = WaitForTicket(Connect(keys, null));
            byte[] wrongPsk = (byte[])ticket.Psk.Clone();
            wrongPsk[0] ^= 1;
            var forged = new Dtls13SessionTicket(ticket.Ticket, ticket.LifetimeSeconds, ticket.AgeAdd, ticket.CipherSuite, wrongPsk, ticket.ServerCertificate);

            var r = Connect(keys, forged, expectSuccess: false);
            Assert.AreEqual(AlertDescription.DecryptError, (r.ClientError as DtlsException)?.Alert, r.ClientError?.ToString());
        }

        [TestMethod]
        public void ClientCertificate_CarriesOverToTheResumedSession()
        {
            var keys = new SessionTicketKeys();
            var (clientKey, clientCert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            Action<Dtls13Server> requireCert = s => s.RequireClientCertificate = true;
            Action<Dtls13Client> withCert = c => { c.ClientCertificate = clientCert; c.ClientCertificateKeyPair = clientKey; };

            var ticket = WaitForTicket(Connect(keys, null, configureServer: requireCert, configureClient: withCert));
            var r = Connect(keys, ticket, configureServer: requireCert);
            Assert.IsTrue(r.Client.IsResumed);
            Assert.AreEqual(clientCert, r.ServerConnection.ClientCertificate);
        }

        [TestMethod]
        public void ClientWithoutTickets_GetsNone()
        {
            var r = Connect(new SessionTicketKeys(), null, configureClient: c => c.UseSessionTickets = false);
            Thread.Sleep(200);
            Assert.IsNull(r.Client.SessionTicket);
        }
    }
}
