#if NET
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.Net;

namespace SharpDTLS.Tests
{
    /// <summary>The application data of an established connection, sent and received, allocates nothing.</summary>
    [TestClass]
    [DoNotParallelize]
    public sealed class TestAllocations
    {
        private const int Warmup = 200, Records = 1000;

        // Datagrams handed over on the sending thread, so one thread runs both ends and counts every allocation.
        private sealed class Pair : IServerTransport, IClientTransport
        {
            private static readonly EndPoint Client = IPEndPoint.Parse("127.0.0.1:50000");
            private DatagramHandler _toServer, _toClient;

            event DatagramHandler IServerTransport.OnDataReceived { add => _toServer += value; remove => _toServer -= value; }
            event DatagramHandler IClientTransport.OnDataReceived { add => _toClient += value; remove => _toClient -= value; }

            void IServerTransport.Send(EndPoint endpoint, ReadOnlySpan<byte> datagram) => _toClient?.Invoke(null, datagram);
            void IClientTransport.Send(ReadOnlySpan<byte> datagram) => _toServer?.Invoke(Client, datagram);
        }

        [TestMethod]
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC02F, false, true)] // ECDHE_RSA_AES_128_GCM_SHA256
        [DataRow(DtlsVersion.Dtls12, (ushort)0xCCA8, false, true)] // ECDHE_RSA_CHACHA20_POLY1305
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC09E, false, true)] // DHE_RSA_AES_128_CCM
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC013, false, true)] // ECDHE_RSA_AES_128_CBC_SHA
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC02F, true, true)]
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1301, false, true)] // TLS_AES_128_GCM_SHA256
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1302, false, true)] // TLS_AES_256_GCM_SHA384
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1303, false, true)] // TLS_CHACHA20_POLY1305_SHA256
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1304, false, true)] // TLS_AES_128_CCM_SHA256
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1301, true, true)]
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC013, false, false)] // BouncyCastle's CBC and HMAC allocate nothing either
        public void ApplicationDataAllocatesNothing(ushort version, ushort suite, bool connectionIds, bool netCrypto)
        {
            Assert.AreEqual(0L, Allocated(version, suite, connectionIds, netCrypto ? new NetTlsCrypto() : null));
        }

        /// <summary>
        /// BouncyCastle's AEADs allocate as they are set up for each nonce: of a round trip (four records sealed or
        /// opened) about 2.3 KB for GCM and 1.1 KB for ChaCha20-Poly1305 with BouncyCastle 2.7. Bounded here.
        /// </summary>
        [TestMethod]
        [DataRow(DtlsVersion.Dtls12, (ushort)0xC02F, 2400)]
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1301, 2400)]
        [DataRow(DtlsVersion.Dtls13, (ushort)0x1303, 1200)]
        public void BouncyCastleAeadsAllocateInTheirSetUpAlone(ushort version, ushort suite, int bound)
        {
            long perRoundTrip = Allocated(version, suite, connectionIds: false, crypto: null) / Records;
            Console.WriteLine($"{perRoundTrip} bytes per round trip");
            Assert.IsTrue(perRoundTrip <= bound, $"{perRoundTrip} bytes per round trip");
        }

        // Bytes allocated by Records round trips: the client sends, the server echoes, the client receives.
        private static long Allocated(ushort version, ushort suite, bool connectionIds, ITlsCrypto crypto)
        {
            var pair = new Pair();
            var server = new DtlsServer(pair) { CipherSuites = new List<ushort> { suite }, UseConnectionIds = connectionIds, RequireCookie = false };
            var client = new DtlsClient(pair)
            {
                MaximumVersion = version,
                CipherSuites = new List<ushort> { suite },
                UseConnectionId = connectionIds,
                ConnectionIdLength = connectionIds ? 8 : 0,
                ServerCertificateValidator = (certificate, chain) => true,
            };
            if (crypto != null)
            {
                server.Crypto = crypto;
                client.Crypto = crypto;
            }
            int received = 0;
            server.ApplicationDataReceived += (connection, data) => connection.SendApplicationData(data);
            client.ApplicationDataReceived += (connection, data) => received++;
            bool finished = false;
            client.HandshakeFinished += (_, _) => finished = true;
            client.BeginHandshake();
            Assert.IsTrue(finished, "The handshake did not complete.");

            byte[] payload = new byte[1000];
            for (int i = 0; i < Warmup; i++)
                client.SendApplicationData(payload);
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < Records; i++)
                client.SendApplicationData(payload);
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.AreEqual(Warmup + Records, received);
            client.Close();
            return allocated;
        }
    }
}
#endif
