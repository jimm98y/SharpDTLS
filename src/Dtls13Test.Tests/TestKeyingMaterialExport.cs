using SharpDTLS;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol10.DTLS10;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Checks exported keying material (RFC 5705 / RFC 8446 §7.5) and DTLS-SRTP keys (RFC 5764)
    /// against what OpenSSL and wolfSSL derive for the same session.
    /// </summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestKeyingMaterialExport
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static string OpenSslKeyingMaterial(OpenSslProcess process)
        {
            Assert.IsTrue(process.WaitForOutput("Keying material:", Timeout), "OpenSSL did not print keying material:\n" + process.Output);
            return Regex.Match(process.Output, @"Keying material:\s*([0-9A-Fa-f]+)").Groups[1].Value.ToLowerInvariant();
        }

        private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

        private static string Concat(DtlsSrtpKeys keys)
            => Hex(keys.ClientWriteKey.Concat(keys.ServerWriteKey).Concat(keys.ClientWriteSalt).Concat(keys.ServerWriteSalt).ToArray());

        [DataRow("-dtls1_2", (ushort)0x0001, "SRTP_AES128_CM_SHA1_80")]
        [DataRow("-dtls1_2", (ushort)0x0007, "SRTP_AEAD_AES_128_GCM")]
        [DataRow("-dtls1", (ushort)0x0001, "SRTP_AES128_CM_SHA1_80")]
        [TestMethod]
        public void SharpDtlsClient_SrtpKeys_MatchOpenSslServer(string version, ushort profile, string profileName)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Dtls12CryptoUtils.GenerateSelfSignedCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            int length = DtlsSrtp.KeyingMaterialLength(profile);
            string cipher = version == "-dtls1" ? " -cipher DEFAULT@SECLEVEL=0" : "";

            using var server = OpenSslProcess.StartServer(p =>
                $"s_server {version} -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}{cipher} -use_srtp {profileName} -keymatexport {DtlsSrtp.ExporterLabel} -keymatexportlen {length} -msg", dir, Timeout, out int port);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<DtlsSrtpKeys> getKeys;
            Func<ushort?> selected;

            if (version == "-dtls1")
            {
                var client = new Dtls10Client(transport) { SrtpProtectionProfiles = new[] { profile } };
                client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
                client.Failed += (_, ex) => handshake.TrySetException(ex);
                getKeys = client.GetSrtpKeys;
                selected = () => client.SelectedSrtpProtectionProfile;
                client.BeginHandshake();
            }
            else
            {
                var client = new Dtls12Client(transport) { SrtpProtectionProfiles = new[] { profile } };
                client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
                client.Failed += (_, ex) => handshake.TrySetException(ex);
                getKeys = client.GetSrtpKeys;
                selected = () => client.SelectedSrtpProtectionProfile;
                client.BeginHandshake();
            }

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);
            Assert.AreEqual(profile, selected(), server.Output);
            Assert.AreEqual(OpenSslKeyingMaterial(server), Concat(getKeys()));
        }

        [DataRow("-dtls1_2", (ushort)0x0001, "SRTP_AES128_CM_SHA1_80")]
        [DataRow("-dtls1_2", (ushort)0x0007, "SRTP_AEAD_AES_128_GCM")]
        [DataRow("-dtls1", (ushort)0x0007, "SRTP_AEAD_AES_128_GCM")]
        [TestMethod]
        public void OpenSslClient_SrtpKeys_MatchSharpDtlsServer(string version, ushort profile, string profileName)
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            int length = DtlsSrtp.KeyingMaterialLength(profile);
            string cipher = version == "-dtls1" ? " -cipher DEFAULT@SECLEVEL=0" : "";

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var received = new TaskCompletionSource<EndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<EndPoint, DtlsSrtpKeys> getKeys;

            if (version == "-dtls1")
            {
                var server = new Dtls10Server(transport);
                server.ApplicationDataReceived += (_, e) => received.TrySetResult(e.RemoteEndPoint);
                getKeys = server.GetSrtpKeys;
            }
            else
            {
                var server = new Dtls12Server(transport);
                server.ApplicationDataReceived += (_, e) => received.TrySetResult(e.RemoteEndPoint);
                getKeys = server.GetSrtpKeys;
            }

            using var client = new OpenSslProcess(
                $"s_client {version} -connect 127.0.0.1:{transport.LocalEndpoint.Port}{cipher} -use_srtp {profileName} -keymatexport {DtlsSrtp.ExporterLabel} -keymatexportlen {length} -ign_eof -msg", dir);

            string expected = OpenSslKeyingMaterial(client);
            client.WriteLine("ping");
            Assert.IsTrue(received.Task.Wait(Timeout), "Server did not receive data:\n" + client.Output);

            var keys = getKeys(received.Task.Result);
            Assert.IsNotNull(keys, "use_srtp was not negotiated");
            Assert.AreEqual(profile, keys.Profile);
            Assert.AreEqual(expected, Concat(keys));
        }

        [DataRow("TLS13-AES128-GCM-SHA256", "SRTP_AES128_CM_SHA1_80", (ushort)0x0001)]
        [DataRow("TLS13-AES256-GCM-SHA384", "SRTP_AEAD_AES_128_GCM", (ushort)0x0007)]
        [TestMethod]
        public void SharpDtlsClient_Dtls13Export_MatchesWolfSslServer(string cipher, string profileName, ushort profile)
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (kp, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", kp.Private);
            using var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath} -cipher {cipher} -srtp {profileName} -export EXPORTER-sharpdtls-test 48", dir, Timeout, out int port, WolfSsl.Harness);
            Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls13Client(transport) { SrtpProtectionProfiles = new[] { profile } };
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.BeginHandshake();

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + server.Output);
            Assert.IsTrue(server.WaitForOutput("EXPORT:", Timeout), server.Output);

            Assert.AreEqual(profile, client.SelectedSrtpProtectionProfile);
            Assert.AreEqual(Regex.Match(server.Output, "SRTP:([0-9a-f]+)").Groups[1].Value, Concat(client.GetSrtpKeys()));
            Assert.AreEqual(Regex.Match(server.Output, "EXPORT:([0-9a-f]+)").Groups[1].Value, Hex(client.ExportKeyingMaterial("EXPORTER-sharpdtls-test", null, 48)));
        }

        [TestMethod]
        public void WolfSslClient_Dtls13Export_MatchesSharpDtlsServer()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls13Server(transport);
            var handshake = new TaskCompletionSource<Tls13ServerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, e) => handshake.TrySetResult(((Dtls13ConnectionEventArgs)e).Connection);

            using var client = new OpenSslProcess($"client {transport.LocalEndpoint.Port} -cipher TLS13-CHACHA20-POLY1305-SHA256 -srtp SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80 -export EXPORTER-sharpdtls-test 32", dir, WolfSsl.Harness);

            Assert.IsTrue(handshake.Task.Wait(Timeout), "Handshake did not complete:\n" + client.Output);
            Assert.IsTrue(client.WaitForOutput("EXPORT:", Timeout), client.Output);
            var connection = handshake.Task.Result;

            Assert.AreEqual((ushort)0x0007, connection.SelectedSrtpProtectionProfile, "server preference is AEAD_AES_128_GCM");
            Assert.AreEqual(Regex.Match(client.Output, "SRTP:([0-9a-f]+)").Groups[1].Value, Concat(connection.GetSrtpKeys()));
            Assert.AreEqual(Regex.Match(client.Output, "EXPORT:([0-9a-f]+)").Groups[1].Value, Hex(connection.ExportKeyingMaterial("EXPORTER-sharpdtls-test", null, 32)));
        }
    }
}
