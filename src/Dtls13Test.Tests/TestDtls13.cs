using Dtls13Test.Messages;
using System.Diagnostics;

namespace Dtls13Test.Tests
{
    [TestClass]
    public sealed class TestDtls13
    {
        [DataRow("e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff", "35:80:72:d6:36:58:80:d1:ae:ea:32:9a:df:91:21:38:38:51:ed:21:a2:8e:3b:75:e9:65:d0:d2:cd:16:62:54", "16 fe fd 00 00 00 00 00 00 00 00 00 9d 01 00 00 91 00 00 00 00 00 00 00 91 fe fd e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 06 13 01 13 02 13 03 01 00 00 61 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2b 00 03 02 fe fc 00 0d 00 20 00 1e 06 03 05 03 04 03 02 03 08 06 08 0b 08 05 08 0a 08 04 08 09 06 01 05 01 04 01 03 01 02 01 00 16 00 00 00 0a 00 04 00 02 00 1d")]
        [TestMethod]
        public void TestClientHelloCreate(string clientRandom, string publicKey, string expected)
        {
            byte[] publicKeyBytes = Convert.FromHexString(publicKey.Replace(":", ""));
            var clientHello = new ClientHelloDatagram(publicKeyBytes) { ClientRandom = Convert.FromHexString(clientRandom.Replace(" ", "")) };
            string actual = Convert.ToHexString(clientHello.ToBytes()).ToLowerInvariant();
            Debug.WriteLine(actual);
            Debug.WriteLine(expected.Replace(" ", ""));
            Assert.AreEqual(expected.Replace(" ", ""), actual);
        }

        [DataRow("16 fe fd 00 00 00 00 00 00 00 00 00 9d 01 00 00 91 00 00 00 00 00 00 00 91 fe fd e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 06 13 01 13 02 13 03 01 00 00 61 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2b 00 03 02 fe fc 00 0d 00 20 00 1e 06 03 05 03 04 03 02 03 08 06 08 0b 08 05 08 0a 08 04 08 09 06 01 05 01 04 01 03 01 02 01 00 16 00 00 00 0a 00 04 00 02 00 1d")]
        [TestMethod]
        public void TestClientHelloRead(string clientHelloHex)
        {
            var clientHello = new ClientHelloDatagram();
            clientHello.FromBytes(Convert.FromHexString(clientHelloHex.Replace(" ", "")));

            string actual = Convert.ToHexString(clientHello.ToBytes()).ToLowerInvariant();
            Assert.AreEqual(clientHelloHex.Replace(" ", ""), actual);
        }

        [DataRow("70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f", "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "16 fe fd 00 00 00 00 00 00 00 00 00 62 02 00 00 56 00 00 00 00 00 00 00 56 fe fd 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 fe fc")]
        [TestMethod]
        public void TestServerHelloCreate(string serverRandom, string publicKey, string expected)
        {
            byte[] publicKeyBytes = Convert.FromHexString(publicKey);
            var serverHello = new ServerHelloDatagram(publicKeyBytes, 0x1301) { ServerRandom = Convert.FromHexString(serverRandom.Replace(" ", "")) };
            string actual = Convert.ToHexString(serverHello.ToBytes()).ToLowerInvariant();
            Debug.WriteLine(actual);
            Debug.WriteLine(expected.Replace(" ", ""));
            Assert.AreEqual(expected.Replace(" ", ""), actual);
        }


        [DataRow("16 fe fd 00 00 00 00 00 00 00 00 00 62 02 00 00 56 00 00 00 00 00 00 00 56 fe fd 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 fe fc")]
        [TestMethod]
        public void TestServerHelloRead(string serverHelloHex)
        {
            var serverHello = new ServerHelloDatagram();
            serverHello.FromBytes(Convert.FromHexString(serverHelloHex.Replace(" ", "")));

            string actual = Convert.ToHexString(serverHello.ToBytes()).ToLowerInvariant();
            Assert.AreEqual(serverHelloHex.Replace(" ", ""), actual);
        }

        [DataRow("08 00 00 12 00 01 00 00 00 00 00 12 00 10 00 0a 00 0c 00 0a 00 17 00 1d 00 18 00 19 01 00 16")]
        [TestMethod]
        public void TestServerExtensions(string serverExtensionsHex)
        {
            var serverExtensions = new ServerExtensionsDatagram();
            serverExtensions.FromBytes(Convert.FromHexString(serverExtensionsHex.Replace(" ", "")));

            string actual = Convert.ToHexString(serverExtensions.ToBytes()).ToLowerInvariant();
            Assert.AreEqual(serverExtensionsHex.Replace(" ", ""), actual);

            var cryptoContext = new Dtls13CryptoContext("", "", "004e03e64ab6cba6b542775ec230e20a", "6d9924be044ee97c624913f2", "", "7173fac51194e775001d625ef69d7c9f");
            var encrypted = new ServerEncryptedExtensionsDatagram(cryptoContext, serverExtensions);
            encrypted.FromBytes(encrypted.ToBytes());
        }


        [DataRow("2e 79 fa 00 2f ee 9d cf f3 f8 67 9a 48 59 fe 68 37 7f b3 4a da 85 df 87 9c 67 3e 50 1d 7a 4e 8f 19 50 e0 fc f6 7f e4 42 e7 d7 d2 b8 a3 d5 fa 59 57 4f fd 00")]
        [TestMethod]
        public void TestEncryptedServerExtensions(string serverExtensionsHex)
        {
            var cryptoContext = new Dtls13CryptoContext("", "", "004e03e64ab6cba6b542775ec230e20a", "6d9924be044ee97c624913f2", "", "7173fac51194e775001d625ef69d7c9f");
            var serverExtensions = new ServerEncryptedExtensionsDatagram(cryptoContext, new ServerExtensionsDatagram());
            serverExtensions.FromBytes(Convert.FromHexString(serverExtensionsHex.Replace(" ", "")));

            string actual = Convert.ToHexString(serverExtensions.ToBytes()).ToLowerInvariant();
            Assert.AreEqual(serverExtensionsHex.Replace(" ", ""), actual);
        }

        [DataRow("2e ed 2b 03 4b d3 77 7e 1a df 9e 98 c8 c4 ff a0 72 c2 c3 b6 bb cd 9f bd 2d 1f 34 3c 5d f9 54 d9 97 a2 cd 1d 33 42 a3 3d 3f 6a 85 e1 21 42 3c e0 02 ea 33 5e 37 7e 7a 21 5b 8a 9e cc 5e 26 7c 60 a2 bc 79 4e d1 d8 1f 39 8b ce df a3 68 fb db 7c a3 67 a0 46 65 5d 61 e4 86 67 62 fa ac fd a4 9d 0f 3a 39 71 86 d8 32 e4 81 87 d0 76 ea 8d e5 32 12 87 be 9b fd a2 15 19 da 58 e0 c4 80 56 99 7e 49 2e df e4 76 6b 2c d5 1e a1 2b c2 f6 d5 50 5b 80 e5 1a 64 5d a9 b0 7f bf 7a 01 b8 4d 5b a7 22 b2 e1 7d d9 52 8c 28 63 cd 63 a7 35 b5 4c d8 23 95 87 84 1a 59 2f be 57 5b 2d e1 8a 6c 99 f7 82 a9 56 e2 8c e7 69 67 42 67 3d 7e e7 37 f4 6e 9c ba a2 89 2d 97 21 ef cc c9 1f 16 72 26 a5 be 4c 9c d8 6b 97 fe f3 32 3f d1 92 f4 60 e8 ef 8b 91 3b bf 9f 97 05 63 85 d4 c3 ec 2b 2b dc 2e c4 8a 66 8c f6 f1 0d b3 fe 00 91 97 fa b9 8d 7c 2a 88 15 ac 5a 4e d3 aa 08 94 b9 f9 f9 95 12 43 0d f2 1f 13 4c 49 34 40 73 f9 af 32 8e 35 c2 e1 6b 91 3f 4e 61 33 21 e4 a7 9b d2 d3 38 47 32 1e 61 5d 58 94 09 b1 65 f9 c2 b0 18 80 4f 3c 33 40 e4 0a d5 f5 9a 26 46 0a 12 0f 2d 55 fc 8b ca 47 22 74 fd b9 06 09 a2 18 70 e1 cc 41 aa d0 24 fa 48 a8 6f 07 8f 90 8b c6 26 18 c4 c3 2f 0c fc fb b5 95 a7 d2 93 f4 ba ab 93 ff 35 f0 de 10 71 17 1e 4c 51 0d 75 dd 29 f5 0d 3d e8 1c ae 9e 1c 56 ed 60 9c 1b c7 27 5e ac 1d 69 33 df 08 93 dd 0e 3c 5c 7f d3 65 14 26 b3 e4 c3 ca 6d 46 1d 82 0a df ff 75 fb 7b 15 8b e9 89 30 89 da c9 30 a0 15 f8 9c b4 ef 22 7a b9 e4 3d f0 14 7a 25 07 59 e3 e0 1b 5d b7 48 0c 52 7a 1d 4b 8a 09 c4 ac 05 fc c6 d6 40 15 d6 af 2c 3e 52 15 03 a8 2f b9 02 5c 61 98 18 ca 31 fb 24 03 63 0a c0 6a b7 11 90 53 a7 02 86 24 0b 3f 8e 43 96 61 ad 95 48 7a a5 72 d7 08 60 8d d0 d4 fe 27 bb cf 1e df 50 3a 54 05 46 0b 9e 10 f6 93 4a 41 a8 cf b7 0b 60 90 6f 7e 66 d6 53 15 61 ef 08 ad e3 de 45 77 a7 77 6b f6 56 bb 48 5c ee 28 2c 83 7a a8 bc e0 6a e6 06 a1 71 d7 54 96 36 fe d8 3e 24 bf 9f 10 5b 7d 1d 02 da 30 86 ce 24 49 af a2 d0 ec 26 18 5d 0c 1f 05 2f 88 cd 9d 55 eb 12 4b da e3 66 7f 59 79 97 95 f9 27 50 b9 ca 70 55 66 86 6a 99 24 a2 46 a4 71 90 4b 2d 69 dc 17 cb fe 50 a5 62 ff 26 ff 9e 40 4d 7b 2a 11 67 0c 27 56 3f 3e 37 99 3c c6 e6 73 43 6d c3 a8 51 21 4d 6d 27 86 2b 64 5d cb 0b f4 d4 c7 44 0f 6a d4 83 ef 9d 58 fa b4 7d 24 4b d6 cf a6 8f 12 e9 aa ae cd 2d 52 8e 85 66 f9 7f 50 56 cf 8e fc 7d 1e 55 fb ee 1b e8 7f 7f 89 73 7c 8a fa 20 e4 96 37 0d 25 f7 52 99 e5 91 8c b9 4b a5 b5 ef db 84 7d 9c a5 44 a5 38 65 a3 6d 69 1e be 8b e8 e2 da 08 c1 7b e9 02 38 0d b9 a3 d7 04 91 b8 98 f8 c5 88 e7 44 64 8e b9 37 70 53 0c 83 ce cf a4 30 70 21 45 22 93 8c 0e 66 82 9e f1 33 34 9b")]
        [TestMethod]
        public void TestEncryptedCertificate(string serverCertificateHex)
        {
            var cryptoContext = new Dtls13CryptoContext("", "", "004e03e64ab6cba6b542775ec230e20a", "6d9924be044ee97c624913f2", "", "7173fac51194e775001d625ef69d7c9f") { KeyUseCounter = 1 };
            var serverCertificate = new ServerEncryptedExtensionsDatagram(cryptoContext, new ServerCertificateDatagram());
            serverCertificate.FromBytes(Convert.FromHexString(serverCertificateHex.Replace(" ", "")));

            string actual = Convert.ToHexString(serverCertificate.ToBytes()).ToLowerInvariant();
            Assert.AreEqual(serverCertificateHex.Replace(" ", ""), actual);
        }
    }
}
