using Dtls13Test.Messages;
using Org.BouncyCastle.Asn1;
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
        }
    }
}
