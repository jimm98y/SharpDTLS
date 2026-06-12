using System;

namespace SharpDTLS.DTLS13.Messages
{
    public class HelloRetryRequest : ServerHelloDatagram
    {
        const string HelloRetryRequestRandom = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";

        public HelloRetryRequest()
        { }

        public HelloRetryRequest(DateTime timestamp, string clientIP, int clientPort)
        {
            ServerRandom = Convert.FromHexString(HelloRetryRequestRandom);
            Extensions = [.. GetDefaultExtensions(), new CookieExtension(Dtls13CryptoUtils.CreateCookie(timestamp, clientIP, clientPort))];
        }

        private static ITlsExtension[] GetDefaultExtensions()
        {
            return new ITlsExtension[]
            {
                new ServerSupportedVersions(),
            };
        }
    }
}
