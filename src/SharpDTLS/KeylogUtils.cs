using System.IO;
using System.Text;

namespace SharpDTLS
{
    internal static class KeylogUtils
    {
        public static void WriteKeys(string clientRandom, string clientHandshakeTrafficSecret, string clientTrafficSecret, string serverHandhsakeTrafficSecret, string serverTrafficSecret)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"CLIENT_HANDSHAKE_TRAFFIC_SECRET {clientRandom.ToLowerInvariant()} {clientHandshakeTrafficSecret.ToLowerInvariant()}");
            sb.AppendLine($"SERVER_HANDSHAKE_TRAFFIC_SECRET {clientRandom.ToLowerInvariant()} {serverHandhsakeTrafficSecret.ToLowerInvariant()}");
            sb.AppendLine($"CLIENT_TRAFFIC_SECRET_0 {clientRandom.ToLowerInvariant()} {clientTrafficSecret.ToLowerInvariant()}");
            sb.AppendLine($"SERVER_TRAFFIC_SECRET_0 {clientRandom.ToLowerInvariant()} {serverTrafficSecret.ToLowerInvariant()}");
            File.WriteAllText("keylog.txt", sb.ToString());
        }
    }
}
