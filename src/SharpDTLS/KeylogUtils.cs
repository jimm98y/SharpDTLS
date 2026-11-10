// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

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
