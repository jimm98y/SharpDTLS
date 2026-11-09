using System;
using System.Globalization;

namespace SharpDTLS.Tests
{
    /// <summary>
    /// How long a test waits for something it expects to happen. A wait ends as soon as it does, so a long limit only
    /// slows a test that fails anyway; a short one fails tests on a busy machine, where the tests run in parallel and an
    /// external OpenSSL or wolfSSL process can take many seconds to start. To give a slow machine more time, set
    /// SHARPDTLS_TEST_TIMEOUT_SCALE to a factor, e.g. 2.
    /// </summary>
    internal static class TestTimeouts
    {
        private static readonly double Scale =
            double.TryParse(Environment.GetEnvironmentVariable("SHARPDTLS_TEST_TIMEOUT_SCALE"), NumberStyles.Float, CultureInfo.InvariantCulture, out double scale) && scale > 0
                ? scale
                : 1;

        /// <summary>A wait within this process: a handshake or a reply between our own peers or BouncyCastle's.</summary>
        public static readonly TimeSpan InProcess = TimeSpan.FromSeconds(30 * Scale);

        /// <summary>A wait involving an external process (OpenSSL, wolfSSL): its start, its handshake, its output.</summary>
        public static readonly TimeSpan Interop = TimeSpan.FromSeconds(60 * Scale);
    }
}
