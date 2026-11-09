using System;
using System.Threading;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace SharpDTLS.Tests
{
    [TestClass]
    public static class TestAssembly
    {
        /// <summary>
        /// The tests run in parallel on thread-pool threads and block them waiting for a handshake, whose completion
        /// needs a pool thread of its own. The pool adds threads slowly when they are all busy, on .NET Framework by
        /// about two a second, so a test could wait many seconds for what had already happened; starting with enough
        /// threads avoids that.
        /// </summary>
        [AssemblyInitialize]
        public static void Initialize(TestContext context)
        {
            ThreadPool.GetMinThreads(out int workers, out int io);
            int wanted = Math.Max(64, Environment.ProcessorCount * 4);
            ThreadPool.SetMinThreads(Math.Max(workers, wanted), Math.Max(io, wanted));
        }
    }
}
