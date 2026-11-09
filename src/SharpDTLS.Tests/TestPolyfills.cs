#if NETFRAMEWORK
// What the tests use on .NET Framework beyond Meziantou.Polyfill (and SharpDTLS's own polyfills, visible to them).
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

internal static class TestPolyfills
{
    public static int Receive(this Socket socket, Span<byte> buffer)
    {
        byte[] array = new byte[buffer.Length];
        int received = socket.Receive(array);
        array.AsSpan(0, received).CopyTo(buffer);
        return received;
    }

    public static int Send(this Socket socket, ReadOnlySpan<byte> buffer) => socket.Send(buffer.ToArray());

    /// <summary>The processes the tests start (openssl, the wolfSSL harness) have no children.</summary>
    public static void Kill(this Process process, bool entireProcessTree) => process.Kill();

    public static Task ConnectAsync(this TcpClient client, IPEndPoint endpoint) => client.ConnectAsync(endpoint.Address, endpoint.Port);

    /// <summary>SharpDTLS's ReadExactlyAsync polyfill returns a Task where .NET returns a ValueTask.</summary>
    public static Task AsTask(this Task task) => task;
}
#endif
