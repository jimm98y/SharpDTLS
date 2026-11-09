using System.Net;
using System.Net.Sockets;
using SharpDTLS;

var server = new TlsServer(); // a self-signed certificate
var listener = new TcpListener(IPAddress.Any, 4433);
listener.Start();
Console.WriteLine("TLS server listening on TCP port 4433.");
while (true)
{
    using var tcp = await listener.AcceptTcpClientAsync();
    using var tls = await TlsStream.AcceptAsync(server, tcp.GetStream());
    var buffer = new byte[4096];
    int read = await tls.ReadAsync(buffer);
    await tls.WriteAsync(buffer.AsMemory(0, read)); // echo it back
}
