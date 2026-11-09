using System.Text;
using SharpDTLS;
using SharpDTLS.UDP;

// listens on UDP 0.0.0.0:8888 with a self-signed certificate
var server = new DtlsServer(new ServerTransport());
server.ApplicationDataReceived += (sender, e) =>
{
    Console.WriteLine($"Received: {Encoding.UTF8.GetString(e.Data)}");
    e.Connection.SendApplicationData(e.Data); // echo it back
};
Console.WriteLine("DTLS server listening on UDP port 8888, press Enter to stop.");
Console.ReadLine();
