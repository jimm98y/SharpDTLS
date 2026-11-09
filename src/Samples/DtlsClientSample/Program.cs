using System.Text;
using SharpDTLS;
using SharpDTLS.UDP;

// connects to UDP 127.0.0.1:8888
var client = new DtlsClient(new ClientTransport());
client.HandshakeFinished += (sender, e) => client.SendApplicationData(Encoding.UTF8.GetBytes("Hello over DTLS!"));
client.ApplicationDataReceived += (sender, data) => Console.WriteLine($"Received: {Encoding.UTF8.GetString(data)}");
client.Failed += (sender, ex) => Console.WriteLine($"Failed: {ex.Message}");
client.BeginHandshake();
Console.WriteLine("Press Enter to stop.");
Console.ReadLine();
client.Close();
