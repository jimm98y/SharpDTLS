

using Dtls13Test;
using SharpSRTP.UDP;
using System.Text;

var serverTransport = new ServerTransport();
var clientTransport = new ClientTransport();

var server = new Dtls13Server(serverTransport);
var client = new Dtls13Client(clientTransport);

client.HandshakeFinished += (sender, args) =>
{
    client.SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
};
client.BeginHandshake();

Console.ReadLine();