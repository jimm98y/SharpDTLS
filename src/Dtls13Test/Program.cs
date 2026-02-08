

using Dtls13Test;
using SharpSRTP.UDP;

var serverTransport = new ServerTransport();
var clientTransport = new ClientTransport();

var server = new Dtls13Server(serverTransport);
var client = new Dtls13Client(clientTransport);

client.BeginHandshake();

Console.ReadLine();