using codecrafters_dns_server.src;
using System.Net;
using System.Net.Sockets;
using System.Text;

IPEndPoint? resolverEndPoint = null;

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--resolver")
    {
        string[] resolver = args[i + 1].Split(':');
        IPAddress resolverIP = IPAddress.Parse(resolver[0]);
        int resolverPort = int.Parse(resolver[1]);
        resolverEndPoint = new IPEndPoint(resolverIP, resolverPort);
        Console.WriteLine("Resolver: {0}:{1}", resolverEndPoint.Address, resolverEndPoint.Port);
    }
}

// Resolve UDP address
IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
int port = 2053;
IPEndPoint udpEndPoint = new IPEndPoint(ipAddress, port);

// Create UDP socket
UdpClient udpClient = new UdpClient(udpEndPoint);

Console.WriteLine("Listening for requests...");
while (true)
{
    // Receive data
    IPEndPoint sourceEndPoint = new IPEndPoint(IPAddress.Any, 0);
    byte[] receivedData = udpClient.Receive(ref sourceEndPoint);
    string receivedString = Encoding.ASCII.GetString(receivedData);

    DNSMessage receivedMessage = DNSUtils.ParseMessage(receivedData);

    Console.WriteLine($"Received {receivedData.Length} bytes from {sourceEndPoint}: {receivedString}\n");

    // Custom response
    DNSMessage responseMsg = receivedMessage;
    responseMsg.Header.QueryResponse = true;
    responseMsg.Header.ResponseCode = (byte)(receivedMessage.Header.OperationCode == 0 ? 0 : 4);

    if (resolverEndPoint != null)
    {
        Console.WriteLine("Asking resolver...");
        UdpClient resolverClient = new();
        int questionsToAsk = receivedMessage.QuestionSection.Questions.Count;

        if (questionsToAsk > 1) // multi question
        {
            DNSMessage resolverQuery = receivedMessage;

            Console.WriteLine("Received multiple ({0}) questions, asking one by one", questionsToAsk);
            for (int i = 0; i < questionsToAsk; i++)
            {
                Console.WriteLine("Asking question {0}", i);
                resolverQuery.QuestionSection = new DNSQuestionSection();
                resolverQuery.QuestionSection.Questions.Add(receivedMessage.QuestionSection.Questions[i]);

                DNSMessage partialResolverMsg = DoDNSRequest(resolverClient, resolverEndPoint, resolverQuery);
                Console.WriteLine("Partial response: {0}", partialResolverMsg);
                responseMsg.AnswerSection.Answers = responseMsg.AnswerSection.Answers
                    .Concat(partialResolverMsg.AnswerSection.Answers).ToList();
            }
        }
        else // single question
        {
            responseMsg.AnswerSection = DoDNSRequest(resolverClient, resolverEndPoint, receivedMessage).AnswerSection;
        }

        // handle response
        udpClient.Send(responseMsg.GetResponse(), sourceEndPoint);
        Console.WriteLine("Resolver response sent");
        Console.WriteLine("Response: {0}", Encoding.ASCII.GetString(responseMsg.GetResponse()));
        Console.WriteLine("Response formatted: {0}", responseMsg);
        resolverClient.Close();
        continue;
    }
    else // not using resolver
    {
        for (int i = 0; i < receivedMessage.QuestionSection.Questions.Count; i++)
        {
            DNSRecord answer = new();
            answer.Name = receivedMessage.QuestionSection.Questions[i].Name;
            answer.Type = 0x1;
            answer.Class = 0x1;
            answer.TTL = 60;
            answer.Length = 4;
            answer.Data = new byte[] { (byte)(i + 0), (byte)(i + 1), (byte)(i + 2), (byte)(i + 3) };

            responseMsg.AnswerSection.Answers.Add(answer);
        }
    }

    udpClient.Send(responseMsg.GetResponse(), sourceEndPoint);
    Console.WriteLine("Response sent");
    Console.WriteLine("Response: {0}", Encoding.ASCII.GetString(responseMsg.GetResponse()));
    Console.WriteLine("Response formatted: {0}", responseMsg);

    // Send response
    udpClient.Send(responseMsg.GetResponse(), sourceEndPoint);
}

static DNSMessage DoDNSRequest(UdpClient client, IPEndPoint endPoint, DNSMessage query)
{
    client.Send(query.GetResponse(), endPoint);
    return DNSUtils.ParseMessage(client.Receive(ref endPoint));
}