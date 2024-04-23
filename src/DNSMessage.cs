using System.Reflection.PortableExecutable;
using System.Text;
using System.Xml.Linq;

namespace codecrafters_dns_server.src
{

    internal struct DNSQuestionSection
    {
        public List<DNSQuestion> Questions;

        public DNSQuestionSection()
        {
            Questions = new();
        }

        public byte[] GetResponse()
        {
            return Questions
                .SelectMany(question => question.GetResponse()).ToArray();
        }
    }

    internal struct DNSAnswerSection
    {
        public List<DNSRecord> Answers;

        public DNSAnswerSection()
        {
            Answers = new();
        }

        public byte[] GetResponse()
        {
            return Answers
                .SelectMany(answer => answer.GetResponse()).ToArray();
        }
    }

    internal struct DNSRecord
    {
        public List<byte[]> Name;
        public ushort Type;
        public ushort Class;
        public int TTL;
        public ushort Length;
        public byte[] Data;

        public DNSRecord()
        {
            Name = new();
            Type = new();
            Class = new();
            TTL = new();
            Length = 0;
            Data = new byte[Length];
        }

        public byte[] GetResponse()
        {
            // 11 = 1 for null byte, 2 for type, 2 for class, 4 for TTL and 2 for Length
            int responseLen = Name.Aggregate(0, (acc, label) => acc + label.Length + 1) + 11 + Data.Length;

            byte[] response = new byte[responseLen];
            int ind = 0;
            foreach (var label in Name)
            {
                response[ind++] = (byte)label.Length;
                foreach (var character in label)
                {
                    response[ind++] = character;
                }
            }
            response[ind++] = 0x0;
            response[ind++] = (byte)(Type >> 8);
            response[ind++] = (byte)(Type & 0xFF);
            response[ind++] = (byte)(Class >> 8);
            response[ind++] = (byte)(Class & 0xFF);
            response[ind++] = (byte)(TTL >> 24);
            response[ind++] = (byte)(TTL >> 16);
            response[ind++] = (byte)(TTL >> 8);
            response[ind++] = (byte)(TTL & 0xFF);
            response[ind++] = (byte)(Length >> 8);
            response[ind++] = (byte)(Length & 0xFF);
            Array.Copy(Data,0,response,ind,Data.Length);
            return response;
        }

        public DNSRecord AddName(string name)
        {
            foreach (var label in name.Split("."))
            {
                Name.Add(Encoding.ASCII.GetBytes(label));
            }
            return this;
        }
    }


    internal struct DNSQuestion
    {
        public List<byte[]> Name;
        public ushort Type;
        public ushort Class;

        public DNSQuestion()
        {
            Name = new();
            Type = new();
            Class = new();
        }

        public byte[] GetResponse()
        {
            // 5 = 1 for null byte, 2 for type and 2 for class
            int responseLen = Name.Aggregate(0, (acc, label) => acc + label.Length + 1) + 5;

            byte[] response = new byte[responseLen];
            int ind = 0;
            foreach (var label in Name)
            {
                response[ind++] = (byte)label.Length;
                foreach (var character in label)
                {
                    response[ind++] = character;
                }
            }
            response[ind++] = 0x0;
            response[ind++] = (byte)(Type >> 8);
            response[ind++] = (byte)(Type & 0xFF);
            response[ind++] = (byte)(Class >> 8);
            response[ind++] = (byte)(Class & 0xFF);
            return response;
        }

        public DNSQuestion AddName(string name)
        {
            foreach (var label in name.Split("."))
            {
                Name.Add(Encoding.ASCII.GetBytes(label));
            }
            return this;
        }
    }

    internal struct DNSHeader
    {
        // (ID)
        // A random ID to identify packets,
        // response must reply with same ID as request
        public ushort ID;

        // (QR)
        // False for queries, true for responses
        public bool QueryResponse;

        // (OPCODE)
        // The kind of query in this message, usually 0 (4 bits)
        public byte OperationCode;

        // (AA)
        // True if the responding server owns the requested domain
        public bool AuthoritativeAnswer;

        // (TC)
        // True if message exceeds 512 bytes
        public bool TruncatedMessage;

        // (RD)
        // Set in request, specifies if client wants
        // the request to be resolved recursively
        public bool RecursionDesired;

        // (RA)
        // Set in response, specifies if server
        // can resolve recursively
        public bool RecursionAvailable;

        // (Z)
        // Used for DNSSEC queries. (3 bits)
        public byte Reserved;

        // (RCODE)
        // Set in response, specifies if request
        // was successful or not, and gives reason (4 bits)
        public byte ResponseCode;

        // (QDCOUNT)
        // Number of entries in question section
        public ushort QuestionCount;

        // (ANCOUNT)
        // Number of entries in answer section
        public ushort AnswerCount;

        // (NSCOUNT)
        // Number of entries in authority section
        public ushort AuthorityCount;

        // (ARCOUNT)
        // Number of entries in additional section
        public ushort AdditionalCount;

        public byte[] GetResponse()
        {
            var response = new byte[12];
            var ind = 0;
            response[ind++] = (byte)(ID >> 8);
            response[ind++] = (byte)(ID & 0xFF);
            response[ind++] = (byte)(
                ((QueryResponse ? 1 : 0) << 7) |
                ((OperationCode & 0xF) << 3) |
                (AuthoritativeAnswer ? 1 : 0) << 2 |
                (TruncatedMessage ? 1 : 0) << 1 |
                (RecursionDesired ? 1 : 0)
                );
            response[ind++] = (byte)(
                (RecursionAvailable ? 1 : 0) << 7 |
                (Reserved & 0x7) << 4 |
                (ResponseCode & 0xF));
            response[ind++] = (byte)(QuestionCount >> 8);
            response[ind++] = (byte)(QuestionCount & 0xFF);
            response[ind++] = (byte)(AnswerCount >> 8);
            response[ind++] = (byte)(AnswerCount & 0xFF);
            response[ind++] = (byte)(AuthorityCount >> 8);
            response[ind++] = (byte)(AuthorityCount & 0xFF);
            response[ind++] = (byte)(AdditionalCount >> 8);
            response[ind++] = (byte)(AdditionalCount & 0xFF);
            return response;
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendFormat("ID: {0}\n", ID)
                .AppendFormat("QueryResponse: {0}\n", QueryResponse)
                .AppendFormat("OperationCode: {0}\n", OperationCode)
                .AppendFormat("AuthoritativeAnswer: {0}\n", AuthoritativeAnswer)
                .AppendFormat("TruncatedMessage: {0}\n", TruncatedMessage)
                .AppendFormat("RecursionDesired: {0}\n", RecursionDesired)
                .AppendFormat("RecursionAvailable: {0}\n", RecursionAvailable)
                .AppendFormat("Reserved: {0}\n", Reserved)
                .AppendFormat("ResponseCode: {0}\n", ResponseCode)
                .AppendFormat("QuestionCount: {0}\n", QuestionCount)
                .AppendFormat("AnswerCount: {0}\n", AnswerCount)
                .AppendFormat("AuthorityCount: {0}\n", AuthorityCount)
                .AppendFormat("AdditionalCount: {0}\n", AdditionalCount);

            return builder.ToString();
        }
    }

    internal struct DNSMessage
    {
        public DNSHeader Header;
        public DNSQuestionSection QuestionSection;
        public DNSAnswerSection AnswerSection;

        public DNSMessage()
        {
            QuestionSection = new DNSQuestionSection();
            Header = new DNSHeader();
            AnswerSection = new DNSAnswerSection();
        }

        public byte[] GetResponse()
        {
            // update QDCOUNT before
            Header.QuestionCount = (ushort) QuestionSection.Questions.Count;
            Header.AnswerCount = (ushort) AnswerSection.Answers.Count;
            byte[] headerResponse = Header.GetResponse();
            byte[] questionResponse = QuestionSection.GetResponse();
            byte[] answerResponse = AnswerSection.GetResponse();
            return headerResponse.Concat(questionResponse).Concat(answerResponse).ToArray();
        }

        public override string ToString()
        {
            return Header.ToString();
        }
    }
}
