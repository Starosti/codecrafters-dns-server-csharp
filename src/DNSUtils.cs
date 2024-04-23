namespace codecrafters_dns_server.src
{
    internal static class DNSUtils
    {
        public static DNSMessage ParseMessage(byte[] request)
        {
            DNSMessage message = new DNSMessage();
            message.Header = ParseHeader(request);
            message.QuestionSection = ParseQuestionSection(request);
            // find end of question section
            // skip header
            int ind = 12;
            for (int i = 0; i < message.Header.QuestionCount; i++)
            {
                // find the next question
                while (true)
                {
                    byte len = request[ind++];
                    if (len == 0) // end of question
                    {
                        ind += 4; // class and type skipped
                        break;
                    }

                    if (len >> 6 == 0b11) // compressed
                    {
                        ind += 2;
                        break;
                    }

                    // not compressed
                    ind += len;
                }
            }
            message.AnswerSection = ParseAnswerSection(request, ind);
            return message;
        }

        public static DNSHeader ParseHeader(byte[] request)
        {
            /*
                00010101 byte
                00010101 byte
                ID

                0 0010 1 0 1 byte
                QR OPCODE AA TC RD

                0 001 0101 byte
                RA Z RCODE

                00010101 byte
                00010101 byte
                QDCOUNT

                00010101 byte
                00010101 byte
                ANCOUNT

                00010101 byte
                00010101 byte
                NSCOUNT

                00010101 byte
                00010101 byte
                ARCOUNT
            */
            DNSHeader header = new()
            {
                ID = (ushort)((request[0] << 8) | request[1]),

                QueryResponse = (request[2] & 0x80) == 1,
                OperationCode = (byte)((request[2] >> 3) & 0xF),
                AuthoritativeAnswer = (request[2] & 0x4) == 1,
                TruncatedMessage = (request[2] & 0x2) == 1,
                RecursionDesired = (request[2] & 0x1) == 1,

                RecursionAvailable = (request[3] & 0x80) == 1,
                Reserved = (byte)((request[3] >> 4) & 0x7),
                ResponseCode = (byte)(request[3] & 0xF),

                QuestionCount = (ushort)((request[4] << 8) | request[5]),
                AnswerCount = (ushort)((request[6] << 8) | request[7]),
                AuthorityCount = (ushort)((request[8] << 8) | request[9]),
                AdditionalCount = (ushort)((request[10] << 8) | request[11])
            };
            return header;
        }

        public static DNSQuestionSection ParseQuestionSection(byte[] request)
        {
            DNSHeader header = ParseHeader(request);
            DNSQuestionSection questionSection = new();
            // skip header
            var ind = 12;
            for (int i = 0; i < header.QuestionCount; i++)
            {
                DNSQuestion question = ParseQuestion(request, ind);
                questionSection.Questions.Add(question);
                // find the next question
                while (true)
                {
                    byte len = request[ind++];
                    if (len == 0 | len >> 6 == 0b11) // end of question or compressed
                    {
                        if (len >> 6 == 0b11) ind += 1; // compressed
                        ind += 4; // type and class skipped
                        break;
                    }

                    // not compressed
                    ind += len;
                }
            }
            return questionSection;
        }

        public static DNSAnswerSection ParseAnswerSection(byte[] request, int startingIndex)
        {
            DNSHeader header = ParseHeader(request);
            DNSAnswerSection answerSection = new();
            var ind = startingIndex;
            for (int i = 0; i < header.AnswerCount; i++)
            {
                DNSRecord answer = ParseAnswer(request, ind);
                answerSection.Answers.Add(answer);
                // find the next answer
                while (true)
                {
                    byte len = request[ind++];
                    if (len == 0 | len >> 6 == 0b11) // end of answer or compressed
                    {
                        if (len >> 6 == 0b11) ind += 1; // compressed
                        ind += 8; // type, class, TTL skipped
                        ushort dataLen = (ushort)((request[ind++] << 8) | request[ind++]);
                        ind += dataLen;
                        break;
                    }

                    // not compressed
                    ind += len;
                }
            }
            return answerSection;
        }

        public static DNSRecord ParseAnswer(byte[] request, int startingIndex, List<byte[]> name)
        {
            DNSRecord answer = new();
            int ind = startingIndex;

            while (true)
            {
                byte len = request[ind++];

                if (len == 0) break;

                if (len >> 6 == 0b11) // compressed
                {
                    ushort offset = (ushort)(((len & 0b00111111) << 8) | request[ind++]);
                    ParseAnswer(request, offset, name);
                    break;
                }

                var label = new byte[len];
                for (int j = 0; j < len; j++)
                {
                    label[j] = request[ind++];
                }
                name.Add(label);
            }
            answer.Name = name;

            answer.Type = (ushort)(request[ind++] << 8 | request[ind++]);
            answer.Class = (ushort)(request[ind++] << 8 | request[ind++]);
            answer.TTL = (request[ind++] << 24) | (request[ind++] << 16) | (request[ind++] << 8) | request[ind++];
            answer.Length = (ushort)(request[ind++] << 8 | request[ind++]);
            answer.Data = request.Skip(ind).Take(answer.Length).ToArray();

            return answer;
        }

        public static DNSRecord ParseAnswer(byte[] request, int startingIndex)
        {
            return ParseAnswer(request, startingIndex, new List<byte[]>());
        }

        public static DNSQuestion ParseQuestion(byte[] request, int startingIndex, List<byte[]> name)
        {
            DNSQuestion question = new();

            int ind = startingIndex;

            while (true)
            {
                byte len = request[ind++];

                if (len == 0) break;

                if (len >> 6 == 0b11) // compressed
                {
                    ushort offset = (ushort)(((len & 0b00111111) << 8) | request[ind++]);
                    ParseQuestion(request, offset, name);
                    break;
                }

                var label = new byte[len];
                for (int j = 0; j < len; j++)
                {
                    label[j] = request[ind++];
                }
                name.Add(label);
            }
            // reaching here means that this isn't compressed
            question.Name = name;

            question.Type = (ushort)(request[ind++] << 8 | request[ind++]);
            question.Class = (ushort)(request[ind++] << 8 | request[ind++]);

            return question;
        }

        public static DNSQuestion ParseQuestion(byte[] request, int startingIndex)
        {
            return ParseQuestion(request, startingIndex, new List<byte[]>());
        }
    }
}
