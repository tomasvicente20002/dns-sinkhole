#include "dns.h"

int get_name_len(const unsigned char *reader, char *name)
{
	int idx;
	for (idx = 0; reader[idx] != 0; idx++)	{}
	//memccpy(name,reader,0,idx);
	return idx;
}

BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size)
{
	int len;
	pkt->row_packet_data = malloc(size);
	memccpy(pkt->row_packet_data, data, 0, size);
	// Parse the first 12 bytes that corresponds to the header
	dns_header_parse(&pkt->header, data);

	// Rest o fhte quest less the header
	pkt->data = malloc(size - DNS_HEADER_SIZE);
	memcpy(pkt->data, data + DNS_HEADER_SIZE, size - DNS_HEADER_SIZE);
	pkt->data_size = size - DNS_HEADER_SIZE;
	dns_question_parse(pkt);	

	//If is a request whe parse the response
	if(pkt->header.ancount > 0)
	{
		dns_answer answers[5];
		unsigned char *reader;
		reader = &data[sizeof(dns_header) + (12 + 1) + sizeof(dns_question_request)];

		for (int i = 0; i < pkt->header.ancount; i++)
		{
			len = get_name_len(reader, answers[i].name);
			reader = reader + len;

			answers[i].resource = (dns_answer_details *)(reader);
			reader = reader + sizeof(dns_answer_details);

			if (ntohs(answers[i].resource->type) == 1) // if its an ipv4 address
			{
				answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

				for (int j = 0; j < ntohs(answers[i].resource->data_len); j++)
				{
					answers[i].rdata[j] = reader[j];
				}

				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

				reader = reader + ntohs(answers[i].resource->data_len);
			}
			else
			{

				len = get_name_len(reader, answers[i].rdata);
				reader = reader + len;
			}
		}


		// print answers
		struct sockaddr_in a;
		printf("\nAnswer Records : %d \n", ntohs(pkt->header.ancount));
		for (int i = 0; i < pkt->header.ancount; i++)
		{
			//printf("Name : %s ", answers[i].name);

			if (ntohs(answers[i].resource->type) == 1) // IPv4 address
			{
				long *p;
				p = (long *)answers[i].rdata;
				a.sin_addr.s_addr = (*p); // working without ntohl
				printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
			}

			if (ntohs(answers[i].resource->type) == 5)
			{
				// Canonical name for an alias
				printf("has alias name : %s", answers[i].rdata);
			}

			printf("\n");
		}
	}


	return TRUE;
}
void print_dns_header_parse(const dns_header *header)
{
	printf("-----------HEADER-----------\n");
	printf("id :%d\n", header->id);
	printf("qr :%d\n", header->qr);
	printf("opcode :%d\n", header->opcode);
	printf("aa :%d\n", header->aa);
	printf("tc :%d\n", header->tc);
	printf("rd :%d\n", header->rd);
	printf("ra :%d\n", header->ra);
	printf("z :%d\n", header->z);
	printf("rcode :%d\n", header->rcode);
	printf("qdcount :%d\n", header->qdcount);
	printf("ancount :%d\n", header->ancount);
	printf("nscount :%d\n", header->nscount);
	printf("arcount :%d\n", header->arcount);
}

BOOL dns_header_parse(dns_header *header, const void *data)
{
	memcpy(header, data, DNS_HEADER_SIZE);

	header->id = ntohs(header->id);
	header->qr = ntohs(header->qr);
	header->opcode = ntohs(header->opcode);
	header->aa = ntohs(header->aa);
	header->tc = ntohs(header->tc);
	header->rd = ntohs(header->rd);
	header->ra = ntohs(header->ra);
	header->z = ntohs(header->z);
	header->rcode = ntohs(header->rcode);
	header->qdcount = ntohs(header->qdcount);
	header->ancount = ntohs(header->ancount);
	header->nscount = ntohs(header->nscount);
	header->arcount = ntohs(header->arcount);
	print_dns_header_parse(header);
	return TRUE;
}
void print_dns_question_parse(const dns_question question)
{
	printf("-----------QUESTION-----------\n");
	printf("qname :%s\n", question.qname);
	printf("qtype :%d\n", question.qtype);
	printf("qclass :%d\n", question.qclass);
}
BOOL dns_question_parse(dns_packet *pkt)
{
	int i = 0;
	while (pkt->data[i])
	{
		int len = pkt->data[i];
		i += len + 1;
	}

	char *qname = malloc(sizeof(char) * (i + 1));
	memcpy(qname, pkt->data, i);
	qname[i] = '\0';

	pkt->question.qname = qname;
	pkt->question.qtype = (unsigned short)pkt->data[i + 1];
	pkt->question.qclass = (unsigned short)pkt->data[i + 3];

	print_dns_question_parse(pkt->question);

	return TRUE;
}

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
    int lock = 0;
    strcat((char *)host, ".");

    for (int i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++; // or lock=i+1;
        }
    }
    *dns++ = '\0';
}

BOOL dns_forward(const dns_packet *pkt)
{
	int sockfd;
	unsigned char buffer_answer[65536];
	unsigned char buffer_request[DNS_PACKET_SIZE + 4];
	unsigned char *qname;

	struct sockaddr_in servaddr;
	u_int16_t req_size;
	socklen_t len;

	// Creating socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));

	// Filling external dns server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_PORT);
	servaddr.sin_addr.s_addr = inet_addr(DNS_EXTERNAL_IP);

	dns_header *header;
	header = (dns_header *)&buffer_request;
	header->id = htons(getpid());
	header->qr = htons(0);		// This is a query
	header->opcode = htons(0); // This is a standard query
	header->aa = htons(0);		// Not Authoritative
	header->tc = htons(0);		// This message is not truncated
	header->rd = htons(1);	// Recursion Desired
	header->ra = htons(0);		// Recursion not available! hey we dont have it (lol)
	header->z = htons(0);
	header->rcode = htons(0);
	header->qdcount = htons(1); // we have only 1 question
	header->ancount = htons(0);
	header->nscount = htons(0);
	header->arcount = htons(0);

	qname = &buffer_request[sizeof(dns_header)];

	unsigned char hostname[13] = "facebook.com";
	ChangetoDnsNameFormat(qname, hostname);
	//strcpy(qname,pkt->question.qname);

	dns_question_request *question;
	question = (dns_question_request *)&buffer_request[sizeof(dns_header) + (strlen((const char *)qname) + 1)];
	question->qtype = htons(1);
	question->qclass = htons(1);

	printf("-----------------------dns_forward--------------------------\n");
	u_int16_t t = (u_int16_t)sendto(
		sockfd,
		(char *)buffer_request,
		(strlen((const char *)qname) + 1) + sizeof(dns_header) + sizeof(dns_question_request),
		0,
		(struct sockaddr *)&servaddr,
		sizeof(servaddr));

	printf("client: %s %d\n", strerror(errno), t);

	req_size = (u_int16_t)recvfrom(
		sockfd,
		(char *)buffer_answer,
		65536,
		0,
		(struct sockaddr *)&servaddr,
		&len);

	dns_packet *req_pkt = calloc(1, sizeof(dns_packet));

	dns_req_parse(req_pkt, buffer_answer, req_size);

	free(req_pkt);
	close(sockfd);

	return 0;
}