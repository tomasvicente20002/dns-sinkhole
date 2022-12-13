#include "dns.h"
void prinf_pk(const unsigned char  *buffer_request , int len_r)
{

	for (int idx = 0; idx < len_r; idx++)
	{
		if ((idx % 8) == 0)
			printf("\t");
		if ((idx % 16) == 0)
			printf("\n");

		printf("%02X", buffer_request[idx]);
	}

	printf("\n");
}
void convert_to_ip(const unsigned char* hexr)
{
	unsigned char* hex =malloc(sizeof(char)*9);
	sprintf(hex,"%02X%02X%02X%02X",hexr[0],hexr[1],hexr[2],hexr[3]);

    // Split hexadecimal number into groups of two digits
    char *group1 = malloc(sizeof(char) * 3);
    memccpy(group1, hex, 0, 2);
    char *group2 = malloc(sizeof(char) * 3);
    memccpy(group2, &hex[2], 0, 2);
    char *group3 = malloc(sizeof(char) * 3);
    memccpy(group3, &hex[4], 0, 2);
    char *group4 = malloc(sizeof(char) * 3);
    memccpy(group4, &hex[6], 0, 2);

    group1[2] = '\0';
    group2[2] = '\0';
    group3[2] = '\0';
    group4[2] = '\0';

    // Convert groups to decimal numbers
    unsigned long num1 = strtol(group1, NULL, 16);
    unsigned long num2 = strtol(group2, NULL, 16);
    unsigned long num3 = strtol(group3, NULL, 16);
    unsigned long num4 = strtol(group4, NULL, 16);

	free(group1);
	free(group2);
	free(group3);
	free(group4);
	free(hex);

	printf("IPV4 adress -> %ld.%ld.%ld.%ld \n", num1,num2,num3,num4);
}
BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size)
{

	pkt->row_packet_data = malloc(size);
	memccpy(pkt->row_packet_data, data, 0, size);
	// Parse the first 12 bytes that corresponds to the header
	dns_header_parse(&pkt->header, data);

	// Rest o fhte quest less the header
	pkt->data = malloc(size - DNS_HEADER_SIZE);
	memcpy(pkt->data, data + DNS_HEADER_SIZE, size - DNS_HEADER_SIZE);
	pkt->data_size = size - DNS_HEADER_SIZE;
	dns_question_parse(pkt);
	return TRUE;
}
void print_dns_header_parse(const dns_header *header)
{
	printf("-----------HEADER-----------\n");
	printf("id :%d\n", header->id);
	printf("qdcount :%d\n", header->qdcount);
	printf("ancount :%d\n", header->ancount);
	printf("nscount :%d\n", header->nscount);
	printf("arcount :%d\n", header->arcount);
}

BOOL dns_header_parse(dns_header *header, const void *data)
{
	memcpy(header, data, DNS_HEADER_SIZE);

	header->id = ntohs(header->id);
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
	header->flags = htons(0x0100); // This is a query
	header->qdcount = htons(1);	   // we have only 1 question
	header->ancount = htons(0);
	header->nscount = htons(0);
	header->arcount = htons(0);

	qname = &buffer_request[sizeof(dns_header)];

	strcpy(qname, pkt->question.qname);

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

	convert_to_ip(&buffer_answer[req_size-4]);

	free(req_pkt);
	close(sockfd);

	return 0;
}