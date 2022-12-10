#include "dns.h"

BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size)
{

	// Parse the first 12 bytes that corresponds to the header
	dns_header_parse(&pkt->header, data);

	//Rest o fhte quest less the header
	pkt->data = malloc(size - DNS_HEADER_SIZE);
	memcpy(pkt->data, data + DNS_HEADER_SIZE, size - DNS_HEADER_SIZE);
	pkt->data_size = size - DNS_HEADER_SIZE;
	dns_question_parse(pkt);
	return TRUE;
}
void print_dns_header_parse(const dns_header *header)
{
	printf("-----------HEADER-----------\n");
	printf("id :%d\n",header->id);
	printf("qr :%d\n",header->qr);
	printf("opcode :%d\n",header->opcode);
	printf("aa :%d\n",header->aa);
	printf("tc :%d\n",header->tc);
	printf("rd :%d\n",header->rd);
	printf("ra :%d\n",header->ra);
	printf("z :%d\n",header->z);
	printf("rcode :%d\n",header->rcode);
	printf("qdcount :%d\n",header->qdcount);
	printf("ancount :%d\n",header->ancount);
	printf("nscount :%d\n",header->nscount);
	printf("arcount :%d\n",header->arcount);
}

BOOL dns_header_parse(dns_header *header, const void *data)
{
	memcpy(header, data, DNS_HEADER_SIZE);

	header->id = ntohs(header->id);
	header->qr = ntohs(header->qr);
	header->opcode  = ntohs(header->opcode);
	header->aa = ntohs(header->aa);
	header->tc = ntohs(header->tc);
	header->rd = ntohs(header->rd);
	header->ra = ntohs(header->ra);
	header->z = ntohs(header->z);
	header->rcode = ntohs(header->rcode);
	header->qdcount = ntohs(header->qdcount);
	header->ancount = ntohs(header->ancount);
	header->nscount  = ntohs(header->nscount);
	header->arcount  = ntohs(header->arcount);
	print_dns_header_parse(header);
	return TRUE;
}
void print_dns_question_parse(const dns_question question)
{
	printf("-----------QUESTION-----------\n");
	printf("qname :%s\n",question.qname);
	printf("qtype :%d\n",question.qtype);
	printf("qclass :%d\n",question.qclass);

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
