#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#define DNS_PACKET_SIZE 512
#define DNS_HEADER_SIZE 12
#define DNS_PORT 53
#define DNS_LOCAl_IP "0.0.0.0"
#define DNS_EXTERNAL_IP "8.8.8.8"
#include "mylib.h"
#define VERBOSE_DNS 0


/*
https://www.netmeister.org/blog/dns-size.html
*/

/*
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					  ID
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					QDCOUNT
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					ANCOUNT
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					NSCOUNT
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					ARCOUNT
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|

Total 96 bits = 12 Bytes
*/
typedef struct dns_header_st
{
	u_int16_t id; /* a 16 bit identifier assigned by the client */
	u_int16_t flags;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
} __attribute__((packed)) dns_header;

/*
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                  				|
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					 QTYPE
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
					 QCLASS
|+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct dns_question_st
{
	char *qname;
	u_int16_t qtype;
	u_int16_t qclass;
} dns_question;

typedef struct dns_question_st_req
{
	u_int16_t qtype;
	u_int16_t qclass;
} dns_question_request;

typedef struct dns_packet_st
{
	dns_header header;
	dns_question question;
	char *data;
	u_int16_t data_size;
	char *row_packet_data;
} dns_packet;

typedef struct dns_answer_st
{
    unsigned char *name;
    u_int16_t type;
    u_int16_t _class;
    unsigned int ttl;
    u_int16_t data_len;
    unsigned char *rdata;
} dns_answer;





BOOL dns_question_parse(dns_packet *pkt);
BOOL dns_header_parse(dns_header *header, const void *data);
BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size);
char * dns_get_ip(const dns_packet *pkt);