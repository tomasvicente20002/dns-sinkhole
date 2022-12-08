#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#define PACKET_SIZE 512
#define HEADER_SIZE 12
#define DNS_PORT 53
#define DNS_IP "0.0.0.0"
#include "mylib.h"



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
	u_int16_t id;
	u_int16_t qr : 1;	  // 1 bit
	u_int16_t opcode : 4; // 4 bit
	u_int16_t aa : 1;	  // 1 bit
	u_int16_t tc : 1;	  // 1 bit
	u_int16_t rd : 1;	  // 1 bit
	u_int16_t ra : 1;	  // 1 bit
	u_int16_t z : 3;	  // 3 bit
	u_int16_t rcode : 4;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
} dns_header;

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

typedef struct dns_packet_st
{
	dns_header header;
	dns_question question;
	char *data;
	u_int16_t data_size;
} dns_packet;

BOOL dns_question_parse(dns_packet *pkt);
BOOL dns_header_parse(dns_header *header, const void *data);
BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size);