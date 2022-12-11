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


    u_int16_t rd : 1;     // recursion desired
    u_int16_t tc : 1;     // truncated message
    u_int16_t aa : 1;     // authoritive answer
    u_int16_t opcode : 4; // purpose of message
    u_int16_t qr : 1;     // query/response flag

    u_int16_t rcode : 4; // response code
    u_int16_t cd : 1;    // checking disabled
    u_int16_t ad : 1;    // authenticated data
    u_int16_t z : 1;     // its z! reserved
    u_int16_t ra : 1;    // recursion available



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

#pragma pack(push, 1)
typedef struct dns_answer_details_st
{
    u_int16_t type;
    u_int16_t _class;
    unsigned int ttl;
    u_int16_t data_len;
} dns_answer_details;
#pragma pack(pop)

typedef struct dns_answer_st
{
    unsigned char *name;
    dns_answer_details *resource;
    unsigned char *rdata;
} dns_answer;



BOOL dns_question_parse(dns_packet *pkt);
BOOL dns_header_parse(dns_header *header, const void *data);
BOOL dns_req_parse(dns_packet *pkt, const void *data, u_int16_t size);
BOOL dns_forward(const dns_packet *pkt);