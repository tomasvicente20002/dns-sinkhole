﻿#include "dns.h"
#include "mylib.h"

extern const char *__progname;

const int EMPTY_IMAGE_SIZE = 49;

unsigned char emptyImage[] = {
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x91, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9,
	0x04, 0x01, 0x00, 0x00, 0x02, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x54, 0x01, 0x00, 0x3b};
unsigned char dn_response[] = {
	0x00, 0x15, 0x5d, 0x2d, 0x10, 0x57, 0x00, 0x15, 0x5d, 0x79, 0xc8, 0x79, 0x08, 0x00, 0x45, 0x8e,
	0x00, 0x52, 0x31, 0x38, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0xac, 0x1b, 0x00, 0x01, 0xac, 0x1b,
	0x00, 0xf6, 0x00, 0x35, 0xe7, 0x06, 0x00, 0x3e, 0x59, 0x7d, 0xc1, 0x41, 0x81, 0x20, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
	0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
	0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x8e, 0xfa, 0xc8, 0x8e};

int get_udp_socket(struct sockaddr_in server_addr)
{
	int tcp_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (tcp_sock < 0)
	{
		printf("Error: Create socket  -> %s\n", strerror(errno));
		exit(-1);
	}
	int bind_err = bind(tcp_sock, (struct sockaddr *)&server_addr,
						sizeof(server_addr));
	if (bind_err < 0)
	{
		printf("Error: Bind -> %s\n", strerror(errno));
		exit(-1);
	}

	close(0);
	return tcp_sock;
}

void dns_response_udp(int sockfd)
{
	char buf[PACKET_SIZE + 4];
	u_int16_t req_size;
	dns_packet *pkt;
	struct sockaddr_in from;

	socklen_t from_len = 0;
	req_size = (u_int16_t)recvfrom(sockfd, buf, PACKET_SIZE + 4, 0, (struct sockaddr *)&from, &from_len);
	printf("client: %s %d\n", strerror(errno), req_size);

	pkt = calloc(1, sizeof(dns_packet));
	dns_req_parse(pkt, buf, req_size);

	free(pkt->data);
	free(pkt);
	sendto(sockfd, (const char *)dn_response, 96, 0, (const struct sockaddr *)&from, from_len);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_addr;

	server_addr.sin_port = htons(DNS_PORT);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(DNS_IP);

	int udp_sock = get_udp_socket(server_addr);
	printf("DNS Server online\n");

	while (TRUE)
	{
		dns_response_udp(udp_sock);
	}

	return 0;
}