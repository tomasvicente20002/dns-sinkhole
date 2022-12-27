#include "dns.h"
#include "mylib.h"
#include "list.h"

extern const char *__progname;

Node *black_list_domains = NULL;
Node *chache_list_domains = NULL;

typedef struct list_adress_st
{
	const char *ip;
	const char *name;
} list_adress;

int get_udp_socket(struct sockaddr_in server_addr)
{
	int tcp_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (tcp_sock < 0)
	{
		log_message(ERROR, "Create socket -> %s", strerror(errno));
		exit(-1);
	}
	log_message(INFO, "Create socket -> %s", strerror(errno));
	int bind_err = bind(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (bind_err < 0)
	{
		log_message(ERROR, "Bind -> %s", strerror(errno));
		exit(-1);
	}
	log_message(INFO, "Bind -> %s", strerror(errno));
	close(0);
	return tcp_sock;
}

BOOL compare_domain_func(const void *p_list_value, const void *p_value)
{
	return strcmp(p_list_value, p_value) == 0;
}

BOOL is_black_listed(const char *name)
{
	return search_from_list(black_list_domains, name, compare_domain_func) != NULL;
}

BOOL compare_domain_cache_func(const void *p_list_value, const void *p_value)
{
	list_adress *list_value = (list_adress *)p_list_value;

	if (strcmp(list_value->name, p_value) == 0)
		return TRUE;
}

list_adress *dns_chache(char *name)
{
	return search_from_list(chache_list_domains, name, compare_domain_cache_func);
}

void dns_response_udp(int sockfd)
{
	char buf[DNS_PACKET_SIZE + 4];
	u_int16_t req_size;
	dns_packet *pkt;
	struct sockaddr_in client;

	socklen_t client_len = 0;
	req_size = (u_int16_t)recvfrom(sockfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr *)&client, &client_len);
	log_message(INFO, "Revice request -> Status:%s  Len:%d", strerror(errno), req_size);
	pkt = calloc(1, sizeof(dns_packet));

	dns_req_parse(pkt, buf, req_size);

	if (is_black_listed(pkt->question.qname))
	{
		log_message(WARNING, "Domain %s is blacklisted", pkt->question.qname);
	}
	else
	{
		const char *ip;
		list_adress *dns = dns_chache(pkt->question.qname);
		if (dns != NULL)
		{
			ip = dns->ip;
		}
		else
		{
			ip = dns_get_ip(pkt);
			dns = malloc(sizeof(list_adress));
			dns->ip = malloc(sizeof(char) * strlen(ip));
			dns->name = malloc(sizeof(char) * strlen(pkt->question.qname));
			strcpy(dns->ip, ip);
			strcpy(dns->name, pkt->question.qname);
			add_to_list(&chache_list_domains, dns);
		}

		char *buf_response = malloc(DNS_PACKET_SIZE + 4);

		dns_header *dns_response_header = &buf_response[0];
		dns_response_header->ancount = htons(1);
		dns_response_header->arcount = pkt->header.arcount;
		dns_response_header->id = pkt->header.id;
		dns_response_header->nscount = pkt->header.nscount;
		dns_response_header->qdcount = pkt->header.qdcount;
		dns_response_header->flags = htons(0x8400);

		dns_question *question = &buf_response[sizeof(dns_header)];
		question->qclass = pkt->question.qclass;
		question->qname = pkt->question.qname;
		question->qtype = pkt->question.qtype;

		dns_answer *answer = &buf_response[sizeof(dns_header) + sizeof(dns_question)];
		answer->data_len = strlen(pkt->question.qname);
		answer->name = pkt->question.qname;
		answer->ttl = htonl(3600); // 1 hour
		answer->type = htons(1); // A record
		answer->_class = htons(1);

		struct in_addr addr;
		inet_aton(dns->ip, &addr);  // example IP address
  		memcpy(answer->rdata, &addr, 4);

 		sendto(sockfd, &buf_response, sizeof(DNS_PACKET_SIZE + 4), 0, (struct sockaddr *)&client, client_len);

		printf("%s\n", dns->ip);
	}

	free(pkt->data);
	free(pkt);
}

BOOL read_black_list()
{
	// Open the file for reading
	FILE *file = fopen("black_list.txt", "r");

	// Check if the file was opened successfully
	if (file == NULL)
	{
		log_message(ERROR, "Error opening file %s", strerror(errno));
		return FALSE;
	}

	// Declare a buffer to hold the data read from the file
	char buffer[500];
	/// 000.000.000.000

	// Read the file line by line
	while (fgets(buffer, 500, file) != NULL)
	{
		// Print the line read from the file
		char *value = malloc(strlen(buffer) * sizeof(char));
		strcpy(buffer, value);
		add_to_list(&black_list_domains, value);
	}

	// Close the file
	fclose(file);

	return TRUE;
}

int main(int argc, char *argv[])
{
	read_black_list();
	struct sockaddr_in server_addr;

	server_addr.sin_port = htons(DNS_PORT);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(DNS_LOCAl_IP);

	int udp_sock = get_udp_socket(server_addr);

	log_message(INFO, "Server online");

	while (TRUE)
	{
		dns_response_udp(udp_sock);
	}

	return 0;
}
