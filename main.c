#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

// net includes.
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// sys includes.
#include <unistd.h>
#include <fcntl.h>

#include "ab_dhcp.h"

typedef struct
{
    int srv_socket;
    bool debug;

    // CLI supplied options.
    struct in_addr start_address;
    struct in_addr end_address;
    struct in_addr *gateway;
    struct in_addr *dns_server;
    uint32_t mask;
} context;

void parse_args(int argc, char **argv, context *ctx);
void create_srv_socket(context *ctx);

int main(int argc, char **argv)
{
    context ctx;
    ctx.debug = argc > 1 && strcmp(argv[1], "-v") == 0;
    create_srv_socket(&ctx);

    int buf_len = 2048;
    uint8_t buf[buf_len + 1];
    buf[buf_len] = '\0';

    while (1)
    {
        int nrec = recvfrom(ctx.srv_socket, buf, buf_len, 0, NULL, NULL);
        dhcp_pkt *pkt = deserialize_dhcp_pkt(buf, buf_len);
        fprintf(stderr, "NREC = %d\n", nrec);
        print_dhcp_pkt(pkt);
        free_dhcp_pkt(pkt);
    }

    return 0;
}

void parse_args(int argc, char **argv, context *ctx)
{
    int opt;
    while ((opt = getopt(argc, argv, "") != -1))
    {
        switch (opt)
        {
            case 'n':
                // Mandatory
                // Network option, expected format is start_address:end_address
                break;
            case 'm':
                // Mandatory
                // Mask option, expected format is an ipv4 address in dotted
                // decimal
                break;
            case 'g':
                // Optional ipv4 gateway in dotted decimal form.
                break;
            case 'd':
                // Optional single ipv4 DNS server in dotted decimal form.
                break;
            default: 
                break;
        }
    }
}

void create_srv_socket(context *ctx)
{
    struct addrinfo hints;
    struct addrinfo *info;
    int ret;

    // Setup UDP socket.
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((ret = getaddrinfo(NULL, "67", &hints, &info)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }

    if ((ctx->srv_socket = socket(
             info->ai_family,
             info->ai_socktype,
             info->ai_protocol)) < 0)
    {
        perror("create server UDP socket");
        exit(EXIT_FAILURE);
    }

    if ((bind(ctx->srv_socket, info->ai_addr, info->ai_addrlen)) < 0)
    {
        perror("bind udp socket");
        exit(EXIT_FAILURE);
    }

    int broadcast_on = 1;
    if ((setsockopt(
            ctx->srv_socket,
            SOL_SOCKET,
            SO_BROADCAST,
            &broadcast_on,
            sizeof broadcast_on)) < 0)
    {
        perror("set UDP server socket to broadcast");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(info);
}