#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

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
} context;

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

    ctx->srv_socket = socket(
        info->ai_family,
        info->ai_socktype,
        info->ai_protocol);

    if ((bind(ctx->srv_socket, info->ai_addr, info->ai_addrlen)) < 0)
    {
        perror("bind udp socket");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(info);
}