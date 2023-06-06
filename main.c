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

typedef enum
{
    OFFERED,
    COMMITED
} client_state;

typedef struct
{
    uint32_t transaction_id;
    uint8_t ethernet_address[ETHERNET_LEN];
    bool address_offered;
    struct in_addr offered_address;
    client_state state;
} client;

typedef struct
{
    int srv_socket;
    bool debug;

    // CLI supplied options.
    struct in_addr start_address;
    struct in_addr end_address;
    struct in_addr mask;
    struct in_addr *gateway;
    struct in_addr *dns_server;

    client **clients;
} context;

void parse_args(int argc, char **argv, context *ctx);
void print_usage_and_exit(FILE *f);
void free_context(context *ctx);
void create_srv_socket(context *ctx);
void run_server(context *ctx);
ssize_t read_msg_or_die(context *ctx, uint8_t *buf, const int BUF_SIZE);

int main(int argc, char **argv)
{
    context ctx;
    parse_args(argc, argv, &ctx);
    create_srv_socket(&ctx);
    run_server(&ctx);

    return 0;
}

void parse_args(int argc, char **argv, context *ctx)
{
    int opt;

    char *address;
    bool has_network = false, has_mask = false;
    struct in_addr *addr;

    ctx->debug = false;
    ctx->gateway = NULL;
    ctx->dns_server = NULL;
    ctx->clients = NULL;

    while ((opt = getopt(argc, argv, "n:m:g:d:hv")) != -1)
    {
        switch (opt)
        {
        case 'n':
            // Mandatory
            // Network option, expected format is start_address:end_address
            for (int i = 0; i < 2; i++)
            {
                address = strtok((i == 0) ? optarg : NULL, ":");
                if (address == NULL)
                    print_usage_and_exit(stderr);

                addr = (i == 0) ? &(ctx->start_address) : &(ctx->end_address);
                if (inet_aton(address, addr) < 1)
                    print_usage_and_exit(stderr);
            }
            has_network = true;
            break;
        case 'm':
            // Mandatory
            // Mask option, expected format is an ipv4 address in dotted
            // decimal
            if (inet_aton(optarg, &(ctx->mask)) < 1)
                print_usage_and_exit(stderr);
            has_mask = true;
            break;
        case 'g':
            // Optional ipv4 gateway in dotted decimal form.
            if ((ctx->gateway = malloc(sizeof(struct in_addr))) == NULL)
            {
                fprintf(stderr, "failed to allocate gateway storage\n");
                exit(EXIT_FAILURE);
            }
            if ((inet_aton(optarg, ctx->gateway)) < 1)
                print_usage_and_exit(stderr);
            break;
        case 'd':
            // Optional single ipv4 DNS server in dotted decimal form.
            if ((ctx->dns_server = malloc(sizeof(struct in_addr))) == NULL)
            {
                fprintf(stderr, "failed to allocate dns server storage\n");
                exit(EXIT_FAILURE);
            }
            if ((inet_aton(optarg, ctx->dns_server)) < 1)
                print_usage_and_exit(stderr);
            break;
        case 'v':
            ctx->debug = true;
            break;
        case 'h':
        default:
            print_usage_and_exit(stderr);
            break;
        }
    }

    if (!has_network || !has_mask)
        print_usage_and_exit(stderr);
}

void print_usage_and_exit(FILE *f)
{
    fprintf(f, "Usage: abdhcp -n <start address>:<end address>");
    fprintf(f, " -m <subnet mask> [-g <gateway] [-d <dns server>]\n");
    exit(EXIT_FAILURE);
}

void free_context(context *ctx)
{
    if (ctx->gateway != NULL)
        free(ctx->gateway);
    if (ctx->dns_server != NULL)
        free(ctx->dns_server);
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

void run_server(context *ctx)
{
    const int BUF_SIZE = 2048;
    uint8_t buf[BUF_SIZE];
    ssize_t num_read;
    dhcp_pkt *pkt;

    while (1)
    {
        num_read = read_msg_or_die(ctx, buf, BUF_SIZE);
        if ((pkt = deserialize_dhcp_pkt(buf, num_read)) == NULL)
        {
            fprintf(stderr, "failed to deserialize packet\n");
            continue;
        }
        if (!is_ethernet_dhcp_pkt(pkt))
        {
            fprintf(
                stderr,
                "got DHCP packet that was not ethernet (HTYPE=%u)\n",
                pkt->h_type);
            free_dhcp_pkt(pkt);
            continue;
        }

        switch (get_dhcp_message_type(pkt))
        {
            case PKT_TYPE_DISCOVER:
                break;
            default:
                break;
        }

        print_dhcp_pkt(pkt);
        free_dhcp_pkt(pkt);
    }
}

ssize_t read_msg_or_die(context *ctx, uint8_t *buf, const int BUF_SIZE)
{
    ssize_t num_read;
    if ((num_read = recvfrom(
             ctx->srv_socket,
             buf,
             BUF_SIZE,
             0,
             NULL,
             NULL)) < 0)
    {
        perror("reading server socket");
        exit(EXIT_FAILURE);
    }

    return num_read;
}