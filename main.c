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
#include "dhcp_manager.h"
#include "core.h"

void parse_args(int argc, char **argv, context *ctx);
bool validate_network(context *ctx);
void print_usage_and_exit(FILE *f);
void free_context(context *ctx);
void create_srv_socket(context *ctx);
void run_server(context *ctx);
ssize_t read_msg_or_die(context *ctx, uint8_t *buf, const int BUF_SIZE);
void handle_discover(context *ctx, dhcp_pkt *pkt);

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
    bool has_network = false, has_mask = false, has_server_addr = false;
    struct in_addr *addr;

    ctx->debug = false;
    ctx->gateway = NULL;
    ctx->dns_server = NULL;
    ctx->clients = NULL;
    ctx->num_clients = 0;

    while ((opt = getopt(argc, argv, "s:n:m:g:d:hv")) != -1)
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
        case 's':
            // Mandatory
            // IP address of server.
            if (inet_aton(optarg, &(ctx->srv_address)) < 1)
                print_usage_and_exit(stderr);
            has_server_addr = true;
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

    if (!has_server_addr || !has_network || !has_mask || !validate_network(ctx))
        print_usage_and_exit(stderr);
}

bool validate_network(context *ctx)
{
    uint32_t raw_start = ntohl(ctx->start_address.s_addr);
    uint32_t raw_end = ntohl(ctx->end_address.s_addr);
    uint32_t raw_mask = ntohl(ctx->mask.s_addr);

    uint32_t net_address = raw_start & raw_mask;
    uint32_t broadcast_address = net_address | ~raw_mask;

    // Check that the addresses we are using are sequentual and not network or
    // broadcast addresses.
    return raw_start < raw_end &&
           raw_start > net_address &&
           raw_start < broadcast_address &&
           raw_end < broadcast_address;
}

void print_usage_and_exit(FILE *f)
{
    fprintf(f, "Usage: abdhcp -n <start address>:<end address>");
    fprintf(f, " -s <server address> -m <subnet mask> [-g <gateway]");
    fprintf(f, " [-d <dns server>]\n");
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

    ret = getaddrinfo(NULL, "67", &hints, &info);
    if (ret != 0)
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

    if (ctx->debug)
        fprintf(stderr, "Listening on 0.0.0.0:67\n");

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

        if (ctx->debug)
            print_dhcp_pkt(pkt);

        switch (get_dhcp_message_type(pkt))
        {
        case PKT_TYPE_DISCOVER:
            handle_discover(ctx, pkt);
            break;
        case PKT_TYPE_OFFER:
            break;
        case PKT_TYPE_REQUEST:
            break;
        case PKT_TYPE_DECLINE:
            break;
        case PKT_TYPE_ACK:
            break;
        case PKT_TYPE_NAK:
            break;
        case PKT_TYPE_RELEASE:
            break;
        case PKT_TYPE_INFORM:
            break;
        default:
            fprintf(stderr, "Got invalid DHCP message type\n");
            break;
        }

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

void handle_discover(context *ctx, dhcp_pkt *pkt)
{
    struct in_addr addr;
    client *client;
    int ret;
    uint8_t *buf;
    uint16_t buf_len;
    const int NUM_PARAMS = 3;
    uint8_t param_len;
    uint8_t params[NUM_PARAMS];
    struct sockaddr_in broadcast;

    if (ctx->debug)
        printf("got dhcp discover pkt\n");

    if ((ret = find_usable_client_addr(ctx, &addr)) < 0)
    {
        fprintf(stderr, "failed to find usable address for discover\n");
        return;
    }

    if ((client = malloc(sizeof(client))) == NULL)
    {
        fprintf(stderr, "failed to allocate client memory\n");
        return;
    }

    client->state = OFFERED;
    client->offered_address.s_addr = addr.s_addr;
    memcpy(client->ethernet_address, pkt->ch_addr, ETHERNET_LEN);
    client->identifier = NULL;
    if ((find_dhcp_option(
            pkt, OPT_IDENTIFIER, &buf, &buf_len, true)) != OPT_SEARCH_ERROR)
    {
        client->identifier = buf;
        client->id_len = buf_len;
    }

    if (insert_client(ctx, client) < 0)
    {
        fprintf(stderr, "failed to insert client into client table\n");
        if (client->identifier != NULL)
            free(client->identifier);
        free(client);
        return;
    }

    // Send response
    dhcp_pkt *response = make_ret_pkt(
        pkt,
        ntohl(client->offered_address.s_addr),
        ntohl(ctx->srv_address.s_addr));
    if (response == NULL)
    {
        fprintf(stderr, "failed to create dhcp offer response\n");
        remove_client_by_client(ctx, client, true);
        return;
    }

    param_len = get_dhcp_requested_params(pkt, params, NUM_PARAMS);
    for (int i = 0; i < param_len; i++)
    {
        uint8_t addr_buf[4];
        switch (params[i])
        {
        case OPT_SUBNET_MASK:
            memcpy(addr_buf, &ctx->mask.s_addr, sizeof addr_buf);
            add_pkt_option(
                response, OPT_SUBNET_MASK, sizeof addr_buf, addr_buf);
            break;
        case OPT_DEFAULT_ROUTER:
            if (ctx->gateway)
            {
                memcpy(addr_buf, &ctx->gateway->s_addr, sizeof addr_buf);
                add_pkt_option(
                    response, OPT_DEFAULT_ROUTER, sizeof addr_buf, addr_buf);
            }
            break;
        case OPT_DNS_SERVER:
            if (ctx->dns_server)
            {
                memcpy(addr_buf, &ctx->gateway->s_addr, sizeof addr_buf);
                add_pkt_option(
                    response, OPT_DNS_SERVER, sizeof addr_buf, addr_buf);
            }
            break;
        default:
            break;
        }
    }

    memset(&broadcast, 0, sizeof broadcast);
    const int DHCP_CLIENT_PORT = 68;
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(DHCP_CLIENT_PORT);
    broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    uint8_t *response_buf = serialize_dhcp_pkt(response);
    if (response_buf == NULL)
    {
        fprintf(stderr, "failed to serialize dhcp offer response\n");
        remove_client_by_client(ctx, client, true);
        free_dhcp_pkt(response);
        return;
    }

    ret = sendto(
        ctx->srv_socket,
        response_buf,
        ETHERNET_MTU,
        0,
        (struct sockaddr *)&broadcast,
        sizeof(broadcast));
    if (ret != ETHERNET_MTU)
    {
        perror("failed to send dhcp offer response");
        remove_client_by_client(ctx, client, true);
        free_dhcp_pkt(response);
        free(response_buf);
    } 
}
