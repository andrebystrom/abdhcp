#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

// net includes.
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// sys includes.
#include <unistd.h>

#include "core.h"
#include "dhcp_manager.h"

static int8_t 
register_client(context *ctx, client *client, dhcp_pkt *pkt);

static int8_t 
add_requested_options(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response);

static int8_t
send_discover_response(context *ctx, dhcp_pkt *response);

int8_t 
find_usable_client_addr(context *ctx, struct in_addr *addr)
{
    uint32_t base_addr = ntohl(ctx->start_address.s_addr);
    uint32_t mask = ntohl(ctx->mask.s_addr);
    uint32_t base_addr_host = base_addr & ~mask;
    uint32_t ret_host = base_addr_host;
    uint32_t ret_address;

    for (int i = 0; i < ctx->num_clients; i++)
    {
        uint32_t offered_addr = ntohl(ctx->clients[i]->offered_address.s_addr);
        uint32_t offered_host = offered_addr & ~mask;
        if (ret_host < offered_host)
            break;

        ret_host++;
    }

    ret_address = ret_host | (base_addr & mask);

    addr->s_addr = htonl(ret_address);
    if (ret_address > ntohl(ctx->end_address.s_addr))
    {
        return -1;
    }

    addr->s_addr = htonl(ret_address);
    return 0;
}

int8_t 
insert_client(context *ctx, client *c)
{
    client **tmp = reallocarray(
        ctx->clients,
        ctx->num_clients + 1,
        sizeof(client *));
    if (tmp == NULL)
    {
        fprintf(stderr, "failed to re-allocate clients\n");
        return -1;
    }

    ctx->clients = tmp;
    ctx->clients[ctx->num_clients++] = c;
    qsort(ctx->clients, ctx->num_clients, sizeof(client *), client_cmp);

    return 0;
}

int8_t 
remove_client_by_client(context *ctx, client *client, bool free_it)
{
    if (client->identifier != NULL)
        return remove_client(ctx, client->identifier, client->id_len, free_it);

    return remove_client(ctx, client->ethernet_address, ETHERNET_LEN, free_it);
}

int8_t 
remove_client(context *ctx, uint8_t *id, uint8_t len, bool free_it)
{
    for (int i = 0; i < ctx->num_clients; i++)
    {
        client *c = ctx->clients[i];
        if (c->identifier)
        {
            if (c->id_len != len)
                continue;
            if (memcmp(c->identifier, id, len) != 0)
                continue;
        }
        else
        {
            if (sizeof(c->ethernet_address) != len)
                continue;
            if (memcmp(c->ethernet_address, id, len) != 0)
                continue;
        }

        // Remove and return.
        c->offered_address.s_addr = INADDR_BROADCAST;
        qsort(ctx->clients, ctx->num_clients, sizeof(client *), client_cmp);
        if (free_it)
        {
            if (c->identifier)
                free(c->identifier);
            free(c);
        }
        ctx->clients[ctx->num_clients - 1] = NULL;
        ctx->num_clients--;
        return 0;
    }
    return -1;
}

int 
client_cmp(const void *c1, const void *c2)
{
    client **cl1 = (client **)c1;
    client **cl2 = (client **)c2;
    long addr1 = ntohl((*cl1)->offered_address.s_addr);
    long addr2 = ntohl((*cl2)->offered_address.s_addr);

    return (int)addr1 - addr2;
}

/* DHCP DISCOVER */

void 
handle_discover(context *ctx, dhcp_pkt *pkt)
{
    client *client;
    uint8_t opt;
    uint32_t long_opt;

    if (ctx->debug)
        printf("got dhcp discover pkt\n");

    // Try to register the client in the allocation pool.
    if ((client = malloc(sizeof(client))) == NULL)
    {
        fprintf(stderr, "failed to allocate client memory\n");
        return;
    }
    if (register_client(ctx, client, pkt) < 0)
    {
        // Issue with registering the client, eg. address pool exhausted.
        return;
    }

    // Send response
    dhcp_pkt *response = make_ret_pkt(
        pkt, ntohl(client->offered_address.s_addr),
        ntohl(ctx->srv_address.s_addr));
    if (response == NULL)
    {
        fprintf(stderr, "failed to create dhcp offer response\n");
        goto err_client;
    }

    opt = OPT_MESSAGE_TYPE_OFFER;
    add_pkt_option(response, OPT_MESSAGE_TYPE, sizeof opt, &opt);
    add_requested_options(ctx, pkt, response);
    add_pkt_option(response, OPT_SERVER_IDENTIFIER,
                   sizeof ctx->srv_address.s_addr,
                   (uint8_t *)&(ctx->srv_address.s_addr));
    long_opt = htonl(DEFAULT_LEASE_SEC);
    add_pkt_option(response, OPT_LEASE_TIME, sizeof(uint32_t),
                   (uint8_t *)&long_opt);
    add_pkt_opt_end(response);

    if (send_discover_response(ctx, response) < 0)
        goto err_response;

    free_dhcp_pkt(response);
    return;

err_response:
    free_dhcp_pkt(response);
err_client:
    remove_client_by_client(ctx, client, true);
}

static int8_t 
register_client(context *ctx, client *client, dhcp_pkt *pkt)
{
    struct in_addr addr;
    int ret;
    uint8_t *buf;
    uint16_t buf_len;

    if ((ret = find_usable_client_addr(ctx, &addr)) < 0)
    {
        fprintf(stderr, "failed to find usable address for discover\n");
        return -1;
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
    client->lease_end = time(NULL) + DEFAULT_LEASE_SEC;

    if (insert_client(ctx, client) < 0)
    {
        fprintf(stderr, "failed to insert client into client table\n");
        if (client->identifier != NULL)
            free(client->identifier);
        free(client);
        return -1;
    }

    return 0;
}

static int8_t
add_requested_options(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response)
{
    const int NUM_PARAMS = 3;
    uint8_t params[NUM_PARAMS];
    uint8_t param_len = get_dhcp_requested_params(pkt, params, NUM_PARAMS);

    for (int i = 0; i < param_len; i++)
    {
        uint8_t addr_buf[4];
        switch (params[i])
        {
        case OPT_SUBNET_MASK:
            memcpy(addr_buf, &(ctx->mask.s_addr), sizeof addr_buf);
            add_pkt_option(
                response, OPT_SUBNET_MASK, sizeof addr_buf, addr_buf);
            break;
        case OPT_DEFAULT_ROUTER:
            if (ctx->gateway)
            {
                memcpy(addr_buf, &(ctx->gateway->s_addr), sizeof addr_buf);
                add_pkt_option(
                    response, OPT_DEFAULT_ROUTER, sizeof addr_buf, addr_buf);
            }
            break;
        case OPT_DNS_SERVER:
            if (ctx->dns_server)
            {
                memcpy(addr_buf, &(ctx->gateway->s_addr), sizeof addr_buf);
                add_pkt_option(
                    response, OPT_DNS_SERVER, sizeof addr_buf, addr_buf);
            }
            break;
        default:
            break;
        }
    }
    return 0;
}

static int8_t 
send_discover_response(context *ctx, dhcp_pkt *response)
{
    struct sockaddr_in broadcast;
    ssize_t ret;

    memset(&broadcast, 0, sizeof broadcast);
    const int DHCP_CLIENT_PORT = 68;
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(DHCP_CLIENT_PORT);
    broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    uint8_t *response_buf = serialize_dhcp_pkt(response);
    if (response_buf == NULL)
    {
        fprintf(stderr, "failed to serialize dhcp offer response\n");
        return -1;
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
        free(response_buf);
        return -1;
    }

    return 0;
}