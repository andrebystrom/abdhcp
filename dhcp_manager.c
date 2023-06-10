#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

// net includes.
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// sys includes.
#include <unistd.h>

#include "core.h"
#include "dhcp_manager.h"

int8_t find_usable_client_addr(context *ctx, struct in_addr *addr)
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

int8_t insert_client(context *ctx, client *c)
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

int8_t remove_client(context *ctx, uint8_t *id, uint8_t len, bool free_it)
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

int client_cmp(const void *c1, const void *c2)
{
    client **cl1 = (client **)c1;
    client **cl2 = (client **)c2;
    long addr1 = ntohl((*cl1)->offered_address.s_addr);
    long addr2 = ntohl((*cl2)->offered_address.s_addr);

    return (int)addr1 - addr2;
}