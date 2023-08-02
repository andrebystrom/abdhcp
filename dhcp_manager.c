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
add_response_options(
    context *ctx,
    dhcp_pkt *req, dhcp_pkt *response,
    client *client,
    uint8_t pkt_type);

static int8_t
add_requested_options(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response);

static int8_t
send_response(context *ctx, dhcp_pkt *response);

static int8_t
register_client(context *ctx, client **res, dhcp_pkt *pkt);

static void
handle_request_offer_response(
    context *ctx,
    dhcp_pkt *pkt,
    uint8_t *serv_id, uint8_t serv_id_len,
    uint8_t *client_id, uint8_t client_id_len);

static void
handle_request_reboot(context *ctx, dhcp_pkt *pkt,
                      uint8_t *client_id, uint8_t client_id_len,
                      uint8_t *req_ip, uint8_t req_ip_len);

static void
handle_request_renew_rebind(context *ctx, dhcp_pkt *pkt,
                            uint8_t *client_id, uint8_t client_id_len);

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

int8_t
get_client(context *ctx, uint8_t *id, uint8_t id_len, client **res)
{
    for (int i = 0; i < ctx->num_clients; i++)
    {
        client *c = ctx->clients[i];
        if (c->identifier)
        {
            if (c->id_len == id_len && memcmp(c->identifier, id, id_len) == 0)
            {
                *res = c;
                return 0;
            }
        }
        else
        {
            if (ETHERNET_LEN == id_len &&
                memcmp(c->ethernet_address, id, id_len) == 0)
            {
                *res = c;
                return 0;
            }
        }
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

/* GENERAL */

static int8_t
add_response_options(
    context *ctx,
    dhcp_pkt *req, dhcp_pkt *response,
    client *client,
    uint8_t pkt_type)
{
    uint32_t lease = htonl(client->lease_end - client->lease_start);

    if (add_pkt_option(response, OPT_MESSAGE_TYPE,
                       sizeof pkt_type, &pkt_type) == OPT_WR_ERROR)
    {
        fprintf(stderr, "failed to add message type option\n");
        return -1;
    }
    if (add_requested_options(ctx, req, response) < 0)
    {
        fprintf(stderr, "failed to add requested options\n");
        return -1;
    }
    if (add_pkt_option(response, OPT_SERVER_IDENTIFIER,
                       sizeof ctx->srv_address.s_addr,
                       (uint8_t *)&(ctx->srv_address.s_addr)) == OPT_WR_ERROR)
    {
        fprintf(stderr, "failed to write server identifier option\n");
        return -1;
    }
    client->lease_end = htonl(DEFAULT_LEASE_SEC);
    if (add_pkt_option(response, OPT_LEASE_TIME, sizeof(uint32_t),
                       (uint8_t *)&lease) == OPT_WR_ERROR)
    {
        fprintf(stderr, "failed to write lease option\n");
        return -1;
    }
    if (add_pkt_opt_end(response) == OPT_WR_ERROR)
    {
        fprintf(stderr, "failed to write end option\n");
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
            if (add_pkt_option(response, OPT_SUBNET_MASK,
                               sizeof addr_buf, addr_buf) == OPT_WR_ERROR)
            {
                return -1;
            }
            break;
        case OPT_DEFAULT_ROUTER:
            if (ctx->gateway)
            {
                memcpy(addr_buf, &(ctx->gateway->s_addr), sizeof addr_buf);
                if (add_pkt_option(response, OPT_DEFAULT_ROUTER,
                                   sizeof addr_buf, addr_buf) == OPT_WR_ERROR)
                {
                    return -1;
                }
            }
            break;
        case OPT_DNS_SERVER:
            if (ctx->dns_server)
            {
                memcpy(addr_buf, &(ctx->dns_server->s_addr), sizeof addr_buf);
                if (add_pkt_option(response, OPT_DNS_SERVER,
                                   sizeof addr_buf, addr_buf) == OPT_WR_ERROR)
                {
                    return -1;
                }
            }
            break;
        default:
            break;
        }
    }
    return 0;
}

static int8_t
send_response(context *ctx, dhcp_pkt *response)
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
        fprintf(stderr, "failed to serialize dhcp message\n");
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
        perror("failed to send dhcp response");
        free(response_buf);
        return -1;
    }

    free(response_buf);
    return 0;
}

/* DHCP DISCOVER */

void handle_discover(context *ctx, dhcp_pkt *pkt)
{
    client *client;

    if (ctx->debug)
        printf("got dhcp discover pkt\n");

    // Try to register the client in the allocation pool.
    if (register_client(ctx, &client, pkt) < 0)
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

    if (add_response_options(ctx, pkt, response,
                             client, OPT_MESSAGE_TYPE_OFFER) < 0)
    {
        fprintf(stderr, "failed to add dhcp offer response options\n");
        goto err_response;
    }

    if (send_response(ctx, response) < 0)
    {
        fprintf(stderr, "failed to send dhcp offer response\n");
        goto err_response;
    }

    free_dhcp_pkt(response);
    return;

err_response:
    free_dhcp_pkt(response);
err_client:
    remove_client_by_client(ctx, client, true);
}

static int8_t
register_client(context *ctx, client **res, dhcp_pkt *pkt)
{
    struct in_addr addr;
    int ret;
    uint8_t *buf;
    uint16_t buf_len;
    uint8_t *client_id;
    uint16_t client_id_len;
    bool allocd_client_id = true;

    if (find_dhcp_option(pkt, OPT_IDENTIFIER, &client_id,
                         &client_id_len, true) == OPT_SEARCH_ERROR)
    {
        client_id = pkt->ch_addr;
        client_id_len = ETHERNET_LEN;
        allocd_client_id = false;
    }

    if (get_client(ctx, client_id, client_id_len, res) >= 0)
    {
        // Client already registered, reset lease and return it.
        (*res)->state = OFFERED;
        (*res)->lease_start = time(NULL);
        (*res)->lease_end = (*res)->lease_start + DEFAULT_LEASE_SEC;
        return 0;
    }

    if ((*res = malloc(sizeof(**res))) == NULL)
    {
        fprintf(stderr, "failed to allocate client memory\n");
        goto err_client_id;
    }

    if ((ret = find_usable_client_addr(ctx, &addr)) < 0)
    {
        fprintf(stderr, "failed to find usable address for discover\n");
        goto err_client_id;
    }

    (*res)->state = OFFERED;
    (*res)->offered_address.s_addr = addr.s_addr;
    memcpy((*res)->ethernet_address, pkt->ch_addr, ETHERNET_LEN);
    (*res)->identifier = NULL;
    if ((find_dhcp_option(
            pkt, OPT_IDENTIFIER, &buf, &buf_len, true)) != OPT_SEARCH_ERROR)
    {
        (*res)->identifier = buf;
        (*res)->id_len = buf_len;
    }
    (*res)->lease_start = time(NULL);
    (*res)->lease_end = (*res)->lease_start + DEFAULT_LEASE_SEC;

    if (insert_client(ctx, *res) < 0)
    {
        fprintf(stderr, "failed to insert client into client table\n");
        goto err_insert_client;
    }

    return 0;

err_insert_client:
    if ((*res)->identifier != NULL)
        free((*res)->identifier);
    free(*res);
err_client_id:
    if (allocd_client_id)
        free(client_id);

    return -1;
}

/* DHCP REQUEST */

void handle_request(context *ctx, dhcp_pkt *pkt)
{
    uint8_t *serv_id = NULL;
    uint16_t serv_id_len;
    uint8_t *client_id = NULL;
    uint16_t client_id_len;
    bool allocd_client_id = true;
    uint8_t *req_ip = NULL;
    uint16_t req_ip_len;

    uint8_t serv_res = find_dhcp_option(pkt, OPT_SERVER_IDENTIFIER,
                                        &serv_id, &serv_id_len, true);
    uint8_t client_res = find_dhcp_option(pkt, OPT_IDENTIFIER,
                                          &client_id, &client_id_len, true);
    uint8_t req_res = find_dhcp_option(pkt, OPT_REQUESTED_IP,
                                       &req_ip, &req_ip_len, true);

    // No client ID specified, use ethernet address.
    if (client_res == OPT_SEARCH_ERROR)
    {
        client_id = pkt->ch_addr;
        client_id_len = ETHERNET_LEN;
        allocd_client_id = false;
    }

    if (serv_res == OPT_SEARCH_SUCCESS)
    {
        // Response to DHCP offer.
        handle_request_offer_response(ctx, pkt, serv_id, serv_id_len,
                                      client_id, client_id_len);
        free(serv_id);
    }
    else if (req_res == OPT_SEARCH_SUCCESS)
    {
        // Client wants to verify existing config.
        handle_request_reboot(ctx, pkt, client_id, client_id_len,
                              req_ip, req_ip_len);

        free(req_ip);
    }
    else
    {
        // Either a renew or rebind.
        handle_request_renew_rebind(ctx, pkt, client_id, client_id_len);
    }

    if (allocd_client_id)
    {
        free(client_id);
    }
}

static void
handle_request_offer_response(
    context *ctx,
    dhcp_pkt *pkt,
    uint8_t *serv_id, uint8_t serv_id_len,
    uint8_t *client_id, uint8_t client_id_len)
{
    if (ctx->debug)
        printf("Got DHCP request offer response\n");
    const uint8_t id_len = sizeof(ctx->srv_address.s_addr);
    int8_t client_res;
    client *client = NULL;
    dhcp_pkt *response;

    if (serv_id_len != id_len ||
        memcmp(serv_id, &(ctx->srv_address.s_addr), id_len) != 0)
    {
        if (ctx->debug)
            printf("Got offer response destined for another server (%.*s)\n",
                   serv_id_len, serv_id);
        return;
    }

    client_res = get_client(ctx, client_id, client_id_len, &client);
    if (client_res < 0)
    {
        fprintf(stderr, "Failed to find client entry for request message\n");
        return;
    }
    client->state = COMMITED;

    if ((response = make_ret_pkt(pkt, ntohl(client->offered_address.s_addr),
                                 ntohl(ctx->srv_address.s_addr))) == NULL)
    {
        fprintf(stderr, "Failed to create response to request message\n");
        return;
    }

    if (add_response_options(ctx, pkt, response,
                             client, OPT_MESSAGE_TYPE_ACK) < 0)
    {
        fprintf(stderr, "Failed to add options to request response\n");
        free(response);
        return;
    }

    if (send_response(ctx, response) < 0)
    {
        fprintf(stderr, "Failed to send request response\n");
        free(response);
    }
}

static void
handle_request_reboot(context *ctx, dhcp_pkt *pkt,
                      uint8_t *client_id, uint8_t client_id_len,
                      uint8_t *req_ip, uint8_t req_ip_len)
{
    if (ctx->debug)
        printf("Got DHCP request reboot\n");
}

static void
handle_request_renew_rebind(context *ctx, dhcp_pkt *pkt,
                            uint8_t *client_id, uint8_t client_id_len)
{
    // TODO we need the clients sockaddr to determine if this is
    // a unicast   -> renew, respond with unicast
    // a broadcast -> rebind, respond with broadcast.
    // For now, we will settle with using broadcast for both.
    // This is OK per RFC 2131,
    // "If unicasting is not possible, the message
    // MAY be sent as an IP broadcast using an IP broadcast address
    // (preferably 0xffffffff) as the IP destination address and the link-
    // layer broadcast address as the link-layer destination address."
    if (ctx->debug)
        printf("Got DHCP request renew/rebind\n");
}