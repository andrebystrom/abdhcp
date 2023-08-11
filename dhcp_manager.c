/*
* Summary: Handles and responds to DHCP messages, allocates addresses etc.
*/
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
find_usable_client_addr(context *ctx, struct in_addr *addr);

static int8_t
insert_client(context *ctx, client *c);

static int8_t
remove_client_by_client(context *ctx, client *client, bool free_it);

static int8_t
remove_client(context *ctx, uint8_t *id, uint8_t len, bool free_it);

static int8_t
get_client(context *ctx, uint8_t *id, uint8_t id_len, client **res);

static int
client_cmp(const void *c1, const void *c2);

static int8_t
add_response_options(
    context *ctx,
    dhcp_pkt *req, dhcp_pkt *response,
    client *client,
    uint8_t pkt_type);

static int8_t
add_requested_options(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response);

static int8_t
prepare_response(context *ctx, dhcp_pkt *pkt, dhcp_pkt **response,
                 client *client, uint8_t msg_type);

static int8_t
send_response(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response,
              struct sockaddr_in *addr);

static int8_t
send_response_broadcast(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response);

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

/* Client operations */

/// @brief Finds a usable client address.
/// @param ctx the context.
/// @param addr the return address, only set if the return value is success.
/// @return -1 on fail, 0 otherwise.
static int8_t
find_usable_client_addr(context *ctx, struct in_addr *addr)
{
    // network pool info.
    uint32_t base_addr = ntohl(ctx->start_address.s_addr);
    uint32_t end_addr = ntohl(ctx->end_address.s_addr);
    uint32_t num_addrs = end_addr - base_addr;

    bool found_addr = false;
    uint32_t candidate_addr;
    client *ret;
    for (uint32_t i = 0; i <= num_addrs; i++)
    {
        candidate_addr = htonl(base_addr + ctx->host_offset);
        client search_client = {.offered_address.s_addr = candidate_addr};
        client *tmp = &search_client;
        if (ctx->num_clients == 0 ||
            (ret = bsearch(&tmp, ctx->clients, ctx->num_clients,
                           sizeof(client *), client_cmp)) == NULL)
        {
            // address not in use
            found_addr = true;
            break;
        }
        // Check if the found client has expired
        time_t now = time(NULL);
        if (now > ret->lease_end + DEFAULT_LEASE_GRACE)
        {
            remove_client_by_client(ctx, ret, true);
            found_addr = true;
            break;
        }

        ctx->host_offset = (ctx->host_offset + 1) % (num_addrs + 1);
    }

    if (!found_addr)
        return -1;

    ctx->host_offset = (ctx->host_offset + 1) % (num_addrs + 1);
    addr->s_addr = candidate_addr;
    return 0;
}

/// @brief Inserts a client.
/// @param ctx the context.
/// @param c the client to insert.
/// @return -1 on fail, 0 on success.
static int8_t
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

/// @brief Removes a client by a client.
/// @param ctx the context.
/// @param client the client to remove.
/// @param free_it true if the client should be freed.
/// @return -1 on fail, 0 on success.
static int8_t
remove_client_by_client(context *ctx, client *client, bool free_it)
{
    if (client->identifier != NULL)
        return remove_client(ctx, client->identifier, client->id_len, free_it);

    return remove_client(ctx, client->ethernet_address, ETHERNET_LEN, free_it);
}

/// @brief Removes a client.
/// @param ctx the context.
/// @param id the id of the client.
/// @param len the length of the client id.
/// @param free_it true if the client should be freed.
/// @return -1 on fail, 0 on success.
static int8_t
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
        if (free_it)
        {
            if (c->identifier)
                free(c->identifier);
            free(c);
        }
        memmove(ctx->clients + i, ctx->clients + i + 1,
                ctx->num_clients - i - 1);

        ctx->clients[ctx->num_clients - 1] = NULL;
        ctx->num_clients--;
        return 0;
    }
    return -1;
}

/// @brief Gets a client.
/// @param ctx the context.
/// @param id the id of the client.
/// @param id_len the length of the id.
/// @param res result placed here on success.
/// @return -1 on fail, 0 on success.
static int8_t
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

/// @brief Compares clients by addresses in ascending order.
/// @param c1 client 1.
/// @param c2 client 2.
/// @return 0 on equal, < 0 when c1 < c2, > 0 when c1 > c2.
static int
client_cmp(const void *c1, const void *c2)
{
    client **cl1 = (client **)c1;
    client **cl2 = (client **)c2;
    long addr1 = ntohl((*cl1)->offered_address.s_addr);
    long addr2 = ntohl((*cl2)->offered_address.s_addr);

    return (int)addr1 - addr2;
}

/* GENERAL DHCP */

/// @brief add general response options.
/// @param ctx the context.
/// @param req the request.
/// @param response the responset to add to.
/// @param client the client entry.
/// @param pkt_type the type of packet.
/// @return -1 on fail, 0 on success.
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

/// @brief Adds the request param options.
/// @param ctx the context.
/// @param pkt the request pkt.
/// @param response the response pkt.
/// @return -1 on fail, 0 on success.
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

/// @brief Prepares the response to be ready to be sent to the client.
/// @param ctx the context.
/// @param pkt the request pkt.
/// @param response the response pkt to prepare.
/// @param client the client.
/// @param msg_type the message type.
/// @return -1 on fail, 0 on success.
static int8_t
prepare_response(context *ctx, dhcp_pkt *pkt, dhcp_pkt **response,
                 client *client, uint8_t msg_type)
{
    *response = make_ret_pkt(
        pkt, ntohl(client->offered_address.s_addr),
        ntohl(ctx->srv_address.s_addr));
    if (*response == NULL)
    {
        return -1;
    }

    if (add_response_options(ctx, pkt, *response,
                             client, msg_type) < 0)
    {
        free(*response);
        return -1;
    }

    return 0;
}

/// @brief Sends the response to addr.
/// @param ctx the context.
/// @param pkt the request pkt.
/// @param response the response pkt to send.
/// @param addr the addr to send to.
/// @return -1 on fail, 0 on success.
static int8_t
send_response(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response,
              struct sockaddr_in *addr)
{
    uint32_t max_response_len;
    uint32_t response_size;
    ssize_t ret;

    uint8_t *response_buf = serialize_dhcp_pkt(response, &response_size);
    if (response_buf == NULL)
    {
        fprintf(stderr, "failed to serialize DHCP message\n");
        return -1;
    }

    if ((max_response_len = get_max_message_size(pkt)) > 0 &&
        response_size > max_response_len)
    {
        fprintf(stderr, "DHCP response is to large for client\n");
        free(response_buf);
        return -1;
    }

    ret = sendto(ctx->srv_socket,
                 response_buf, response_size, 0,
                 (struct sockaddr *)addr, sizeof(*addr));
    if (ret != response_size)
    {
        perror("failed to send DHCP response");
        free(response_buf);
        return -1;
    }

    free(response_buf);
    return 0;
}

/// @brief send response as broadcast.
/// @param ctx the context.
/// @param pkt the request pkt.
/// @param response the response pkt.
/// @return -1 on fail, 0 on success.
static int8_t
send_response_broadcast(context *ctx, dhcp_pkt *pkt, dhcp_pkt *response)
{
    struct sockaddr_in broadcast;
    ssize_t ret;
    uint32_t max_response_len;
    uint32_t response_len;

    memset(&broadcast, 0, sizeof broadcast);
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(DHCP_CLIENT_PORT);
    broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    uint8_t *response_buf = serialize_dhcp_pkt(response, &response_len);
    if (response_buf == NULL)
    {
        fprintf(stderr, "failed to serialize DHCP message\n");
        return -1;
    }

    if ((max_response_len = get_max_message_size(pkt)) > 0 &&
        response_len > max_response_len)
    {
        fprintf(stderr, "DHCP response is to large for client\n");
        free(response_buf);
        return -1;
    }

    ret = sendto(
        ctx->srv_socket,
        response_buf,
        response_len,
        0,
        (struct sockaddr *)&broadcast,
        sizeof(broadcast));
    if (ret != response_len)
    {
        perror("failed to send DHCP response");
        free(response_buf);
        return -1;
    }

    free(response_buf);
    return 0;
}

/* DHCP DISCOVER */

/// @brief Handles a DHCP discover packet.
/// @param ctx the context.
/// @param pkt the discover request packet.
void handle_discover(context *ctx, dhcp_pkt *pkt)
{
    client *client;
    dhcp_pkt *response;

    if (ctx->debug)
        printf("got dhcp discover pkt\n");

    // Try to register the client in the allocation pool.
    if (register_client(ctx, &client, pkt) < 0)
    {
        // Issue with registering the client, eg. address pool exhausted.
        return;
    }

    // Send response
    if (prepare_response(ctx, pkt, &response, client,
                         OPT_MESSAGE_TYPE_OFFER) < 0)
    {
        fprintf(stderr, "failed to prepare DHCP offer response\n");
        goto cleanup;
    }

    if (send_response_broadcast(ctx, pkt, response) < 0)
    {
        fprintf(stderr, "failed to send DHCP offer response\n");
        goto cleanup;
    }

    free_dhcp_pkt(response);
    return;

cleanup:
    free_dhcp_pkt(response);
    remove_client_by_client(ctx, client, true);
}

/// @brief Registers a client by finding a lease and adding it to the list of
/// clients.
/// @param ctx the context.
/// @param res the added client.
/// @param pkt the request.
/// @return -1 on fail, 0 on success.
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

/// @brief Handles a DHCP request packet.
/// @param ctx the context.
/// @param pkt the request packet.
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

/// @brief Handles a DHCP request thats a response to an offer.
/// @param ctx the context.
/// @param pkt the packet.
/// @param serv_id the server id.
/// @param serv_id_len the server id len.
/// @param client_id the client id.
/// @param client_id_len the client id len.
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

    if (prepare_response(ctx, pkt, &response, client, OPT_MESSAGE_TYPE_ACK) < 0)
    {
        fprintf(stderr, "Failed to prepare response to DHCP request message\n");
        return;
    }

    if (send_response_broadcast(ctx, pkt, response) < 0)
    {
        fprintf(stderr, "Failed to send request response\n");
        free(response);
    }
}

/// @brief Handles a DHCP request thats a reboot.
/// @param ctx the context.
/// @param pkt the request.
/// @param client_id the client id.
/// @param client_id_len the cliebt id len.
/// @param req_ip the requested ip.
/// @param req_ip_len the requested ip len.
static void
handle_request_reboot(context *ctx, dhcp_pkt *pkt,
                      uint8_t *client_id, uint8_t client_id_len,
                      uint8_t *req_ip, uint8_t req_ip_len)
{
    client *client;
    dhcp_pkt *response;
    uint32_t allocd_addr_raw;
    uint32_t req_addr_raw;
    time_t old_start;
    time_t old_end;

    if (ctx->debug)
        printf("Got DHCP request reboot\n");

    if (req_ip_len != sizeof(uint32_t))
    {
        fprintf(stderr, "Invalid request IP address in reboot request\n");
        return;
    }

    if (get_client(ctx, client_id, client_id_len, &client) < 0)
    {
        // Todo send NAK
        fprintf(stderr, "Got dhcp reboot request for non-allocated client\n");
        return;
    }

    memcpy(&req_addr_raw, req_ip, sizeof(uint32_t));
    req_addr_raw = ntohl(req_addr_raw);
    allocd_addr_raw = ntohl(client->offered_address.s_addr);
    if (req_addr_raw != allocd_addr_raw)
    {
        // Client has wrong notion of its address.
        // TODO send NAK
        printf("Got dhcp reboot request where requested address "
               "does not match\n");
        return;
    }

    // Extend lease and send ACK
    old_start = client->lease_start;
    old_end = client->lease_end;
    client->lease_start = time(NULL);
    client->lease_end = client->lease_start + DEFAULT_LEASE_SEC;

    if (prepare_response(ctx, pkt, &response, client, OPT_MESSAGE_TYPE_ACK) < 0)
    {
        fprintf(stderr, "Failed to prepare response to DHCP request message\n");
        goto err_lease;
    }

    if (send_response_broadcast(ctx, pkt, response) < 0)
    {
        fprintf(stderr, "Failed to send request response\n");
        goto err_response;
    }

err_response:
    free(response);
err_lease:
    client->lease_start = old_start;
    client->lease_end = old_end;
}

/// @brief Handles a DHCP request thats a rebind.
/// @param ctx the context.
/// @param pkt the request.
/// @param client_id the client id.
/// @param client_id_len the client id len.
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

    client *client;
    dhcp_pkt *response;
    time_t old_start;
    time_t old_end;

    if (ctx->debug)
        printf("Got DHCP request renew/rebind\n");

    if (get_client(ctx, client_id, client_id_len, &client) < 0)
    {
        // Client not managed by this server, do nothing.
        if (ctx->debug)
            printf("Got renew/rebind from %.*s not managed by this server",
                   client_id_len, client_id);
        return;
    }

    // Extend lease
    old_start = client->lease_start;
    old_end = client->lease_end;
    client->lease_start = time(NULL);
    client->lease_end = client->lease_start + DEFAULT_LEASE_SEC;

    if (prepare_response(ctx, pkt, &response, client, OPT_MESSAGE_TYPE_ACK) < 0)
    {
        fprintf(stderr, "Failed to create response to DHCP request message\n");
        goto err_lease;
    }

    if (send_response_broadcast(ctx, pkt, response) < 0)
    {
        fprintf(stderr, "Failed to send request response\n");
        goto err_response;
    }

err_response:
    free(response);
err_lease:
    client->lease_start = old_start;
    client->lease_end = old_end;
}

/* DHCP RELEASE */

/// @brief Handles a DHCP release message.
/// @param ctx the context.
/// @param pkt the release.
void handle_release(context *ctx, dhcp_pkt *pkt)
{
    uint8_t *client_id;
    uint16_t client_id_len;
    bool allocd_client_id = true;

    if (ctx->debug)
    {
        printf("Got DHCP release message\n");
    }

    if (find_dhcp_option(pkt, OPT_IDENTIFIER, &client_id,
                         &client_id_len, true) == OPT_SEARCH_ERROR)
    {
        client_id = pkt->ch_addr;
        client_id_len = ETHERNET_LEN;
        allocd_client_id = false;
    }

    if (remove_client(ctx, client_id, client_id_len, true) < 0)
        fprintf(stderr, "Failed to find client binding to remove for "
                        "DHCP release\n");

    if (allocd_client_id)
        free(client_id);
}

/* DCHP DECLINE */

/// @brief Handles a DHCP decline message by removing the client and
/// incrementing the host offset.
/// @param ctx the context.
/// @param pkt the decline message.
void handle_decline(context *ctx, dhcp_pkt *pkt)
{
    if (ctx->debug)
        printf("got DHCP decline message\n");

    uint8_t *client_id;
    uint16_t client_id_len;
    bool allocd_client_id = true;

    if (find_dhcp_option(pkt, OPT_IDENTIFIER, &client_id,
                         &client_id_len, true) == OPT_SEARCH_ERROR)
    {
        allocd_client_id = false;
        client_id = pkt->ch_addr;
        client_id_len = ETHERNET_LEN;
    }

    remove_client(ctx, client_id, client_id_len, true);

    uint32_t num_addrs = ntohl(ctx->end_address.s_addr) -
                         ntohl(ctx->start_address.s_addr);
    ctx->host_offset = (ctx->host_offset + 1) % (num_addrs + 1);

    if (allocd_client_id)
        free(client_id);
}

/* DHCP INFORM */

/// @brief Handles a DHCP inform packet.
/// @param ctx the context.
/// @param pkt the inform message.
void handle_inform(context *ctx, dhcp_pkt *pkt)
{
    dhcp_pkt *response;
    client *client;

    uint8_t *client_id;
    uint16_t client_id_len;
    bool allocd_client_id = true;
    struct sockaddr_in addr;

    if (ctx->debug)
        printf("got DHCP inform message\n");

    if (find_dhcp_option(pkt, OPT_IDENTIFIER, &client_id,
                         &client_id_len, true) == OPT_SEARCH_ERROR)
    {
        allocd_client_id = false;
        client_id = pkt->ch_addr;
        client_id_len = ETHERNET_LEN;
    }

    if (get_client(ctx, client_id, client_id_len, &client) < 0)
    {
        fprintf(stderr, "got DHCP inform from non-bound client\n");
        goto cleanup_client;
    }

    if (prepare_response(ctx, pkt, &response, client, OPT_MESSAGE_TYPE_ACK) < 0)
    {
        fprintf(stderr, "Failed to create response to DHCP request message\n");
        goto cleanup_client;
    }

    // Inform must not include lease time and should not have yi_addr set.
    overwrite_opt_with_pad(response, OPT_LEASE_TIME);
    response->yi_addr = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = htonl(pkt->ci_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DHCP_CLIENT_PORT);
    if (send_response(ctx, pkt, response, &addr) < 0)
    {
        fprintf(stderr, "Failed to send inform response\n");
        goto cleanup_send;
    }

cleanup_send:
    free(response);
cleanup_client:
    if (allocd_client_id)
        free(client_id);
}