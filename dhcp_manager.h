#ifndef DHCP_MANAGER_H
#define DHCP_MANAGER_H

#define DEFAULT_LEASE_SEC 3600
#define DEFAULT_LEASE_GRACE 300

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

int8_t
find_usable_client_addr(context *ctx, struct in_addr *addr);
int8_t
insert_client(context *ctx, client *client);
int8_t
remove_client_by_client(context *ctx, client *client, bool free_it);
int8_t
remove_client(context *ctx, uint8_t *id, uint8_t len, bool free_it);
int client_cmp(const void *c1, const void *c2);

void handle_discover(context *ctx, dhcp_pkt *pkt);
void handle_request(context *ctx, dhcp_pkt *pkt);
void handle_release(context *ctx, dhcp_pkt *pkt);
void handle_decline(context *ctx, dhcp_pkt *pkt);

#endif