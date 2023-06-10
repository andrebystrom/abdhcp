#ifndef DHCP_MANAGER_H
#define DHCP_MANAGER_H

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

int8_t find_usable_client_addr(context *ctx, struct in_addr *addr);
int8_t insert_client(context *ctx, client *client);
int8_t remove_client(context *ctx, uint8_t *id, uint8_t len, bool free_it);
int client_cmp(const void *c1, const void *c2);

#endif