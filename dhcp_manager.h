#ifndef DHCP_MANAGER_H
#define DHCP_MANAGER_H

#define DEFAULT_LEASE_SEC 3600
#define DEFAULT_LEASE_GRACE 300

#define DHCP_CLIENT_PORT 68

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

void handle_discover(context *ctx, dhcp_pkt *pkt);
void handle_request(context *ctx, dhcp_pkt *pkt);
void handle_release(context *ctx, dhcp_pkt *pkt);
void handle_decline(context *ctx, dhcp_pkt *pkt);
void handle_inform(context *ctx, dhcp_pkt *pkt);

#endif