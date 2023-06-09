#ifndef CORE_H
#define CORE_H

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

#include "ab_dhcp.h"

typedef enum
{
    OFFERED,
    COMMITED
} client_state;

typedef struct
{
    uint8_t ethernet_address[ETHERNET_LEN];
    struct in_addr offered_address;
    client_state state;
    uint8_t *identifier;
    uint8_t id_len;
} client;

typedef struct
{
    int srv_socket;
    struct in_addr srv_address;
    bool debug;

    // CLI supplied options.
    struct in_addr start_address;
    struct in_addr end_address;
    struct in_addr mask;
    struct in_addr *gateway;
    struct in_addr *dns_server;

    client **clients;
    int num_clients;
} context;

#endif