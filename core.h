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
    time_t lease_start;
    time_t lease_end;
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

    // keep track of bound clients;
    client **clients; // Sorted from smallest to largest address.
    int num_clients; // Number of bound clients.
    uint32_t host_offset; // The host offset to start finding addresses from.
} context;

#endif