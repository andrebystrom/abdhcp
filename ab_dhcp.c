#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ab_dhcp.h"

dhcp_pkt *deserialize_dhcp_pkt(uint8_t *buf, ssize_t size)
{
    if (size <= 0)
        return NULL;
    dhcp_pkt *pkt = malloc(sizeof(dhcp_pkt));
    if (!pkt)
        return NULL;

    pkt->op = buf[0];
    pkt->h_type = buf[1];
    pkt->h_len = buf[2];
    pkt->hops = buf[3];

    pkt->x_id = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
    pkt->secs = buf[8] << 8 | buf[9];
    pkt->flags = buf[10] << 8 | buf[11];
    pkt->ci_addr = buf[12] << 24 | buf[13] << 16 | buf[14] << 8 | buf[15];
    pkt->yi_addr = buf[16] << 24 | buf[17] << 16 | buf[18] << 8 | buf[19];
    pkt->si_addr = buf[20] << 24 | buf[21] << 16 | buf[22] << 8 | buf[23];
    pkt->gi_addr = buf[24] << 24 | buf[25] << 16 | buf[26] << 8 | buf[27];

    buf += 28;
    memcpy(pkt->ch_addr, buf, 16);
    buf += 16;
    memcpy(pkt->s_name, buf, 64);
    buf += 64;
    memcpy(pkt->file, buf, 128);
    buf += 128;

    uint8_t *opts = malloc(size - 236);
    memcpy(opts, buf, size - 236);

    return pkt;
}

uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt)
{
    return NULL;
}

void free_dhcp_pkt(dhcp_pkt *pkt)
{
    free(pkt);
}

void print_dhcp_pkt(dhcp_pkt *pkt)
{
    struct in_addr ip_addr;

    printf("op=%u htype=%u hlen=%u hops=%u\n",
           pkt->op, pkt->h_type, pkt->h_len, pkt->hops);
    printf("xid=%u\n", pkt->x_id);
    printf("secs=%u broadcast=%u\n", pkt->secs, pkt->flags);

    memcpy(&ip_addr.s_addr, &pkt->ci_addr, 4);
    printf("ci=%s\n", inet_ntoa(ip_addr));

    memcpy(&ip_addr.s_addr, &pkt->yi_addr, 4);
    printf("yi=%s\n", inet_ntoa(ip_addr));

    memcpy(&ip_addr.s_addr, &pkt->si_addr, 4);
    printf("si=%s\n", inet_ntoa(ip_addr));

    memcpy(&ip_addr.s_addr, &pkt->gi_addr, 4);
    printf("gi=%s\n", inet_ntoa(ip_addr));

    if (pkt->h_type == HTYPE_ETHERNET)
    {
        printf("chaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
               pkt->ch_addr[0], pkt->ch_addr[1], pkt->ch_addr[2],
               pkt->ch_addr[3], pkt->ch_addr[4], pkt->ch_addr[5]);
    }
    else
    {
        printf("chaddr=unknown\n");
    }
    
    printf("sname=%s\n",
        (pkt->s_name[0] != '\0') ? (char *)pkt->s_name : "none");
    printf("file=%s\n\n",
        (pkt->file[0] != '\0') ? (char *)pkt->file : "none");
}