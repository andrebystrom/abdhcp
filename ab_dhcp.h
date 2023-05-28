#ifndef AB_DHCP
#define AB_DHCP

#include <stdint.h>
#include <sys/types.h>

#define HTYPE_ETHERNET 1

typedef struct {
    uint8_t op, h_type, h_len, hops;
    uint16_t secs, flags;
    uint32_t x_id, ci_addr, yi_addr, si_addr, gi_addr;
    uint8_t ch_addr[16];
    uint8_t s_name[64];
    uint8_t file[128];
    uint8_t *options;
} dhcp_pkt;


dhcp_pkt *deserialize_dhcp_pkt(uint8_t *buf, ssize_t size);
uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt);
void free_dhcp_pkt(dhcp_pkt *pkt);
void print_dhcp_pkt(dhcp_pkt *pkt);

#endif