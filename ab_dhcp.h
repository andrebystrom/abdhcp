#ifndef AB_DHCP
#define AB_DHCP

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define HTYPE_ETHERNET 1

#define ETHERNET_MTU 1500

#define PKT_CHADDR_LEN 16
#define PKT_SNAME_LEN 64
#define PKT_FILE_LEN 128
#define PKT_STATIC_LEN 236
#define PKT_OPTION_MAX_LEN (ETHERNET_MTU - PKT_STATIC_LEN)

typedef struct
{
    uint8_t op, h_type, h_len, hops;
    uint16_t secs, flags;
    uint32_t x_id, ci_addr, yi_addr, si_addr, gi_addr;
    uint8_t ch_addr[PKT_CHADDR_LEN];
    uint8_t s_name[PKT_SNAME_LEN];
    uint8_t file[PKT_FILE_LEN];
    uint8_t options[PKT_OPTION_MAX_LEN];
    ssize_t pkt_size;
} dhcp_pkt;

dhcp_pkt *deserialize_dhcp_pkt(uint8_t *buf, ssize_t size);
uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt);
void free_dhcp_pkt(dhcp_pkt *pkt);
void print_dhcp_pkt(dhcp_pkt *pkt);
bool is_ethernet_dhcp_pkt(dhcp_pkt *pkt);

#endif