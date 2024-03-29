#ifndef DHCP_PKT_H
#define DHCP_PKT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define HTYPE_ETHERNET 1

#define ETHERNET_MTU 1500
#define ETHERNET_LEN 6

#define PKT_OP_RECV        1
#define PKT_OP_SEND        2
#define PKT_CHADDR_LEN     16
#define PKT_SNAME_LEN      64
#define PKT_FILE_LEN       128
#define PKT_STATIC_LEN     236
#define PKT_OPTION_MAX_LEN (ETHERNET_MTU - PKT_STATIC_LEN)

#define PKT_TYPE_DISCOVER 1
#define PKT_TYPE_OFFER    2
#define PKT_TYPE_REQUEST  3
#define PKT_TYPE_DECLINE  4
#define PKT_TYPE_ACK      5
#define PKT_TYPE_NAK      6
#define PKT_TYPE_RELEASE  7
#define PKT_TYPE_INFORM   8
#define PKT_TYPE_INVALID  0 // anything not in [1, 8] is invalid.

#define OPT_SEARCH_ERROR   0
#define OPT_SEARCH_SUCCESS 1

#define OPT_WR_ERROR OPT_SEARCH_ERROR
#define OPT_WR_SUCCESS OPT_SEARCH_SUCCESS

#define OPT_PADDING              0
#define OPT_SUBNET_MASK          1
#define OPT_DEFAULT_ROUTER       3
#define OPT_DNS_SERVER           6
#define OPT_END                  255
#define OPT_MESSAGE_TYPE         53
#define OPT_MESSAGE_TYPE_OFFER   2
#define OPT_MESSAGE_TYPE_ACK     5
#define OPT_REQUESTED_PARAM_LIST 55
#define OPT_IDENTIFIER           61
#define OPT_SERVER_IDENTIFIER    54
#define OPT_LEASE_TIME           51
#define OPT_REQUESTED_IP         50
#define OPT_MAX_MESSAGE_SIZE     57

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

    // Internal flags.
    int16_t opt_write_offset_;
} dhcp_pkt;

dhcp_pkt *make_pkt(bool zero);
dhcp_pkt *make_ret_pkt(dhcp_pkt *req, uint32_t yi_addr, uint32_t si_addr);
dhcp_pkt *deserialize_dhcp_pkt(uint8_t *buf, ssize_t size);
uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt, uint32_t *size);
void free_dhcp_pkt(dhcp_pkt *pkt);
void print_dhcp_pkt(dhcp_pkt *pkt);
bool is_ethernet_dhcp_pkt(dhcp_pkt *pkt);
uint8_t get_dhcp_message_type(dhcp_pkt *pkt);
uint8_t get_dhcp_requested_params(dhcp_pkt *pkt, uint8_t *buf, uint16_t len);
uint32_t get_max_message_size(dhcp_pkt *pkt);
uint8_t find_dhcp_option(
    dhcp_pkt *pkt,
    uint8_t option_code,
    uint8_t **buf,
    uint16_t *size,
    bool allocate);
uint8_t add_pkt_option(
    dhcp_pkt *pkt,
    uint8_t option_code,
    uint8_t len,
    uint8_t *val);
uint8_t add_pkt_opt_end(dhcp_pkt *pkt);
uint8_t overwrite_opt_with_pad(dhcp_pkt *pkt, uint8_t opt);

#endif