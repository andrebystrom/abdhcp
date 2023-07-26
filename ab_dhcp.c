#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ab_dhcp.h"

static const uint8_t MAGIC_COOKIE[] = {99, 130, 83, 99};

static int get_option_length(dhcp_pkt *pkt)
{
    return pkt->pkt_size - PKT_STATIC_LEN;
}

static uint8_t find_dhcp_option_index(
    dhcp_pkt *pkt,
    uint8_t opt,
    uint16_t *idx,
    uint8_t *len)
{
    if (get_option_length(pkt) < sizeof MAGIC_COOKIE)
        return OPT_SEARCH_ERROR;
    if (memcmp(pkt->options, MAGIC_COOKIE, sizeof MAGIC_COOKIE) != 0)
        return OPT_SEARCH_ERROR;

    int index = sizeof MAGIC_COOKIE;
    // Continue while we have an option code and option length field.
    while (index < get_option_length(pkt) + 1 && pkt->options[index] != OPT_END)
    {
        if (pkt->options[index] == OPT_PADDING)
        {
            index++;
            continue;
        }

        int opt_len = pkt->options[index + 1];
        int opt_val_idx = index + 2;
        if (pkt->options[index] == opt)
        {
            if (opt_len <= 0 || opt_val_idx + opt_len >= get_option_length(pkt))
                return OPT_SEARCH_ERROR;
            *idx = opt_val_idx;
            *len = opt_len;
            return OPT_SEARCH_SUCCESS;
        }
        // TODO: Check for option overload option and search through
        // sname and file later if requested.
        else
        {
            if (opt_val_idx + opt_len >= get_option_length(pkt))
                return OPT_SEARCH_ERROR;
            index = opt_val_idx + opt_len;
        }
    }

    return OPT_SEARCH_ERROR;
}

static void serialize_uint32(uint8_t *dest, uint32_t data)
{
    *dest++ = data >> 24 & 0xff;
    *dest++ = data >> 16 & 0xff;
    *dest++ = data >> 8 & 0xff;
    *dest++ = data & 0xff;
}

dhcp_pkt *make_pkt(bool zero)
{
    dhcp_pkt *pkt = malloc(sizeof(dhcp_pkt));
    if (pkt == NULL)
        return NULL;

    if (zero)
    {
        memset(pkt->ch_addr, OPT_PADDING, sizeof(pkt->ch_addr));
        memset(pkt->s_name, OPT_PADDING, sizeof(pkt->s_name));
        memset(pkt->file, OPT_PADDING, sizeof(pkt->file));
        memset(pkt->options, OPT_PADDING, sizeof(pkt->options));
    }

    memcpy(pkt->options, MAGIC_COOKIE, sizeof(MAGIC_COOKIE));
    pkt->opt_write_offset_ = sizeof(MAGIC_COOKIE);
    return pkt;
}

dhcp_pkt *make_ret_pkt(dhcp_pkt *req, uint32_t yi_addr, uint32_t si_addr)
{
    dhcp_pkt *pkt = make_pkt(true);
    if (pkt == NULL)
        return NULL;
    pkt->op = PKT_OP_SEND;
    pkt->h_type = HTYPE_ETHERNET;
    pkt->h_len = ETHERNET_LEN;
    pkt->hops = 0;
    pkt->secs = req->secs;
    pkt->flags = req->flags;

    pkt->x_id = req->x_id;
    pkt->ci_addr = req->ci_addr;
    pkt->yi_addr = yi_addr;
    pkt->si_addr = si_addr;

    memcpy(pkt->ch_addr, req->ch_addr, sizeof(pkt->ch_addr));
    memset(pkt->s_name, 0, sizeof(pkt->s_name));
    memset(pkt->file, 0, sizeof(pkt->file));

    return pkt;
}

dhcp_pkt *deserialize_dhcp_pkt(uint8_t *buf, ssize_t size)
{
    if (size < PKT_STATIC_LEN)
        return NULL;
    dhcp_pkt *pkt = make_pkt(false);
    if (!pkt)
        return NULL;

    pkt->pkt_size = size;

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

    const int NUM_DESERIALIZED = 28;

    buf += NUM_DESERIALIZED;
    memcpy(pkt->ch_addr, buf, PKT_CHADDR_LEN);
    buf += PKT_CHADDR_LEN;
    memcpy(pkt->s_name, buf, PKT_SNAME_LEN);
    buf += PKT_SNAME_LEN;
    memcpy(pkt->file, buf, PKT_FILE_LEN);
    buf += PKT_FILE_LEN;

    memcpy(pkt->options, buf, size - PKT_STATIC_LEN);

    return pkt;
}

uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt)
{
    uint8_t *buf = malloc(ETHERNET_MTU);
    uint8_t *res = buf;

    *buf++ = pkt->op;
    *buf++ = pkt->h_type;
    *buf++ = pkt->h_len;
    *buf++ = pkt->hops;

    serialize_uint32(buf, pkt->x_id);
    buf += 4;

    *buf++ = pkt->secs >> 8;
    *buf++ = pkt->secs & 0xff;
    *buf++ = pkt->flags >> 8;
    *buf++ = pkt->flags & 0xff;

    serialize_uint32(buf, pkt->ci_addr);
    buf += 4;
    serialize_uint32(buf, pkt->yi_addr);
    buf += 4;
    serialize_uint32(buf, pkt->si_addr);
    buf += 4;
    serialize_uint32(buf, pkt->gi_addr);
    buf += 4;

    memcpy(buf, pkt->ch_addr, sizeof(pkt->ch_addr));
    buf += sizeof(pkt->ch_addr);
    memcpy(buf, pkt->s_name, sizeof(pkt->s_name));
    buf += sizeof(pkt->s_name);
    memcpy(buf, pkt->file, sizeof(pkt->file));
    buf += sizeof(pkt->file);
    memcpy(buf, pkt->options, sizeof(pkt->options));

    return res;
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

bool is_ethernet_dhcp_pkt(dhcp_pkt *pkt)
{
    return pkt->h_type == HTYPE_ETHERNET;
}

uint8_t get_dhcp_message_type(dhcp_pkt *pkt)
{
    uint8_t buf, ret;
    uint16_t buf_size;
    uint8_t *buf_p = &buf;
    ret = find_dhcp_option(pkt, OPT_MESSAGE_TYPE, &buf_p, &buf_size, false);
    if (ret != OPT_SEARCH_SUCCESS || buf_size != 1 || *buf_p < 1 || *buf_p > 8)
    {
        return PKT_TYPE_INVALID;
    }
    return *buf_p;
}

uint8_t get_dhcp_requested_params(dhcp_pkt *pkt, uint8_t *buf, uint16_t buf_len)
{
    uint16_t index, res;
    uint8_t len;
    uint8_t num_params = 0;

    res = find_dhcp_option_index(pkt, OPT_REQUESTED_PARAM_LIST, &index, &len);
    if (res != OPT_SEARCH_SUCCESS)
        return OPT_SEARCH_ERROR;
    for (int i = index; i < index + len && num_params < buf_len; i++)
    {
        uint8_t opt = pkt->options[i];
        if (opt == OPT_SUBNET_MASK ||
            opt == OPT_DEFAULT_ROUTER ||
            opt == OPT_DNS_SERVER)
        {
            buf[num_params++] = opt;
        }
    }
    return num_params;
}

uint8_t find_dhcp_option(
    dhcp_pkt *pkt,
    uint8_t option_code,
    uint8_t **buf,
    uint16_t *size,
    bool allocate)
{
    uint8_t opt_len;
    uint16_t index;
    uint8_t res = find_dhcp_option_index(pkt, option_code, &index, &opt_len);
    if (res != OPT_SEARCH_SUCCESS)
        return OPT_SEARCH_ERROR;

    if (allocate && (*buf = malloc(opt_len)) == NULL)
        return OPT_SEARCH_ERROR;
    memcpy(*buf, pkt->options + index, opt_len);
    *size = opt_len;

    return OPT_SEARCH_SUCCESS;
}

uint8_t add_pkt_option(
    dhcp_pkt *pkt,
    uint8_t option_code,
    uint8_t len,
    uint8_t *val)
{
    int16_t offset = pkt->opt_write_offset_;
    if (PKT_OPTION_MAX_LEN < offset + 2 + len)
        return OPT_WRITE_ERROR;
    memset(pkt->options + offset, option_code, 1);
    offset++;
    memset(pkt->options + offset, len, 1);
    offset++;
    memcpy(pkt->options + offset, val, len);
    pkt->opt_write_offset_ = offset + len;
    return OPT_WRITE_SUCCESS;
}

uint8_t add_pkt_opt_end(dhcp_pkt *pkt)
{
    uint16_t offset = pkt->opt_write_offset_;
    if (PKT_OPTION_MAX_LEN <= offset)
    {
        return OPT_WRITE_ERROR;
    }
    memset(pkt->options + offset, OPT_END, 1);
    pkt->opt_write_offset_++;
    return OPT_WRITE_SUCCESS;
}