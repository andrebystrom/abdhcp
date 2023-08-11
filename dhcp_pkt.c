/*
* Summary: dhcp_pkt serialization/deserialization and general utility functions 
* for interacting with the dhcp_pkt.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dhcp_pkt.h"

static const uint8_t MAGIC_COOKIE[] = {99, 130, 83, 99};

static int get_option_length(dhcp_pkt *pkt)
{
    return pkt->pkt_size - PKT_STATIC_LEN;
}

/// @brief Find the start index for the value of an option.
/// @param pkt the packet to search.
/// @param opt the opt to search for.
/// @param idx the index to set.
/// @param len the length of the option value.
/// @return the index on succes, or 0 on failure.
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

/// @brief Serializes a uint32_t into dest.
/// @param dest the destination buffer of length at least 4.
/// @param data the data to serialize.
static void serialize_uint32(uint8_t *dest, uint32_t data)
{
    *dest++ = data >> 24 & 0xff;
    *dest++ = data >> 16 & 0xff;
    *dest++ = data >> 8 & 0xff;
    *dest++ = data & 0xff;
}

/// @brief Serializes a uint16_t into dest.
/// @param dest the destination buffer of length at least 2.
/// @param data the data to serialize.
static void serialize_uint16(uint8_t *dest, uint16_t data)
{
    *dest++ = data >> 8 & 0xff;
    *dest = data & 0xff;
}

/// @brief Deserializes a uint32_t into host byte order.
/// @param data the data to deserialize.
/// @return the deserialized data.
static uint32_t deserialize_uint32(uint8_t *data)
{
    uint32_t res;
    memcpy(&res, data, sizeof(uint32_t));
    return ntohl(res);
}

/// @brief Deserializes a uint16_t into host byte order.
/// @param data the data to deserialize.
/// @return the deserialized data.
static uint16_t deserialize_uint16(uint8_t *data)
{
    uint16_t res;
    memcpy(&res, data, sizeof(uint16_t));
    return ntohs(res);
}

/// @brief allocates and initializes a dhcp_pkt.
/// @param zero set the ch_addr, s_name, file and options to 0.
/// @return the packet, or NULL on alloc fail.
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

/// @brief Makes a return packet from a request.
/// @param req the dhcp request.
/// @param yi_addr the address for the client.
/// @param si_addr the server address.
/// @return 
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
    pkt->ci_addr = 0;
    pkt->yi_addr = yi_addr;
    pkt->si_addr = si_addr;
    pkt->gi_addr = 0;

    memcpy(pkt->ch_addr, req->ch_addr, sizeof(pkt->ch_addr));
    memset(pkt->s_name, 0, sizeof(pkt->s_name));
    memset(pkt->file, 0, sizeof(pkt->file));

    return pkt;
}

/// @brief Deserializes a dhcp_pkt.
/// @param buf the buffer to deserialize.
/// @param size the size of the buffer.
/// @return 
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

    pkt->x_id = deserialize_uint32(buf + 4);
    pkt->secs = deserialize_uint16(buf + 8);
    pkt->flags = deserialize_uint16(buf + 10);
    pkt->ci_addr = deserialize_uint32(buf + 12);
    pkt->yi_addr = deserialize_uint32(buf + 16);
    pkt->si_addr = deserialize_uint32(buf + 20);
    pkt->gi_addr = deserialize_uint32(buf + 24);

    const int NUM_DESERIALIZED = 28;

    buf += NUM_DESERIALIZED;
    memcpy(pkt->ch_addr, buf, PKT_CHADDR_LEN);
    buf += PKT_CHADDR_LEN;
    memcpy(pkt->s_name, buf, PKT_SNAME_LEN);
    buf += PKT_SNAME_LEN;
    memcpy(pkt->file, buf, PKT_FILE_LEN);
    buf += PKT_FILE_LEN;

    memcpy(pkt->options, buf, size - PKT_STATIC_LEN);
    pkt->opt_write_offset_ = size - PKT_STATIC_LEN;

    return pkt;
}

/// @brief Serializes a dhcp_pkt.
/// @param pkt the pkt to serialize.
/// @param size the size of the returned buffer.
/// @return the serialized packet, or null on fail.
uint8_t *serialize_dhcp_pkt(dhcp_pkt *pkt, uint32_t *size)
{
    *size = pkt->opt_write_offset_ + PKT_STATIC_LEN;
    uint8_t *buf = malloc(*size);
    if(buf == NULL)
        return NULL;
    uint8_t *res = buf;

    *buf++ = pkt->op;
    *buf++ = pkt->h_type;
    *buf++ = pkt->h_len;
    *buf++ = pkt->hops;

    serialize_uint32(buf, pkt->x_id);
    buf += 4;

    serialize_uint16(buf, pkt->secs);
    buf += 2;
    serialize_uint16(buf, pkt->secs);
    buf += 2;

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
    memcpy(buf, pkt->options, pkt->opt_write_offset_);

    return res;
}

/// @brief Frees a dhcp_pkt.
/// @param pkt the pkt to free.
void free_dhcp_pkt(dhcp_pkt *pkt)
{
    free(pkt);
}

/// @brief Prints a dhcp_pkt.
/// @param pkt the pkt to print.
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

/// @brief Checks if a dhcp_pkt is using ethernet hardware type.
/// @param pkt the pkt to check.
/// @return true if ethernet htype, false otherwise.
bool is_ethernet_dhcp_pkt(dhcp_pkt *pkt)
{
    return pkt->h_type == HTYPE_ETHERNET;
}

/// @brief Gets the dhcp message type.
/// @param pkt the pkt to check.
/// @return the pkt type, or PKT_TYPE_INVALID if non-valid value is given.
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

/// @brief Gets the requested parameters from the packet and stores them in buf.
/// @param pkt the packet to check.
/// @param buf the buffer to store results into.
/// @param buf_len the length of the buffer.
/// @return the number of requested params added to buf.
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

/// @brief Get the max message size of the dhcp_pkt.
/// @param pkt the pkt to check.
/// @return the max message size, or 0 on fail.
uint32_t get_max_message_size(dhcp_pkt *pkt)
{
    uint16_t idx;
    uint8_t opt_len;
    uint8_t expected_len = 2;
    uint32_t res = OPT_SEARCH_ERROR;
    uint8_t *opt_val;

    if (find_dhcp_option_index(pkt, OPT_MAX_MESSAGE_SIZE,
                               &idx, &opt_len) == OPT_SEARCH_ERROR ||
        opt_len != expected_len)
        return OPT_SEARCH_ERROR;
    if (idx + opt_len >= pkt->pkt_size - PKT_STATIC_LEN)
    {
        return OPT_SEARCH_ERROR;
    }

    opt_val = pkt->options + idx;
    res = deserialize_uint16(opt_val);

    return res;
}

/// @brief Finds a dhcp option and stores its value in buf.
/// @param pkt the pkt to check.
/// @param option_code the option to search for.
/// @param buf the buf to place the option value in.
/// @param size the size of the option (set by function.)
/// @param allocate true if the buffer should be allocated by the function.
/// @return 
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

/// @brief Adds an option to a dhcp_pkt.
/// @param pkt the pkt to add to.
/// @param option_code the option code.
/// @param len the option length.
/// @param val the option value.
/// @return 0 on fail, 1 on success.
uint8_t add_pkt_option(
    dhcp_pkt *pkt,
    uint8_t option_code,
    uint8_t len,
    uint8_t *val)
{
    int16_t offset = pkt->opt_write_offset_;
    if (PKT_OPTION_MAX_LEN < offset + 2 + len)
        return OPT_WR_ERROR;
    memset(pkt->options + offset, option_code, 1);
    offset++;
    memset(pkt->options + offset, len, 1);
    offset++;
    memcpy(pkt->options + offset, val, len);
    pkt->opt_write_offset_ = offset + len;
    return OPT_WR_SUCCESS;
}

/// @brief Adds the end option to a dhcp_pkt.
/// @param pkt the pkt to add to.
/// @return 0 on fail, 1 on success.
uint8_t add_pkt_opt_end(dhcp_pkt *pkt)
{
    uint16_t offset = pkt->opt_write_offset_;
    if (PKT_OPTION_MAX_LEN <= offset)
    {
        return OPT_WR_ERROR;
    }
    memset(pkt->options + offset, OPT_END, 1);
    pkt->opt_write_offset_++;
    return OPT_WR_SUCCESS;
}

/// @brief Overwrites a dhcp option with padding.
/// @param pkt the pkt to write to.
/// @param opt the opt to overwrite.
/// @return 0 on fail, 1 on success.
uint8_t overwrite_opt_with_pad(dhcp_pkt *pkt, uint8_t opt)
{
    uint16_t idx;
    uint8_t opt_len;
    if (find_dhcp_option_index(pkt, opt, &idx, &opt_len) == OPT_SEARCH_ERROR)
        return OPT_WR_ERROR;

    // We want to overwrite the opt and opt len specifiers as well.
    if (idx < 2 || idx + opt_len - 1 > pkt->pkt_size - PKT_STATIC_LEN)
    {
        return OPT_WR_ERROR;
    }
    idx = idx - 2;
    memset(pkt->options + idx, OPT_PADDING, opt_len + 2);
    return OPT_WR_SUCCESS;
}