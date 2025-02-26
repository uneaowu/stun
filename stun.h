#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TID_LEN 3
#define BINDING_REQUEST 0x0001
#define MAGIC_COOKIE 0x2112A442
#define MAPPED_ADDRESS 0x0001
#define XOR_MAPPED_ADDRESS 0x0020
#define ATTRS_ARR_CAP 128
#define ATTR_VAL_CAP 512
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t cookie;
    uint32_t tid[TID_LEN];
} Stun_Message_Header;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t cookie;
    uint32_t tid[TID_LEN];
} Stun_Response_Header;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t val[ATTR_VAL_CAP];
} Stun_Attr;

typedef struct {
    Stun_Attr arr[ATTRS_ARR_CAP];
    size_t len;
} Stun_Attr_Arr;

typedef enum {
    Stun_Mapped_Address_Family_IPV4 = 0x01u,
    Stun_Mapped_Address_Family_IPV6 = 0x02u,
} Stun_Mapped_Address_Family;

typedef struct {
    Stun_Mapped_Address_Family family;
    uint32_t port;
    uint32_t address; // TODO: add support for 128-bit addresses
} Stun_Attr_Mapped_Address;

Stun_Attr_Mapped_Address stun_xor_mapped_address_decode(Stun_Attr);
Stun_Attr_Mapped_Address stun_mapped_address_decode(Stun_Attr);
Stun_Attr_Arr            stun_response_attrs_decode(uint8_t *, uint16_t);
Stun_Response_Header     stun_response_header_decode(uint8_t *, size_t);
Stun_Message_Header      stun_binding_request_new();

#ifdef STUN_H_IMPLEMENTATION
#define UNIMPLEMENTED(msg) do { \
    fprintf(stderr, "error: not implemented "msg"\n"); \
    exit(EXIT_FAILURE); \
} while (0)

static void gen_tid(size_t len, uint32_t tid[len])
{
    for (size_t i = 0; i < len; ++i) {
        tid[i] = htonl(rand());
    }
}

Stun_Attr_Mapped_Address stun_xor_mapped_address_decode(Stun_Attr attr)
{
    uint8_t *val = attr.val;
    uint32_t ma_header = ntohl(*(uint32_t *)val);

    uint32_t family = (ma_header >> 16) & 0xFF;
    if (family == 0x02) { UNIMPLEMENTED("ipv6"); }

    uint32_t xport = (ma_header >> 0) & 0xFFFF;
    uint32_t port = xport ^ (MAGIC_COOKIE >> 16);

    val += 4;
    uint32_t xaddress = ntohl(*(uint32_t *)val);
    uint32_t address = xaddress ^ MAGIC_COOKIE;

    return (Stun_Attr_Mapped_Address) {
        .family = family,
        .port = port,
        .address = address,
    };
}

Stun_Attr_Mapped_Address stun_mapped_address_decode(Stun_Attr attr)
{
    uint8_t *val = attr.val;
    uint32_t ma_header = ntohl(*(uint32_t *)val);

    uint32_t family = (ma_header >> 16) & 0xFF;
    if (family == 0x02) { UNIMPLEMENTED("ipv6"); }

    uint32_t port = (ma_header >> 0) & 0xFFFF;
    val += 4;

    uint32_t address = ntohl(*(uint32_t *)val);

    return (Stun_Attr_Mapped_Address) {
        .family = family,
        .port = port,
        .address = address,
    };
}

Stun_Attr_Arr stun_response_attrs_decode(uint8_t *rbuf, uint16_t rlen)
{
    Stun_Attr_Arr attr_arr = {0};
    uint8_t *attrs = rbuf + sizeof(Stun_Response_Header);
    uint8_t *attrs_end = attrs + rlen;

    while (attrs < (attrs_end - 4)) {
        assert(attr_arr.len < ATTRS_ARR_CAP);

        uint16_t type = ntohs(*(uint16_t *)attrs);
        attrs += 2;

        uint16_t len = ntohs(*(uint16_t *)attrs);
        attrs += 2;

        if ((attrs+len) > attrs_end) {
            continue;
        }

        size_t idx = attr_arr.len++;
        Stun_Attr *attr = &attr_arr.arr[idx];

        attr->type = type;
        attr->len = len;

        assert(attr->len <= ATTR_VAL_CAP);
        memcpy(attr->val, attrs, attr->len);

        attrs += attr->len;
    }

    return attr_arr;
}

Stun_Response_Header stun_response_header_decode(uint8_t *rbuf, size_t rlen)
{
    Stun_Response_Header r = {0};
    memcpy(&r, rbuf, MIN(rlen, sizeof(Stun_Response_Header)));

    r.type = ntohs(r.type);
    r.len = ntohs(r.len);
    r.cookie = ntohl(r.cookie);

    return r;
}

Stun_Message_Header stun_binding_request_new(void)
{
    Stun_Message_Header h = {0};

    h.type = htons(BINDING_REQUEST);
    h.cookie = htonl(MAGIC_COOKIE);
    gen_tid(TID_LEN, h.tid);

    return h;
}
#endif // STUN_H_IMPLEMENTATION
