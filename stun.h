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
#define ATTRS_ARR_CAP 32
#define ATTR_VAL_CAP 32
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

uint32_t unpack_xor_mapped_address(Stun_Attr);
uint32_t unpack_mapped_address(Stun_Attr);
void decode_response_attrs(Stun_Attr_Arr *, uint8_t *, uint16_t); // TODO: consider moving out the struct
void decode_response_header(Stun_Response_Header *, uint8_t *, size_t);
void make_binding_request(Stun_Message_Header *);

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

uint32_t unpack_xor_mapped_address(Stun_Attr attr)
{
    uint8_t *val = attr.val;
    uint32_t ma_header = ntohl(*(uint32_t *)val);

    uint32_t family = (ma_header >> 16) & 0xFF;
    if (family == 0x02) { UNIMPLEMENTED("ipv6"); }

    uint32_t xport = (ma_header >> 0) & 0xFFFF;
    uint32_t port = xport ^ (MAGIC_COOKIE >> 16);
    (void) port;

    val += 4;
    uint32_t xlong_ip = ntohl(*(uint32_t *)val);
    return xlong_ip ^ MAGIC_COOKIE;
}

uint32_t unpack_mapped_address(Stun_Attr attr)
{
    uint8_t *val = attr.val;
    uint32_t ma_header = ntohl(*(uint32_t *)val);
    uint32_t family = (ma_header >> 16) & 0xFF;
    if (family == 0x02) { UNIMPLEMENTED("ipv6"); }

    uint32_t port = (ma_header >> 0) & 0xFFFF;
    (void) port;
    val += 4;
    return ntohl(*(uint32_t *)val);
}

void decode_response_attrs(Stun_Attr_Arr *attr_arr, uint8_t *rbuf, uint16_t rlen)
{
    uint8_t *attrs = rbuf + sizeof(Stun_Response_Header);
    uint8_t *attrs_end = attrs + rlen;

    while (attrs < attrs_end) {
        assert(attr_arr->len < ATTRS_ARR_CAP);

        uint16_t type = ntohs(*(uint16_t *)attrs);
        attrs += 2;

        uint16_t len = ntohs(*(uint16_t *)attrs);
        attrs += 2;

        size_t idx = attr_arr->len++;
        Stun_Attr *attr = &attr_arr->arr[idx];

        attr->type = type;
        attr->len = len;

        assert(attr->len <= ATTR_VAL_CAP);
        memcpy(attr->val, attrs, attr->len);

        attrs += attr->len;
    }
}

void decode_response_header(Stun_Response_Header *r,
                    uint8_t *rbuf, size_t rlen)
{
    memset(r, 0, sizeof(Stun_Response_Header));
    memcpy(r, rbuf, MIN(rlen, sizeof(Stun_Response_Header)));

    r->type = ntohs(r->type);
    r->len = ntohs(r->len);
    r->cookie = ntohl(r->cookie);
}

void make_binding_request(Stun_Message_Header *sm)
{
    memset(sm, 0, sizeof(Stun_Message_Header));

    sm->type = htons(BINDING_REQUEST);
    sm->cookie = htonl(MAGIC_COOKIE);
    gen_tid(TID_LEN, sm->tid);
}
#endif // STUN_H_IMPLEMENTATION
