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
#define ATTRS_ARR_CAP 128
#define ATTR_VAL_CAP 512
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define BINDING_REQUEST 0x0001
#define MAGIC_COOKIE 0x2112A442

// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
#define __STUN_ATTR_TYPES \
    __STUN_DEF( MAPPED_ADDRESS                     , 0x0001u) \
    __STUN_DEF( XOR_MAPPED_ADDRESS                 , 0x0020u) \
    __STUN_DEF( USERNAME                           , 0x0006u) \
    __STUN_DEF( MESSAGE_INTEGRITY                  , 0x0008u) \
    __STUN_DEF( ERROR_CODE                         , 0x0009u) \
    __STUN_DEF( UNKNOWN_ATTRIBUTES                 , 0x000Au) \
    __STUN_DEF( CHANNEL_NUMBER                     , 0x000Cu) \
    __STUN_DEF( LIFETIME                           , 0x000Du) \
    __STUN_DEF( XOR_PEER_ADDRESS                   , 0x0012u) \
    __STUN_DEF( DATA                               , 0x0013u) \
    __STUN_DEF( REALM                              , 0x0014u) \
    __STUN_DEF( NONCE                              , 0x0015u) \
    __STUN_DEF( XOR_RELAYED_ADDRESS                , 0x0016u) \
    __STUN_DEF( REQUESTED_ADDRESS_FAMILY           , 0x0017u) \
    __STUN_DEF( EVEN_PORT                          , 0x0018u) \
    __STUN_DEF( REQUESTED_TRANSPORT                , 0x0019u) \
    __STUN_DEF( DONT_FRAGMENT                      , 0x001Au) \
    __STUN_DEF( ACCESS_TOKEN                       , 0x001Bu) \
    __STUN_DEF( MESSAGE_INTEGRITY_SHA256           , 0x001Cu) \
    __STUN_DEF( PASSWORD_ALGORITHM                 , 0x001Du) \
    __STUN_DEF( USERHASH                           , 0x001Eu) \
    __STUN_DEF( RESERVATION_TOKEN                  , 0x0022u) \
    __STUN_DEF( PRIORITY                           , 0x0024u) \
    __STUN_DEF( USE_CANDIDATE                      , 0x0025u) \
    __STUN_DEF( PADDING                            , 0x0026u) \
    __STUN_DEF( RESPONSE_PORT                      , 0x0027u) \
    __STUN_DEF( CONNECTION_ID                      , 0x002Au) \
    __STUN_DEF( ADDITIONAL_ADDRESS_FAMILY          , 0x8000u) \
    __STUN_DEF( ADDRESS_ERROR_CODE                 , 0x8001u) \
    __STUN_DEF( PASSWORD_ALGORITHMS                , 0x8002u) \
    __STUN_DEF( ALTERNATE_DOMAIN                   , 0x8003u) \
    __STUN_DEF( ICMP                               , 0x8004u) \
    __STUN_DEF( SOFTWARE                           , 0x8022u) \
    __STUN_DEF( ALTERNATE_SERVER                   , 0x8023u) \
    __STUN_DEF( TRANSACTION_TRANSMIT_COUNTER       , 0x8025u) \
    __STUN_DEF( CACHE_TIMEOUT                      , 0x8027u) \
    __STUN_DEF( FINGERPRINT                        , 0x8028u) \
    __STUN_DEF( ICE_CONTROLLED                     , 0x8029u) \
    __STUN_DEF( ICE_CONTROLLING                    , 0x802Au) \
    __STUN_DEF( RESPONSE_ORIGIN                    , 0x802Bu) \
    __STUN_DEF( OTHER_ADDRESS                      , 0x802Cu) \
    __STUN_DEF( ECN_CHECK_STUN                     , 0x802Du) \
    __STUN_DEF( THIRD_PARTY_AUTHORIZATION          , 0x802Eu) \
    __STUN_DEF( MOBILITY_TICKET                    , 0x8030u) \
    __STUN_DEF( CISCO_STUN_FLOWDATA                , 0xC000u) \
    __STUN_DEF( ENF_FLOW_DESCRIPTION               , 0xC001u) \
    __STUN_DEF( ENF_NETWORK_STATUS                 , 0xC002u) \
    __STUN_DEF( CISCO_WEBEX_FLOW_INFO              , 0xC003u) \
    __STUN_DEF( CITRIX_TRANSACTION_ID              , 0xC056u) \
    __STUN_DEF( GOOG_NETWORK_INFO                  , 0xC057u) \
    __STUN_DEF( GOOG_LAST_ICE_CHECK_RECEIVED       , 0xC058u) \
    __STUN_DEF( GOOG_MISC_INFO                     , 0xC059u) \
    __STUN_DEF( GOOG_OBSOLETE_1                    , 0xC05Au) \
    __STUN_DEF( GOOG_CONNECTION_ID                 , 0xC05Bu) \
    __STUN_DEF( GOOG_DELTA                         , 0xC05Cu) \
    __STUN_DEF( GOOG_DELTA_ACK                     , 0xC05Du) \
    __STUN_DEF( GOOG_DELTA_SYNC_REQ                , 0xC05Eu) \
    __STUN_DEF( GOOG_MESSAGE_INTEGRITY_32          , 0xC060u) \
    __STUN_DEF( META_DTLS_IN_STUN                  , 0xC070u) \
    __STUN_DEF( META_DTLS_IN_STUN_ACKNOWLEDGEMENT  , 0xC071u)

#define __STUN_DEF(k,v) const uint16_t STUN_ATTR_##k = v;
__STUN_ATTR_TYPES
#undef __STUN_DEF

const char* STUN_ATTR_TYPE_NAMES[] = {
#define __STUN_DEF(k,v) #k,
__STUN_ATTR_TYPES
#undef __STUN_DEF
};

const uint16_t STUN_ATTR_TYPES[] = {
#define __STUN_DEF(k,v) v,
__STUN_ATTR_TYPES
#undef __STUN_DEF
};

#define STUN_ATTR_TYPES_LEN (sizeof(STUN_ATTR_TYPES)/sizeof(*STUN_ATTR_TYPES))

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
    STUN_ADDRESS_FAMILY_IPV4 = 0x01u,
    STUN_ADDRESS_FAMILY_IPV6 = 0x02u,
} Stun_Address_Family;

typedef struct {
    Stun_Address_Family family;
    uint32_t port;
    uint32_t address[4];
} Stun_Attr_Mapped_Address;

ssize_t                  stun_attr_type_find_idx(uint16_t);
Stun_Attr_Mapped_Address stun_xor_mapped_address_decode(Stun_Attr, uint32_t tid[TID_LEN]);
Stun_Attr_Mapped_Address stun_mapped_address_decode(Stun_Attr);
Stun_Attr_Arr            stun_response_attrs_decode(uint8_t *, uint16_t);
Stun_Response_Header     stun_response_header_decode(uint8_t *, size_t);
Stun_Message_Header      stun_binding_request_new();

#ifdef STUN_H_IMPLEMENTATION
static void gen_tid(size_t len, uint32_t tid[len])
{
    for (size_t i = 0; i < len; ++i) {
        tid[i] = htonl(rand());
    }
}

Stun_Attr_Mapped_Address stun_xor_mapped_address_decode(Stun_Attr attr, uint32_t tid[TID_LEN])
{
    Stun_Attr_Mapped_Address addr = {0};

    uint8_t *val = attr.val;
    assert(attr.len >= 4 + 4);
    uint32_t ma_header = ntohl(*(uint32_t *)val);

    uint32_t family = (ma_header >> 16) & 0xFF;
    uint32_t xport = (ma_header >> 0) & 0xFFFF;
    uint32_t port = xport ^ (MAGIC_COOKIE >> 16);

    val += 4;

    addr.family = family;
    addr.port = port;
    addr.address[0] = ntohl(*((uint32_t *)val)) ^ MAGIC_COOKIE;
    val += 4;

    if (family == 0x02) {
        assert(attr.len >= 4 + 4 + 4 * 3);

        // assuming that the transaction id is in network byte order
        addr.address[1] = ntohl(*((uint32_t *)val)) ^ ntohl(tid[0]);
        val += 4;
        addr.address[2] = ntohl(*((uint32_t *)val)) ^ ntohl(tid[1]);
        val += 4;
        addr.address[3] = ntohl(*((uint32_t *)val)) ^ ntohl(tid[2]);
        val += 4;
    }

    return addr;
}

Stun_Attr_Mapped_Address stun_mapped_address_decode(Stun_Attr attr)
{
    Stun_Attr_Mapped_Address addr = {0};

    uint8_t *val = attr.val;
    uint32_t ma_header = ntohl(*(uint32_t *)val);

    uint32_t family = (ma_header >> 16) & 0xFF;
    uint32_t port = (ma_header >> 0) & 0xFFFF;
    val += 4;

    addr.family = family;
    addr.port = port;
    addr.address[0] = ntohl(*(uint32_t *)val);
    val += 4;

    if (family == 0x02) {
        assert(attr.len >= 4 + 4 + 4 * 3);

        addr.address[1] = ntohl(*((uint32_t *)val));
        val += 4;
        addr.address[2] = ntohl(*((uint32_t *)val));
        val += 4;
        addr.address[3] = ntohl(*((uint32_t *)val));
        val += 4;
    }

    return addr;
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


ssize_t stun_attr_type_find_idx(uint16_t t)
{
    for (size_t i = 0; i < STUN_ATTR_TYPES_LEN; ++i) {
        if (t == STUN_ATTR_TYPES[i]) {
            return i;
        }
    }

    return -1;
}

#endif // STUN_H_IMPLEMENTATION
