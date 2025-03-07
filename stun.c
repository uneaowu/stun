#define STUN_H_IMPLEMENTATION
#include "./stun.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define SOCKET_TIMEOUT 2.
#define MAX_ATTEMPTS 10
#define UNUSED(v) (void)(v)

#define FLAG_POLL "--poll"
#define FLAG_POLL_SLEEP "--poll-sleep="
#define FLAG_DUMP_ATTRS "--dump-attrs"

//#define PRINT_RESPONSE_ORIGIN
//#define PRINT_SOFTWARE
//#define PRINT_OTHER_ADDRESS
//

#define QUOTE(name) #name
#define STR(m) QUOTE(m)

#define PANIC(msg) do { \
    fprintf(stderr, "error: %s\n", (msg)); \
    exit(EXIT_FAILURE); \
} while (0)

static char *arg_shift(int *argc, char** argv[])
{
    if (argc <= 0) {
        return NULL;
    }
    char * v = **argv;
    *argv += 1;
    *argc -= 1;

    return v;
}

static int tid_cmp(uint32_t *tid1, uint32_t *tid2, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (tid1[i] != tid2[i]) {
            return 1;
        }
    }

    return 0;
}

static int await_sock(int rsock, int wsock, double timeout)
{
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    if (rsock > 0) {
        FD_SET(rsock, &rfds);
    }

    if (wsock > 0) {
        FD_SET(wsock, &wfds);
    }

    struct timeval tv;

    tv.tv_sec = (int)timeout; tv.tv_usec = (int)((timeout-(int)timeout)*1e6);
    int sret = select(MAX(rsock, wsock)+1, &rfds, &wfds, NULL, &tv);
    if (sret == -1) {
        perror("select");
        exit(EXIT_FAILURE);
    } else if (sret < 1) {
        return -1;
    }

    return 0;
}

static ssize_t recv_with_timeout(int sockfd, uint8_t **buf, size_t bufsize, double timeout)
{
    if (await_sock(sockfd, 0, timeout) != 0) {
        return 0;
    }

    return recv(sockfd, buf, bufsize, 0);
}

static ssize_t send_with_timeout(int sockfd, void *sm, size_t smsize, double timeout)
{
    if (await_sock(0, sockfd, timeout) != 0) {
        return 0;
    }

    return send(sockfd, sm, smsize, 0);
}

Stun_Attr_Address find_any_address_attr(Stun_Attr_Arr attr_arr, uint32_t tid[TID_LEN])
{
    Stun_Attr_Address xor_addr_attr = {0}, addr_attr = {0};

    for (size_t i = 0; i < attr_arr.len; ++i) {
        Stun_Attr *attr = &attr_arr.arr[i];
        if (attr->type == STUN_ATTR_XOR_MAPPED_ADDRESS) {
             xor_addr_attr = stun_xor_mapped_address_decode(*attr, tid);
        } else if (attr->type == STUN_ATTR_MAPPED_ADDRESS) {
            addr_attr = stun_mapped_address_decode(*attr);
        }
    }

    if (xor_addr_attr.family > 0) {
        return xor_addr_attr;
    }

    if (addr_attr.family > 0) {
        return addr_attr;
    }

    fprintf(stderr, "error: no address attribute found\n");
    exit(EXIT_FAILURE);
}

Stun_Attr * find_attr_of_type(Stun_Attr_Arr *attr_arr, uint16_t type)
{
    for (size_t i = 0; i < attr_arr->len; ++i) {
        if (attr_arr->arr[i].type == type) {
            return attr_arr->arr + i;
        }
    }

    return NULL;
}

int conn_init(const char* host, const char* port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ALL;
    hints.ai_protocol = 0;

    int ai_ret = getaddrinfo(host, port, &hints, &result);
    if (ai_ret != 0) {
        fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(ai_ret));
        exit(EXIT_FAILURE);
    }

    int s;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol))  == -1) {
            continue;
        }

        if (connect(s, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }

        close(s);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        fprintf(stderr, "error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    return s;
}

void print_ipv4(uint32_t ip)
{
    printf("%d.%d.%d.%d",
            (ip >> 8*3) & 0xFF,
            (ip >> 8*2) & 0xFF,
            (ip >> 8*1) & 0xFF,
            (ip >> 8*0) & 0xFF);
}

void print_ipv6(uint32_t ip[4])
{
    char str[8*8+1];

    snprintf(str, sizeof(str), "%x:%x:%x:%x:%x:%x:%x:%x",
        (ip[0] >> 8) & 0xFF,
        (ip[0] >> 0) & 0xFF,

        (ip[1] >> 8) & 0xFF,
        (ip[1] >> 0) & 0xFF,

        (ip[2] >> 8) & 0xFF,
        (ip[2] >> 0) & 0xFF,

        (ip[3] >> 8) & 0xFF,
        (ip[3] >> 0) & 0xFF
    );

    char s_str[sizeof(str)];
    size_t ss_len = 0;

    for (size_t i = 0; i < sizeof(str); ++i) {
        for (; i < sizeof(str) && str[i] == '0'; ++i) {}

        if (str[i] == ':' && ss_len > 1 && s_str[ss_len-1] == ':' && s_str[ss_len-2] == ':') {
            continue;
        }

        s_str[ss_len++] = str[i];
    }

    printf("%s", s_str);
}

void print_addr_attr(Stun_Attr_Address attr)
{
    if (attr.family == STUN_ADDRESS_FAMILY_IPV4) {
        print_ipv4(attr.address[0]);
    } else if (attr.family == STUN_ADDRESS_FAMILY_IPV6) {
        print_ipv6(attr.address);
    } else {
        fprintf(stderr, "error: unexpected address family\n");
        exit(EXIT_FAILURE);
    }
}

static void address_arg_parse(const char *address, char host[64], char port[64])
{
#define HOST_BUF_CAP 64
#define PORT_BUF_CAP 64
    const char *h = address;
    size_t hlen = 0;

    while (*h && *h != '!' && *h != ':') {
        if (hlen >= HOST_BUF_CAP - 1) PANIC("host length must be less than " STR(HOST_BUF_CAP) " characters");
        host[hlen++] = *h;
        h++;
    }
    host[hlen++] = '\0';

    if (*h == '\0' || strchr("!:", *h) == NULL) {
        strcpy(port, STR(STUN_DEFAULT_PORT));
        return;
    }

    const char *p = h + 1;
    size_t plen = 0;

    while (*p) {
        if (plen >= PORT_BUF_CAP - 1) PANIC("port length must be less than " STR(PORT_BUF_CAP) " characters");
        port[plen++] = *p;
        p++;
    }

    if (plen == 0) {
        PANIC("port must be specified after the host, separated by ':' or '!'");
    }

    port[plen++] = '\0';

#undef HOST_BUF_CAP
#undef PORT_BUF_CAP
}

int main(int argc, char* argv[])
{
    srand(time(NULL));

    char *program = arg_shift(&argc, &argv);
    (void) program;

    const char *addr_arg = arg_shift(&argc, &argv);
    if (addr_arg == NULL) {
        fprintf(stderr, "error: address argument must be provided\n");
        exit(EXIT_FAILURE);
    }

    char host[256] = {0}; char port[256] = {0};

    address_arg_parse(addr_arg, host, port);

    bool poll = false;
    int poll_sleep = 5;
    bool dump_attrs = false;
    char *arg;
    while ((arg = arg_shift(&argc, &argv)) != NULL) {
        if (strcmp(arg, FLAG_POLL) == 0) {
            poll = true;
        } else if (strncmp(arg, FLAG_POLL_SLEEP, sizeof(FLAG_POLL_SLEEP) - 1) == 0) {
            char *val = arg + sizeof(FLAG_POLL_SLEEP) - 1;
            poll_sleep = atoi(val);
            if (poll_sleep <= 0) {
                fprintf(stderr, "error: " FLAG_POLL_SLEEP " value is invalid\n");
                exit(EXIT_FAILURE);
            }
        } else if (strncmp(arg, FLAG_DUMP_ATTRS, sizeof(FLAG_DUMP_ATTRS) - 1) == 0) {
            dump_attrs = true;
        }
    }

    assert(poll_sleep > 0);

    uint8_t rbuf[0xFFFF];

    Stun_Message_Header sm = stun_binding_request_new();
    Stun_Response_Header r;
    Stun_Attr_Arr attr_arr;
    size_t attempts_count = 0;

    int s = conn_init(host, port);

#define ON_SOCK_ERR(msg, ...) do { \
    fprintf(stderr, (msg), ##__VA_ARGS__); \
    if (! poll) { \
        exit(EXIT_FAILURE); \
    } \
    close(s); \
    attempts_count++; \
    sleep(poll_sleep); \
    s = conn_init(host, port); \
} while (0)

    do {
        if (attempts_count > MAX_ATTEMPTS) {
            printf("error: max attempts exhausted\n");
            exit(EXIT_FAILURE);
        }

        ssize_t wn = send_with_timeout(s, &sm, sizeof(sm), SOCKET_TIMEOUT);
        if (wn == 0) {
            ON_SOCK_ERR("error: wait timeout\n");
            continue;
        } else if (wn == -1) {
            ON_SOCK_ERR("error: %s\n", strerror(errno));
            continue;
        }
        assert(wn == sizeof(sm));

        ssize_t rn = recv_with_timeout(s, (uint8_t **)&rbuf, sizeof(rbuf), SOCKET_TIMEOUT);
        if (rn == 0) {
            ON_SOCK_ERR("error: wait timeout\n");
            continue;
        } else if (rn == -1) {
            ON_SOCK_ERR("error: %s\n", strerror(errno));
            continue;
        }

        r = stun_response_header_decode(rbuf, rn);
        attr_arr = stun_response_attrs_decode(rbuf, r.len);

        if (tid_cmp(r.tid, sm.tid, TID_LEN) != 0) {
            fprintf(stderr, "error: mismatching transaction id\n");
            exit(EXIT_FAILURE);
        }

        if (dump_attrs) {
            for (size_t i = 0; i < attr_arr.len; ++i) {
                ssize_t idx = stun_attr_type_find_idx(attr_arr.arr[i].type);
                if (idx < 0) {
                    fprintf(stderr, "error: encountered an unknown attribute type 0x%04X\n", attr_arr.arr[i].type);
                    continue;
                }

                printf("%02zu: %s = 0x%04X\n", i, STUN_ATTR_TYPE_NAMES[idx], STUN_ATTR_TYPES[idx]);
            }
        }

        print_addr_attr(find_any_address_attr(attr_arr, sm.tid));
        printf("\n");

#ifdef PRINT_RESPONSE_ORIGIN
        {
            Stun_Attr *attr = find_attr_of_type(&attr_arr, STUN_ATTR_RESPONSE_ORIGIN);
            if (attr == NULL) {
                fprintf(stderr, "error: response origin not found\n");
            } else {
                Stun_Attr_Address ro = stun_response_origin_decode(*attr);
                printf("response origin: ");
                print_addr_attr(ro);
                printf("\n");
            }
        }
#endif

#ifdef PRINT_SOFTWARE
        {
            Stun_Attr *attr = find_attr_of_type(&attr_arr, STUN_ATTR_SOFTWARE);
            if (attr == NULL) {
                fprintf(stderr, "error: software not found\n");
            } else {
                printf("software: %.*s\n", attr->len, attr->val);
            }
        }
#endif

#ifdef PRINT_OTHER_ADDRESS
        {
            Stun_Attr *attr = find_attr_of_type(&attr_arr, STUN_ATTR_OTHER_ADDRESS);
            if (attr == NULL) {
                fprintf(stderr, "error: other address not found\n");
            } else {
                Stun_Attr_Address oa = stun_other_address_decode(*attr);
                printf("other address: ");
                print_addr_attr(oa);
                printf("\n");
            }
        }
#endif

        if (poll) {
            sleep(poll_sleep);
        }

        attempts_count = 0;
    } while (poll);

    return 0;
}
