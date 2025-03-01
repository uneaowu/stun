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

Stun_Attr_Mapped_Address find_any_address_attr(Stun_Attr_Arr attr_arr, uint32_t tid[TID_LEN])
{
    Stun_Attr_Mapped_Address xor_addr_attr = {0}, addr_attr = {0};

    for (size_t i = 0; i < attr_arr.len; ++i) {
        Stun_Attr *attr = &attr_arr.arr[i];
        if (attr->type == XOR_MAPPED_ADDRESS) {
             xor_addr_attr = stun_xor_mapped_address_decode(*attr, tid);
        } else if (attr->type == MAPPED_ADDRESS) {
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
    printf("%d.%d.%d.%d\n",
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

    printf("%s\n", s_str);
}

void print_addr_attr(Stun_Attr_Mapped_Address attr)
{
    if (attr.family == Stun_Mapped_Address_Family_IPV4) {
        print_ipv4(attr.address[0]);
    } else if (attr.family == Stun_Mapped_Address_Family_IPV6) {
        print_ipv6(attr.address);
    } else {
        fprintf(stderr, "error: unexpected address family\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[])
{
    srand(time(NULL));

    char *program = arg_shift(&argc, &argv);
    (void) program;

    const char *host = arg_shift(&argc, &argv);
    if (host == NULL) {
        fprintf(stderr, "error: host argument must be provided\n");
        exit(EXIT_FAILURE);
    }
    const char *port = arg_shift(&argc, &argv);
    if (port == NULL) {
        fprintf(stderr, "error: port argument must be provided\n");
        exit(EXIT_FAILURE);
    }

    int portn = atoi(port);
    if (portn <= 0) {
        fprintf(stderr, "error: port argument is invalid\n");
        exit(EXIT_FAILURE);
    }

    bool poll = false;
    int poll_sleep = 5;
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

        print_addr_attr(find_any_address_attr(attr_arr, sm.tid));

        if (poll) {
            sleep(poll_sleep);
        }

        attempts_count = 0;
    } while (poll);

    return 0;
}
