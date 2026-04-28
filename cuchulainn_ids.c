/*
 * CuChulainn IDS v5.1 - Main Entry Point
 * High-performance protocol-aware intrusion detection system
 *
 * Author: Max Gecse
 * License: Apache 2.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "protocol_parser.h"

#define VERSION "5.1"
#define MAX_EVENTS 32
#define MAX_PACKET_SIZE 65536
#define PROTO_TABLE_MAX 64
#define FD_TABLE_MAX 32
#define MAINTENANCE_INTERVAL_SEC 5
#define INOTIFY_BUFFER_SIZE 4096
#define BASE_EPOLL_FLAGS (EPOLLIN | EPOLLET)

static volatile sig_atomic_t g_running = 1;
static int g_sockfd = -1;
static int g_epollfd = -1;
static int g_signalfd = -1;
static int g_timerfd = -1;
static int g_eventfd = -1;
static int g_inotifyfd = -1;
static int g_rules_watch = -1;
static const char *g_rules_path = "/etc/cuchulainn";

typedef struct {
    uint64_t total_packets;
    uint64_t detected_packets;
    uint64_t dropped_packets;
    uint64_t proto_counts[PROTO_TABLE_MAX];
    uint64_t parse_failures[PROTO_TABLE_MAX];
    uint64_t signal_events;
    uint64_t timer_events;
    uint64_t timer_expirations;
    uint64_t eventfd_events;
    uint64_t eventfd_notifications;
    uint64_t inotify_events;
    uint64_t inotify_overflows;
    uint64_t reload_requests;
} ids_stats_t;

static ids_stats_t g_stats;

typedef struct {
    const uint8_t *l3;
    size_t l3_len;
    const uint8_t *l4;
    size_t l4_len;
    const uint8_t *payload;
    size_t payload_len;
    uint16_t ethertype;
    uint8_t ip_proto;
    bool ipv6;
} packet_view_t;

typedef int (*proto_parse_fn)(const uint8_t *, size_t, protocol_ctx_t *);
typedef bool (*proto_detect_fn)(const protocol_ctx_t *);
typedef int (*fd_event_fn)(int fd, uint32_t events, void *userdata);

typedef struct {
    protocol_t id;
    const char *name;
    proto_parse_fn parse;
    proto_detect_fn is_malicious;
} proto_handler_t;

typedef struct {
    int fd;
    const char *name;
    fd_event_fn on_event;
    void *userdata;
} event_handler_t;

static const proto_handler_t g_proto_handlers[] = {
    { PROTO_TLS,   "TLS",      parse_tls,   tls_is_malicious   },
    { PROTO_DNS,   "DNS",      parse_dns,   dns_is_malicious   },
    { PROTO_HTTP1, "HTTP/1.1", parse_http1, http_is_malicious  },
    { PROTO_HTTP2, "HTTP/2",   parse_http2, http2_is_malicious },
    { PROTO_SMTP,  "SMTP",     parse_smtp,  smtp_is_malicious  },
    { PROTO_SIP,   "SIP",      parse_sip,   sip_is_malicious   },
    { PROTO_NTP,   "NTP",      parse_ntp,   ntp_is_malicious   },
    { PROTO_FTP,   "FTP",      parse_ftp,   ftp_is_malicious   },
#ifdef PROTO_IMAP
    { PROTO_IMAP,  "IMAP",     parse_imap,  imap_is_malicious  },
#endif
#ifdef PROTO_POP3
    { PROTO_POP3,  "POP3",     parse_pop3,  pop3_is_malicious  },
#endif
};

static const size_t g_proto_handler_count =
    sizeof(g_proto_handlers) / sizeof(g_proto_handlers[0]);

static event_handler_t g_fd_handlers[FD_TABLE_MAX];
static size_t g_fd_handler_count = 0;

static int make_fd_nonblocking_cloexec(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) return -1;

    return 0;
}

static const char *proto_name(protocol_t proto) {
    switch (proto) {
        case PROTO_TLS:   return "TLS";
        case PROTO_DNS:   return "DNS";
        case PROTO_HTTP1: return "HTTP/1.1";
        case PROTO_HTTP2: return "HTTP/2";
        case PROTO_SMTP:  return "SMTP";
        case PROTO_SIP:   return "SIP";
        case PROTO_NTP:   return "NTP";
        case PROTO_FTP:   return "FTP";
#ifdef PROTO_IMAP
        case PROTO_IMAP:  return "IMAP";
#endif
#ifdef PROTO_POP3
        case PROTO_POP3:  return "POP3";
#endif
        default:          return "UNKNOWN";
    }
}

static const proto_handler_t *find_proto_handler(protocol_t proto) {
    for (size_t i = 0; i < g_proto_handler_count; i++) {
        if (g_proto_handlers[i].id == proto) {
            return &g_proto_handlers[i];
        }
    }
    return NULL;
}

static int register_fd_handler(int epollfd, int fd, uint32_t events,
                               const char *name, fd_event_fn on_event, void *userdata) {
    if (g_fd_handler_count >= FD_TABLE_MAX) {
        errno = ENOSPC;
        return -1;
    }

    event_handler_t *handler = &g_fd_handlers[g_fd_handler_count];
    handler->fd = fd;
    handler->name = name;
    handler->on_event = on_event;
    handler->userdata = userdata;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = handler;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        return -1;
    }

    g_fd_handler_count++;
    return 0;
}

static void print_banner(void) {
    printf("CuChulainn IDS v%s\n", VERSION);
    printf("High-performance protocol-aware intrusion detection system\n");
    printf("Protocols: TLS, DNS, HTTP/1.1, HTTP/2, SMTP, SIP, NTP, FTP, IMAP, POP3\n");
    printf("Press Ctrl+C to stop.\n\n");
}

static void print_stats(void) {
    printf("\n=== Runtime Stats ===\n");
    printf("Total packets:     %llu\n", (unsigned long long)g_stats.total_packets);
    printf("Detections:        %llu\n", (unsigned long long)g_stats.detected_packets);
    printf("Dropped/Invalid:   %llu\n", (unsigned long long)g_stats.dropped_packets);
    printf("Signal events:     %llu\n", (unsigned long long)g_stats.signal_events);
    printf("Timer events:      %llu\n", (unsigned long long)g_stats.timer_events);
    printf("Timer expirations: %llu\n", (unsigned long long)g_stats.timer_expirations);
    printf("Eventfd events:    %llu\n", (unsigned long long)g_stats.eventfd_events);
    printf("Eventfd notices:   %llu\n", (unsigned long long)g_stats.eventfd_notifications);
    printf("Inotify events:    %llu\n", (unsigned long long)g_stats.inotify_events);
    printf("Inotify overflow:  %llu\n", (unsigned long long)g_stats.inotify_overflows);
    printf("Reload requests:   %llu\n", (unsigned long long)g_stats.reload_requests);

    for (size_t i = 0; i < g_proto_handler_count; i++) {
        protocol_t p = g_proto_handlers[i].id;
        if ((unsigned)p < PROTO_TABLE_MAX) {
            printf("%-17s %llu (parse_fail=%llu)\n",
                   g_proto_handlers[i].name,
                   (unsigned long long)g_stats.proto_counts[p],
                   (unsigned long long)g_stats.parse_failures[p]);
        }
    }

    printf("=====================\n");
}

static int setup_signalfd(void) {
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror("sigprocmask");
        return -1;
    }

    g_signalfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_signalfd < 0) {
        perror("signalfd");
        return -1;
    }

    return 0;
}

static int setup_timerfd(void) {
    struct itimerspec its;
    memset(&its, 0, sizeof(its));

    g_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_timerfd < 0) {
        perror("timerfd_create");
        return -1;
    }

    its.it_value.tv_sec = MAINTENANCE_INTERVAL_SEC;
    its.it_interval.tv_sec = MAINTENANCE_INTERVAL_SEC;

    if (timerfd_settime(g_timerfd, 0, &its, NULL) < 0) {
        perror("timerfd_settime");
        close(g_timerfd);
        g_timerfd = -1;
        return -1;
    }

    return 0;
}

static int setup_eventfd(void) {
    g_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_eventfd < 0) {
        perror("eventfd");
        return -1;
    }
    return 0;
}

static int setup_inotify(void) {
    g_inotifyfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_inotifyfd < 0) {
        perror("inotify_init1");
        return -1;
    }

    g_rules_watch = inotify_add_watch(
        g_inotifyfd,
        g_rules_path,
        IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY
    );

    if (g_rules_watch < 0) {
        perror("inotify_add_watch");
        close(g_inotifyfd);
        g_inotifyfd = -1;
        return -1;
    }

    return 0;
}

static int notify_eventfd(uint64_t value) {
    ssize_t n = write(g_eventfd, &value, sizeof(value));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        perror("write(eventfd)");
        return -1;
    }

    if ((size_t)n != sizeof(value)) {
        fprintf(stderr, "short write on eventfd\n");
        return -1;
    }

    return 0;
}

static bool is_reload_event(uint32_t mask) {
    return (mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE |
                    IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY)) != 0;
}

static bool parse_l4_payload(const uint8_t *frame, size_t len, packet_view_t *pv) {
    if (!frame || !pv || len < sizeof(struct ether_header)) {
        return false;
    }

    memset(pv, 0, sizeof(*pv));

    size_t off = sizeof(struct ether_header);
    uint16_t ethertype = ntohs(*(const uint16_t *)(frame + 12));

    while ((ethertype == 0x8100 || ethertype == 0x88A8) && len >= off + 4) {
        ethertype = ntohs(*(const uint16_t *)(frame + off + 2));
        off += 4;
    }

    pv->ethertype = ethertype;

    if (ethertype == ETH_P_IP) {
        if (len < off + sizeof(struct iphdr)) {
            return false;
        }

        const struct iphdr *iph = (const struct iphdr *)(frame + off);
        size_t ihl = (size_t)iph->ihl * 4;

        if (ihl < sizeof(struct iphdr) || len < off + ihl) {
            return false;
        }

        pv->ipv6 = false;
        pv->ip_proto = iph->protocol;
        pv->l3 = frame + off;
        pv->l3_len = len - off;
        off += ihl;
    } else if (ethertype == ETH_P_IPV6) {
        if (len < off + sizeof(struct ip6_hdr)) {
            return false;
        }

        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)(frame + off);

        pv->ipv6 = true;
        pv->ip_proto = ip6h->ip6_nxt;
        pv->l3 = frame + off;
        pv->l3_len = len - off;
        off += sizeof(struct ip6_hdr);
    } else {
        return false;
    }

    if (pv->ip_proto == IPPROTO_TCP) {
        if (len < off + sizeof(struct tcphdr)) {
            return false;
        }

        const struct tcphdr *tcph = (const struct tcphdr *)(frame + off);
        size_t doff = (size_t)tcph->doff * 4;

        if (doff < sizeof(struct tcphdr) || len < off + doff) {
            return false;
        }

        pv->l4 = frame + off;
        pv->l4_len = len - off;
        off += doff;
    } else if (pv->ip_proto == IPPROTO_UDP) {
        if (len < off + sizeof(struct udphdr)) {
            return false;
        }

        pv->l4 = frame + off;
        pv->l4_len = len - off;
        off += sizeof(struct udphdr);
    } else {
        return false;
    }

    if (off > len) {
        return false;
    }

    pv->payload = frame + off;
    pv->payload_len = len - off;
    return true;
}

static void print_json_escaped(const char *s) {
    if (!s) return;

    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '\"': printf("\\\""); break;
            case '\\': printf("\\\\"); break;
            case '\b': printf("\\b");  break;
            case '\f': printf("\\f");  break;
            case '\n': printf("\\n");  break;
            case '\r': printf("\\r");  break;
            case '\t': printf("\\t");  break;
            default:
                if (c < 0x20) {
                    printf("\\u%04x", c);
                } else {
                    putchar(c);
                }
                break;
        }
    }
}

static void emit_alert(protocol_t proto, const protocol_ctx_t *ctx) {
    printf("{\"event\":\"alert\",\"proto\":\"%s\"", proto_name(proto));

    if (ctx->domain[0]) {
        printf(",\"domain\":\"");
        print_json_escaped(ctx->domain);
        printf("\"");
    }

    if (ctx->uri[0]) {
        printf(",\"uri\":\"");
        print_json_escaped(ctx->uri);
        printf("\"");
    }

    if (ctx->flags) {
        printf(",\"score\":%u", ctx->flags);
    }

    if (ctx->entropy > 0.0f) {
        printf(",\"entropy\":%.2f", ctx->entropy);
    }

    printf("}\n");
}

static void maintenance_tick(uint64_t expirations) {
    g_stats.timer_expirations += expirations;

    if (expirations > 1) {
        fprintf(stderr,
                "[maintenance] timer lag detected: expirations=%llu\n",
                (unsigned long long)expirations);
    }
}

static void process_control_events(uint64_t count) {
    g_stats.eventfd_notifications += count;
}

static void process_inotify_event(const struct inotify_event *ev) {
    if (!ev) return;

    g_stats.inotify_events++;

    if (ev->mask & IN_Q_OVERFLOW) {
        g_stats.inotify_overflows++;
        fprintf(stderr, "[inotify] queue overflow, rebuild watcher state\n");
        return;
    }

    if (ev->mask & IN_IGNORED) {
        fprintf(stderr, "[inotify] watch removed wd=%d\n", ev->wd);
        return;
    }

    if (is_reload_event(ev->mask)) {
        g_stats.reload_requests++;

        fprintf(stderr, "[inotify] reload-trigger wd=%d mask=0x%x name=%s\n",
                ev->wd, ev->mask, ev->len ? ev->name : "(none)");

        if (g_eventfd >= 0) {
            (void)notify_eventfd(1);
        }
    }
}

static void inspect_payload(const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len == 0) {
        return;
    }

    protocol_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    protocol_t proto = detect_protocol(payload, payload_len, &ctx);
    if ((unsigned)proto < PROTO_TABLE_MAX) {
        g_stats.proto_counts[proto]++;
    }

    const proto_handler_t *handler = find_proto_handler(proto);
    if (!handler || !handler->parse || !handler->is_malicious) {
        return;
    }

    if (handler->parse(payload, payload_len, &ctx) != 0) {
        if ((unsigned)proto < PROTO_TABLE_MAX) {
            g_stats.parse_failures[proto]++;
        }
        return;
    }

    if (handler->is_malicious(&ctx)) {
        g_stats.detected_packets++;
        emit_alert(proto, &ctx);
    }
}

static void process_packet(const uint8_t *packet, ssize_t len) {
    if (!packet || len <= 0) {
        return;
    }

    g_stats.total_packets++;

    packet_view_t pv;
    if (!parse_l4_payload(packet, (size_t)len, &pv)) {
        g_stats.dropped_packets++;
        return;
    }

    if (!pv.payload || pv.payload_len == 0) {
        g_stats.dropped_packets++;
        return;
    }

    inspect_payload(pv.payload, pv.payload_len);
}

static int handle_packet_fd(int fd, uint32_t events, void *userdata) {
    (void)userdata;

    if (events & (EPOLLERR | EPOLLHUP)) {
        g_running = 0;
        return -1;
    }

    uint8_t buffer[MAX_PACKET_SIZE];

    while (1) {
        ssize_t n = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("recvfrom");
            g_running = 0;
            return -1;
        }

        if (n == 0) {
            return 0;
        }

        process_packet(buffer, n);
    }
}

static int handle_signal_fd(int fd, uint32_t events, void *userdata) {
    (void)userdata;

    if (events & (EPOLLERR | EPOLLHUP)) {
        g_running = 0;
        return -1;
    }

    while (1) {
        struct signalfd_siginfo fdsi;
        ssize_t n = read(fd, &fdsi, sizeof(fdsi));

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("read(signalfd)");
            g_running = 0;
            return -1;
        }

        if (n == 0) {
            return 0;
        }

        if ((size_t)n != sizeof(fdsi)) {
            fprintf(stderr, "short read on signalfd\n");
            g_running = 0;
            return -1;
        }

        g_stats.signal_events++;

        switch (fdsi.ssi_signo) {
            case SIGINT:
            case SIGTERM:
                g_running = 0;
                return 0;
            default:
                break;
        }
    }
}

static int handle_timer_fd(int fd, uint32_t events, void *userdata) {
    (void)userdata;

    if (events & (EPOLLERR | EPOLLHUP)) {
        g_running = 0;
        return -1;
    }

    while (1) {
        uint64_t expirations = 0;
        ssize_t n = read(fd, &expirations, sizeof(expirations));

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("read(timerfd)");
            g_running = 0;
            return -1;
        }

        if (n == 0) {
            return 0;
        }

        if ((size_t)n != sizeof(expirations)) {
            fprintf(stderr, "short read on timerfd\n");
            g_running = 0;
            return -1;
        }

        g_stats.timer_events++;
        maintenance_tick(expirations);
    }
}

static int handle_event_fd(int fd, uint32_t events, void *userdata) {
    (void)userdata;

    if (events & (EPOLLERR | EPOLLHUP)) {
        g_running = 0;
        return -1;
    }

    while (1) {
        uint64_t count = 0;
        ssize_t n = read(fd, &count, sizeof(count));

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("read(eventfd)");
            g_running = 0;
            return -1;
        }

        if (n == 0) {
            return 0;
        }

        if ((size_t)n != sizeof(count)) {
            fprintf(stderr, "short read on eventfd\n");
            g_running = 0;
            return -1;
        }

        g_stats.eventfd_events++;
        process_control_events(count);
    }
}

static int handle_inotify_fd(int fd, uint32_t events, void *userdata) {
    (void)userdata;

    if (events & (EPOLLERR | EPOLLHUP)) {
        g_running = 0;
        return -1;
    }

    char buffer[INOTIFY_BUFFER_SIZE]
        __attribute__((aligned(__alignof__(struct inotify_event))));

    while (1) {
        ssize_t n = read(fd, buffer, sizeof(buffer));

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("read(inotify)");
            g_running = 0;
            return -1;
        }

        if (n == 0) {
            return 0;
        }

        for (char *ptr = buffer; ptr < buffer + n; ) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            process_inotify_event(ev);
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }
}

int main(void) {
    struct epoll_event events[MAX_EVENTS];

    memset(&g_stats, 0, sizeof(g_stats));
    print_banner();

    if (protocol_parser_init() != 0) {
        fprintf(stderr, "Failed to initialize protocol parser\n");
        return 1;
    }

    if (setup_signalfd() != 0) {
        return 1;
    }

    if (setup_timerfd() != 0) {
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    if (setup_eventfd() != 0) {
        if (g_timerfd >= 0) close(g_timerfd);
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    if (setup_inotify() != 0) {
        if (g_eventfd >= 0) close(g_eventfd);
        if (g_timerfd >= 0) close(g_timerfd);
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    g_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_sockfd < 0) {
        perror("socket(AF_PACKET)");
        if (g_inotifyfd >= 0) close(g_inotifyfd);
        if (g_eventfd >= 0) close(g_eventfd);
        if (g_timerfd >= 0) close(g_timerfd);
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    if (make_fd_nonblocking_cloexec(g_sockfd) != 0) {
        perror("fcntl(packet fd)");
        close(g_sockfd);
        if (g_inotifyfd >= 0) close(g_inotifyfd);
        if (g_eventfd >= 0) close(g_eventfd);
        if (g_timerfd >= 0) close(g_timerfd);
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    g_epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epollfd < 0) {
        perror("epoll_create1");
        close(g_sockfd);
        if (g_inotifyfd >= 0) close(g_inotifyfd);
        if (g_eventfd >= 0) close(g_eventfd);
        if (g_timerfd >= 0) close(g_timerfd);
        if (g_signalfd >= 0) close(g_signalfd);
        return 1;
    }

    if (register_fd_handler(g_epollfd, g_sockfd, BASE_EPOLL_FLAGS, "packet-socket",
                            handle_packet_fd, NULL) != 0) {
        perror("register_fd_handler(packet)");
        goto cleanup;
    }

    if (register_fd_handler(g_epollfd, g_signalfd, BASE_EPOLL_FLAGS, "signalfd",
                            handle_signal_fd, NULL) != 0) {
        perror("register_fd_handler(signalfd)");
        goto cleanup;
    }

    if (register_fd_handler(g_epollfd, g_timerfd, BASE_EPOLL_FLAGS, "timerfd",
                            handle_timer_fd, NULL) != 0) {
        perror("register_fd_handler(timerfd)");
        goto cleanup;
    }

    if (register_fd_handler(g_epollfd, g_eventfd, BASE_EPOLL_FLAGS, "eventfd",
                            handle_event_fd, NULL) != 0) {
        perror("register_fd_handler(eventfd)");
        goto cleanup;
    }

    if (register_fd_handler(g_epollfd, g_inotifyfd, BASE_EPOLL_FLAGS, "inotifyfd",
                            handle_inotify_fd, NULL) != 0) {
        perror("register_fd_handler(inotifyfd)");
        goto cleanup;
    }

    while (g_running) {
        int nfds = epoll_wait(g_epollfd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            event_handler_t *handler = (event_handler_t *)events[i].data.ptr;
            if (!handler || !handler->on_event) {
                fprintf(stderr, "Invalid epoll handler pointer\n");
                g_running = 0;
                break;
            }

            if (handler->on_event(handler->fd, events[i].events, handler->userdata) != 0) {
                g_running = 0;
                break;
            }
        }
    }

cleanup:
    print_stats();

    if (g_epollfd >= 0) close(g_epollfd);
    if (g_sockfd >= 0) close(g_sockfd);
    if (g_inotifyfd >= 0) close(g_inotifyfd);
    if (g_eventfd >= 0) close(g_eventfd);
    if (g_timerfd >= 0) close(g_timerfd);
    if (g_signalfd >= 0) close(g_signalfd);

    return 0;
}
