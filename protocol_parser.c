#include "protocol_parser.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static int starts_with(const uint8_t *data, size_t len, const char *sig) {
    size_t slen = strlen(sig);
    if (!data || len < slen) return 0;
    return memcmp(data, sig, slen) == 0;
}

protocol_t detect_protocol(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 2) return PROTO_UNKNOWN;

    memset(ctx, 0, sizeof(*ctx));
    ctx->proto = PROTO_UNKNOWN;

    /* TLS */
    if (len >= 5 && data[0] == 0x16 && data[1] == 0x03) {
        ctx->proto = PROTO_TLS;
        return PROTO_TLS;
    }

    /* SSH */
    if (starts_with(data, len, "SSH-")) {
        ctx->proto = PROTO_SSH;
        return PROTO_SSH;
    }

    /* MQTT */
    if (len >= 2 && (data[0] >> 4) == 1) {
        ctx->proto = PROTO_MQTT;
        return PROTO_MQTT;
    }

    /* RTSP */
    if (starts_with(data, len, "RTSP/") ||
        starts_with(data, len, "OPTIONS ") ||
        starts_with(data, len, "DESCRIBE ") ||
        starts_with(data, len, "SETUP ") ||
        starts_with(data, len, "PLAY ")) {
        ctx->proto = PROTO_RTSP;
        return PROTO_RTSP;
    }

    /* QUIC - heuristic */
    if (len >= 6 && (data[0] & 0x80)) {
        ctx->proto = PROTO_QUIC;
    }

    /* CoAP - heuristic */
    if (len >= 4) {
        uint8_t ver = (data[0] >> 6) & 0x03;
        if (ver == 1) {
            ctx->proto = PROTO_COAP;
        }
    }

    /* DNS */
    if (len >= 12) {
        uint16_t qdcount = ((uint16_t)data[4] << 8) | data[5];
        uint16_t ancount = ((uint16_t)data[6] << 8) | data[7];
        if ((qdcount > 0 || ancount > 0) && qdcount < 64 && ancount < 64) {
            ctx->proto = PROTO_DNS;
            return PROTO_DNS;
        }
    }

    /* HTTP/1.1 */
    if (starts_with(data, len, "GET ") ||
        starts_with(data, len, "POST ") ||
        starts_with(data, len, "PUT ") ||
        starts_with(data, len, "DELETE ") ||
        starts_with(data, len, "HEAD ") ||
        starts_with(data, len, "OPTIONS ") ||
        starts_with(data, len, "PATCH ") ||
        starts_with(data, len, "HTTP/1.")) {
        ctx->proto = PROTO_HTTP1;
        return PROTO_HTTP1;
    }

    /* HTTP/2 preface */
    if (starts_with(data, len, "PRI * HTTP/2.0")) {
        ctx->proto = PROTO_HTTP2;
        return PROTO_HTTP2;
    }

    /* SIP */
    if (starts_with(data, len, "INVITE ") ||
        starts_with(data, len, "REGISTER ") ||
        starts_with(data, len, "ACK ") ||
        starts_with(data, len, "BYE ") ||
        starts_with(data, len, "SIP/2.0")) {
        ctx->proto = PROTO_SIP;
        return PROTO_SIP;
    }

    /* SMTP */
    if (starts_with(data, len, "HELO ") ||
        starts_with(data, len, "EHLO ") ||
        starts_with(data, len, "MAIL FROM:") ||
        starts_with(data, len, "RCPT TO:") ||
        starts_with(data, len, "DATA") ||
        starts_with(data, len, "220 ")) {
        ctx->proto = PROTO_SMTP;
        return PROTO_SMTP;
    }

    /* NTP heuristic */
    if (len >= 8) {
        uint8_t mode = data[0] & 0x07;
        if (mode >= 1 && mode <= 7) {
            if (ctx->proto == PROTO_UNKNOWN)
                ctx->proto = PROTO_NTP;
        }
    }

    /* FTP */
    if (starts_with(data, len, "USER ") ||
        starts_with(data, len, "PASS ") ||
        starts_with(data, len, "220 ") ||
        starts_with(data, len, "230 ") ||
        starts_with(data, len, "530 ")) {
        ctx->proto = PROTO_FTP;
        return PROTO_FTP;
    }

    return ctx->proto;
}

int protocol_parser_init(void) {
    printf("Protocol parser initialized\n");
    return 0;
}

/* DNS */
int parse_dns(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 12) return -1;
    ctx->proto = PROTO_DNS;
    ctx->flags = ((uint32_t)data[2] << 8) | data[3];

    size_t off = 12;
    size_t pos = 0;
    while (off < len && data[off] != 0 && pos < sizeof(ctx->domain) - 2) {
        uint8_t label_len = data[off++];
        if (label_len == 0 || off + label_len > len || label_len > 63) break;
        if (pos && pos < sizeof(ctx->domain) - 1) ctx->domain[pos++] = '.';
        for (uint8_t i = 0; i < label_len && pos < sizeof(ctx->domain) - 1; i++) {
            ctx->domain[pos++] = (char)data[off + i];
        }
        off += label_len;
    }
    ctx->domain[pos] = '\0';
    return 0;
}

bool dns_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return strlen(ctx->domain) > 60 || ctx->entropy > 4.5f;
}

/* HTTP/1.1 */
int parse_http1(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 8) return -1;
    ctx->proto = PROTO_HTTP1;

    const uint8_t *sp1 = memchr(data, ' ', len);
    if (!sp1) return 0;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', len - (size_t)(sp1 - data));
    if (!sp2) return 0;

    size_t uri_len = (size_t)(sp2 - sp1);
    if (uri_len >= sizeof(ctx->uri)) uri_len = sizeof(ctx->uri) - 1;
    memcpy(ctx->uri, sp1, uri_len);
    ctx->uri[uri_len] = '\0';
    return 0;
}

bool http_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return strstr(ctx->uri, "UNION SELECT") ||
           strstr(ctx->uri, "' OR 1=1") ||
           strstr(ctx->uri, "<script>") ||
           strstr(ctx->uri, "javascript:") ||
           strstr(ctx->uri, "../") ||
           strstr(ctx->uri, "/etc/passwd");
}

/* HTTP/2 */
int parse_http2(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 9) return -1;
    ctx->proto = PROTO_HTTP2;
    return 0;
}

bool http2_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return (ctx->flags > 500);
}

/* SIP */
int parse_sip(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 4) return -1;
    ctx->proto = PROTO_SIP;
    return 0;
}

bool sip_is_malicious(const protocol_ctx_t *ctx) {
    (void)ctx;
    return false;
}

/* SMTP */
int parse_smtp(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 4) return -1;
    ctx->proto = PROTO_SMTP;
    return 0;
}

bool smtp_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return strlen(ctx->domain) > 30;
}

/* NTP */
int parse_ntp(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 8) return -1;
    ctx->proto = PROTO_NTP;
    ctx->flags = data[1];
    return 0;
}

bool ntp_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return ctx->flags == 0x17;
}

/* FTP */
int parse_ftp(const uint8_t *data, size_t len, protocol_ctx_t *ctx) {
    if (!data || !ctx || len < 4) return -1;
    ctx->proto = PROTO_FTP;
    if (starts_with(data, len, "USER anonymous")) ctx->flags = 1;
    return 0;
}

bool ftp_is_malicious(const protocol_ctx_t *ctx) {
    if (!ctx) return false;
    return ctx->flags == 1;
}
