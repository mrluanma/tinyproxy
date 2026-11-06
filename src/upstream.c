/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
 * Copyright (C) 2009 Michael Adam <obnox@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Routines for handling the list of upstream proxies.
 */

#include "upstream.h"
#include "heap.h"
#include "log.h"
#include "base64.h"
#include "basicauth.h"

#ifdef UPSTREAM_SUPPORT
const char *
proxy_type_name(proxy_type type)
{
    switch(type) {
        case PT_NONE: return "none";
        case PT_HTTP: return "http";
        case PT_SOCKS4: return "socks4";
        case PT_SOCKS5: return "socks5";
        default: return "unknown";
    }
}


const char* upstream_build_error_string(enum upstream_build_error ube) {
        static const char *emap[] = {
        [UBE_SUCCESS] = "",
        [UBE_OOM] = "Unable to allocate memory in upstream_build()",
        [UBE_USERLEN] = "User / pass in upstream config too long",
        [UBE_EDOMAIN] = "Nonsense upstream none rule: empty domain",
        [UBE_INVHOST] = "Nonsense upstream rule: invalid host or port",
        [UBE_INVPARAMS] = "Nonsense upstream rule: invalid parameters",
        [UBE_NETMASK] = "Nonsense upstream rule: failed to parse netmask",
        };
        return emap[ube];
}

/**
 * Construct an upstream struct from input data.
 */
static struct upstream *upstream_build (const char *host, int port, char *domain,
                        const char *user, const char *pass,
			proxy_type type, enum upstream_build_error *ube)
{
        struct upstream *up;

        *ube = UBE_SUCCESS;
        up = (struct upstream *) safemalloc (sizeof (struct upstream));
        if (!up) {
                *ube = UBE_OOM;
                return NULL;
        }

        up->type = type;
        up->target.type = HST_NONE;
        up->host = up->ua.user = up->pass = NULL;
        if (user) {
                if (type == PT_HTTP) {
                        char b[BASE64ENC_BYTES((256+2)-1) + 1];
                        ssize_t ret;
                        ret = basicauth_string(user, pass, b, sizeof b);
                        if (ret == 0) {
                                *ube = UBE_USERLEN;
                                return NULL;
                        }
                        up->ua.authstr = safestrdup (b);
                } else {
                        up->ua.user = safestrdup (user);
                        up->pass = safestrdup (pass);
                }
        }

        if (domain == NULL) {
                if (type == PT_NONE) {
                e_nonedomain:;
                        *ube = UBE_EDOMAIN;
                        goto fail;
                }
                if (!host || !host[0] || port < 1) {
                        *ube = UBE_INVHOST;
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;

                log_message (LOG_INFO, "Added upstream %s %s:%d for [default]",
                             proxy_type_name(type), host, port);
        } else {
                if (type == PT_NONE) {
                        if (!domain[0]) goto e_nonedomain;
                } else {
                        if (!host || !host[0] || !domain[0]) {
                                *ube = UBE_INVPARAMS;
                                goto fail;
                        }
                        up->host = safestrdup (host);
                        up->port = port;
                }

                if (hostspec_parse(domain, &up->target)
                   || up->target.type == HST_NONE) {
                        *ube = UBE_NETMASK;
                        goto fail;
                }

                if (type == PT_NONE)
                        log_message (LOG_INFO, "Added upstream none for %s", domain);
                else
                        log_message (LOG_INFO, "Added upstream %s %s:%d for %s",
                                     proxy_type_name(type), host, port, domain);
        }

        return up;

fail:
        safefree (up->ua.user);
        safefree (up->pass);
        safefree (up->host);
        if(up->target.type == HST_STRING)
                safefree (up->target.address.string);
        safefree (up);

        return NULL;
}

/*
 * Add an entry to the upstream list
 */
enum upstream_build_error upstream_add (
                   const char *host, int port, char *domain,
                   const char *user, const char *pass,
                   proxy_type type, struct upstream **upstream_list)
{
        struct upstream *up;
        enum upstream_build_error ube;

        up = upstream_build (host, port, domain, user, pass, type, &ube);
        if (up == NULL) {
                return ube;
        }

        if (up->target.type == HST_NONE) {   /* always add default to end */
                struct upstream *tmp = *upstream_list;

                while (tmp) {
                        if (tmp->target.type == HST_NONE) {
                                log_message (LOG_WARNING,
                                             "Duplicate default upstream");
                                goto upstream_cleanup;
                        }

                        if (!tmp->next) {
                                up->next = NULL;
                                tmp->next = up;
                                return ube;
                        }

                        tmp = tmp->next;
                }
        }

        up->next = *upstream_list;
        *upstream_list = up;

        return ube;

upstream_cleanup:
        safefree (up->host);
        if(up->target.type == HST_STRING)
                safefree (up->target.address.string);
        safefree (up);

        return ube;
}

/*
 * Sorted, non-overlapping address ranges for O(log n) CIDR upstream lookups.
 * HST_NUMERIC rules are flattened into disjoint ranges owned by the
 * longest matching prefix; lookups are a binary search per address family.
 */
struct u128 {
        uint64_t hi, lo;
};

struct upstream_range4 {
        uint32_t start, end;
        struct upstream *up;
};

struct upstream_range6 {
        struct u128 start, end;
        struct upstream *up;
};

struct upstream_ranges {
        struct upstream_range4 *v4;
        size_t n4;
        struct upstream_range6 *v6;
        size_t n6;
};

struct range_cand4 {
        uint32_t start, end;
        int plen;
        size_t idx;
        struct upstream *up;
};

struct range_cand6 {
        struct u128 start, end;
        int plen;
        size_t idx;
        struct upstream *up;
};

static int
prefix_length_from_mask (const unsigned char mask[IPV6_LEN])
{
        int i, bits = 0;

        for (i = 0; i < IPV6_LEN; i++) {
                if (mask[i] == 0xff) {
                        bits += 8;
                } else {
                        unsigned char b = mask[i];
                        while (b & 0x80) {
                                bits++;
                                b <<= 1;
                        }
                        break;
                }
        }
        return bits;
}

static int
is_v4_mapped (const unsigned char ip[IPV6_LEN])
{
        int i;

        for (i = 0; i < 10; i++) {
                if (ip[i])
                        return 0;
        }
        return ip[10] == 0xff && ip[11] == 0xff;
}

static uint32_t
u32_from_bytes (const unsigned char *p)
{
        return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
               | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static struct u128
u128_from_bytes (const unsigned char *p)
{
        struct u128 v;

        v.hi = u32_from_bytes (p);
        v.hi = (v.hi << 32) | u32_from_bytes (p + 4);
        v.lo = u32_from_bytes (p + 8);
        v.lo = (v.lo << 32) | u32_from_bytes (p + 12);
        return v;
}

static int
u128_cmp (struct u128 a, struct u128 b)
{
        if (a.hi != b.hi)
                return a.hi < b.hi ? -1 : 1;
        if (a.lo != b.lo)
                return a.lo < b.lo ? -1 : 1;
        return 0;
}

static int
u128_eq (struct u128 a, struct u128 b)
{
        return a.hi == b.hi && a.lo == b.lo;
}

static struct u128
u128_inc (struct u128 a)
{
        a.lo++;
        if (a.lo == 0)
                a.hi++;
        return a;
}

/* subtract 1; a must be nonzero */
static struct u128
u128_dec (struct u128 a)
{
        if (a.lo == 0)
                a.hi--;
        a.lo--;
        return a;
}

static void
mask_from_plen (int plen, uint64_t *mhi, uint64_t *mlo)
{
        if (plen <= 0) {
                *mhi = *mlo = 0;
        } else if (plen < 64) {
                *mhi = ~(uint64_t) 0 << (64 - plen);
                *mlo = 0;
        } else if (plen < 128) {
                *mhi = ~(uint64_t) 0;
                *mlo = ~(uint64_t) 0 << (128 - plen);
        } else {
                *mhi = *mlo = ~(uint64_t) 0;
        }
}

static int
str_null_eq (const char *a, const char *b)
{
        if (a == b)
                return 1;
        if (!a || !b)
                return 0;
        return strcmp (a, b) == 0;
}

static int
upstream_equiv (const struct upstream *a, const struct upstream *b)
{
        if (a == b)
                return 1;
        if (!a->host || !b->host)
                return !a->host && !b->host;
        return a->type == b->type && a->port == b->port
               && strcmp (a->host, b->host) == 0
               && str_null_eq (a->ua.user, b->ua.user)
               && str_null_eq (a->pass, b->pass);
}

static int
cand4_cmp (const void *va, const void *vb)
{
        const struct range_cand4 *a = va, *b = vb;

        if (a->start != b->start)
                return a->start < b->start ? -1 : 1;
        if (a->end != b->end)
                return a->end > b->end ? -1 : 1;
        if (a->plen != b->plen)
                return b->plen - a->plen;
        if (a->idx != b->idx)
                return a->idx < b->idx ? -1 : 1;
        return 0;
}

static int
cand6_cmp (const void *va, const void *vb)
{
        const struct range_cand6 *x = va, *y = vb;
        int c;

        c = u128_cmp (x->start, y->start);
        if (c)
                return c;
        c = u128_cmp (x->end, y->end);
        if (c)
                return -c;
        if (x->plen != y->plen)
                return y->plen - x->plen;
        if (x->idx != y->idx)
                return x->idx < y->idx ? -1 : 1;
        return 0;
}

/*
 * Sweep sorted candidates into disjoint output pieces owned by the
 * innermost (longest-prefix) containing range.  CIDR ranges are either
 * nested or disjoint, never partially overlapping.  IPv4 ranges are
 * swept through the same u128 view.
 */
struct sweep_ctx {
        void *pieces;
        size_t n, cap;
        size_t elemsz;
        int is6;
};

static int
sweep_emit (struct sweep_ctx *ctx, struct u128 start, struct u128 end,
            struct upstream *up)
{
        char *p;

        if (u128_cmp (start, end) > 0)
                return 0;
        if (ctx->n == ctx->cap) {
                size_t ncap = ctx->cap ? ctx->cap * 2 : 64;
                void *np = saferealloc (ctx->pieces, ncap * ctx->elemsz);
                if (!np)
                        return -1;
                ctx->pieces = np;
                ctx->cap = ncap;
        }
        p = (char *) ctx->pieces + ctx->n * ctx->elemsz;
        if (ctx->is6) {
                struct upstream_range6 r;

                r.start = start;
                r.end = end;
                r.up = up;
                memcpy (p, &r, sizeof (r));
        } else {
                struct upstream_range4 r;

                r.start = (uint32_t) start.lo;
                r.end = (uint32_t) end.lo;
                r.up = up;
                memcpy (p, &r, sizeof (r));
        }
        ctx->n++;
        return 0;
}

static int
sweep_ranges (struct sweep_ctx *ctx, const struct u128 *starts,
              const struct u128 *ends, struct upstream *const *ups,
              size_t ncand)
{
        struct u128 stack_end[129];
        struct upstream *stack_up[129];
        int depth = 0;
        struct u128 cur, max;
        int have_cur = 0;
        size_t i;

        memset (&cur, 0, sizeof (cur));
        max.hi = max.lo = ~(uint64_t) 0;

        for (i = 0; i < ncand; i++) {
                /* skip exact duplicate of previous candidate */
                if (i && u128_eq (starts[i], starts[i - 1])
                    && u128_eq (ends[i], ends[i - 1]))
                        continue;
                while (depth && u128_cmp (stack_end[depth - 1], starts[i]) < 0) {
                        if (sweep_emit (ctx, cur, stack_end[depth - 1],
                                        stack_up[depth - 1]) < 0)
                                return -1;
                        cur = u128_inc (stack_end[depth - 1]);
                        depth--;
                }
                if (depth && have_cur
                    && u128_cmp (cur, starts[i]) < 0) {
                        struct u128 gap_end = u128_dec (starts[i]);
                        if (sweep_emit (ctx, cur, gap_end,
                                        stack_up[depth - 1]) < 0)
                                return -1;
                }
                stack_end[depth] = ends[i];
                stack_up[depth] = ups[i];
                depth++;
                cur = starts[i];
                have_cur = 1;
        }
        while (depth) {
                int end_is_max = u128_eq (stack_end[depth - 1], max);
                if (sweep_emit (ctx, cur, stack_end[depth - 1],
                                stack_up[depth - 1]) < 0)
                        return -1;
                if (end_is_max)
                        break;  /* cur would wrap to 0 */
                cur = u128_inc (stack_end[depth - 1]);
                depth--;
        }
        return 0;
}

/*
 * Merge adjacent pieces (prev.end + 1 == cur.start) with equivalent
 * upstreams, then shrink the piece array to its exact size.
 */
static size_t
merge_pieces4 (struct upstream_range4 *r, size_t n)
{
        size_t i, out = 0;

        for (i = 0; i < n; i++) {
                if (out && r[out - 1].end != ~(uint32_t) 0
                    && r[out - 1].end + 1 == r[i].start
                    && upstream_equiv (r[out - 1].up, r[i].up)) {
                        r[out - 1].end = r[i].end;
                } else {
                        r[out++] = r[i];
                }
        }
        return out;
}

static size_t
merge_pieces6 (struct upstream_range6 *r, size_t n)
{
        size_t i, out = 0;
        struct u128 max;

        max.hi = max.lo = ~(uint64_t) 0;
        for (i = 0; i < n; i++) {
                if (out && !u128_eq (r[out - 1].end, max)
                    && u128_eq (u128_inc (r[out - 1].end), r[i].start)
                    && upstream_equiv (r[out - 1].up, r[i].up)) {
                        r[out - 1].end = r[i].end;
                } else {
                        r[out++] = r[i];
                }
        }
        return out;
}

struct upstream_ranges *
upstream_ranges_build (struct upstream *upstream_list)
{
        struct upstream_ranges *ranges;
        struct range_cand4 *c4 = NULL;
        struct range_cand6 *c6 = NULL;
        size_t n4 = 0, n6 = 0, cap4 = 0, cap6 = 0, idx = 0, i;
        struct upstream *up;
        struct sweep_ctx ctx;
        struct u128 *starts = NULL, *ends = NULL;
        struct upstream **ups = NULL;
        int is6_pass;

        for (up = upstream_list; up; up = up->next, idx++) {
                const unsigned char *net, *mask;
                int plen;
                uint64_t mhi, mlo;

                if (up->target.type != HST_NUMERIC)
                        continue;
                net = up->target.address.ip.network;
                mask = up->target.address.ip.mask;
                plen = prefix_length_from_mask (mask);

                if (is_v4_mapped (net) && plen >= 96) {
                        uint32_t m32, net32;

                        net32 = u32_from_bytes (net + 12);
                        m32 = plen == 96 ? 0 : ~(uint32_t) 0 << (128 - plen);
                        if (n4 == cap4) {
                                cap4 = cap4 ? cap4 * 2 : 256;
                                c4 = saferealloc (c4, cap4 * sizeof (*c4));
                                if (!c4)
                                        goto oom;
                        }
                        c4[n4].start = net32 & m32;
                        c4[n4].end = c4[n4].start | ~m32;
                        c4[n4].plen = plen;
                        c4[n4].idx = idx;
                        c4[n4].up = up;
                        n4++;
                } else {
                        struct u128 s, e, bs, be;
                        int covers_v4;

                        mask_from_plen (plen, &mhi, &mlo);
                        s = u128_from_bytes (net);
                        s.hi &= mhi;
                        s.lo &= mlo;
                        e.hi = s.hi | ~mhi;
                        e.lo = s.lo | ~mlo;
                        if (n6 == cap6) {
                                cap6 = cap6 ? cap6 * 2 : 64;
                                c6 = saferealloc (c6, cap6 * sizeof (*c6));
                                if (!c6)
                                        goto oom;
                        }
                        c6[n6].start = s;
                        c6[n6].end = e;
                        c6[n6].plen = plen;
                        c6[n6].idx = idx;
                        c6[n6].up = up;
                        n6++;
                        /* A v6 rule containing all of ::ffff:0:0/96 also
                         * matches IPv4 lookups. */
                        bs.hi = 0;
                        bs.lo = (uint64_t) 0xffff << 32;
                        be.hi = 0;
                        be.lo = ((uint64_t) 0xffff << 32) | 0xffffffffULL;
                        covers_v4 = (bs.hi & mhi) == s.hi
                                    && (bs.lo & mlo) == s.lo
                                    && (be.hi & mhi) == s.hi
                                    && (be.lo & mlo) == s.lo;
                        if (covers_v4) {
                                if (n4 == cap4) {
                                        cap4 = cap4 ? cap4 * 2 : 256;
                                        c4 = saferealloc (c4,
                                                          cap4 * sizeof (*c4));
                                        if (!c4)
                                                goto oom;
                                }
                                c4[n4].start = 0;
                                c4[n4].end = ~(uint32_t) 0;
                                c4[n4].plen = plen;
                                c4[n4].idx = idx;
                                c4[n4].up = up;
                                n4++;
                        }
                }
        }

        if (!n4 && !n6) {
                safefree (c4);
                safefree (c6);
                return NULL;
        }

        ranges = safemalloc (sizeof (*ranges));
        if (!ranges) {
                safefree (c4);
                safefree (c6);
                log_message (LOG_ERR, "Unable to allocate memory in "
                             "upstream_ranges_build()");
                return NULL;
        }
        ranges->v4 = NULL;
        ranges->n4 = 0;
        ranges->v6 = NULL;
        ranges->n6 = 0;

        for (is6_pass = 0; is6_pass < 2; is6_pass++) {
                size_t nc = is6_pass ? n6 : n4;
                size_t npieces;

                if (!nc)
                        continue;
                starts = safemalloc (nc * sizeof (*starts));
                ends = safemalloc (nc * sizeof (*ends));
                ups = safemalloc (nc * sizeof (*ups));
                if (!starts || !ends || !ups)
                        goto oom_lists;
                if (is6_pass)
                        qsort (c6, n6, sizeof (*c6), cand6_cmp);
                else
                        qsort (c4, n4, sizeof (*c4), cand4_cmp);
                for (i = 0; i < nc; i++) {
                        if (is6_pass) {
                                starts[i] = c6[i].start;
                                ends[i] = c6[i].end;
                                ups[i] = c6[i].up;
                        } else {
                                starts[i].hi = 0;
                                starts[i].lo = c4[i].start;
                                ends[i].hi = 0;
                                ends[i].lo = c4[i].end;
                                ups[i] = c4[i].up;
                        }
                }
                ctx.pieces = NULL;
                ctx.n = 0;
                ctx.cap = 0;
                ctx.elemsz = is6_pass ? sizeof (struct upstream_range6)
                             : sizeof (struct upstream_range4);
                ctx.is6 = is6_pass;
                if (sweep_ranges (&ctx, starts, ends, ups, nc) < 0) {
                        safefree (ctx.pieces);
                        goto oom_lists;
                }
                safefree (starts);
                safefree (ends);
                safefree (ups);
                if (is6_pass) {
                        npieces = merge_pieces6 (ctx.pieces, ctx.n);
                        ranges->v6 = saferealloc (ctx.pieces,
                                                  npieces
                                                  * sizeof (*ranges->v6));
                        if (!ranges->v6) {
                                safefree (ctx.pieces);
                                goto oom_lists;
                        }
                        ranges->n6 = npieces;
                } else {
                        npieces = merge_pieces4 (ctx.pieces, ctx.n);
                        ranges->v4 = saferealloc (ctx.pieces,
                                                  npieces
                                                  * sizeof (*ranges->v4));
                        if (!ranges->v4) {
                                safefree (ctx.pieces);
                                goto oom_lists;
                        }
                        ranges->n4 = npieces;
                }
        }

        safefree (c4);
        safefree (c6);
        return ranges;

oom_lists:
        safefree (starts);
        safefree (ends);
        safefree (ups);
        safefree (ranges->v4);
        safefree (ranges->v6);
        safefree (ranges);
oom:
        safefree (c4);
        safefree (c6);
        log_message (LOG_ERR, "Unable to allocate memory in "
                     "upstream_ranges_build()");
        return NULL;
}

static struct upstream *
ranges_lookup4 (const struct upstream_ranges *ranges, uint32_t ip)
{
        size_t lo = 0, hi;

        if (!ranges->n4)
                return NULL;
        hi = ranges->n4;
        while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;

                if (ranges->v4[mid].start <= ip)
                        lo = mid + 1;
                else
                        hi = mid;
        }
        if (!lo)
                return NULL;
        if (ip <= ranges->v4[lo - 1].end)
                return ranges->v4[lo - 1].up;
        return NULL;
}

static struct upstream *
ranges_lookup6 (const struct upstream_ranges *ranges, struct u128 ip)
{
        size_t lo = 0, hi;

        if (!ranges->n6)
                return NULL;
        hi = ranges->n6;
        while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;

                if (u128_cmp (ranges->v6[mid].start, ip) <= 0)
                        lo = mid + 1;
                else
                        hi = mid;
        }
        if (!lo)
                return NULL;
        if (u128_cmp (ip, ranges->v6[lo - 1].end) <= 0)
                return ranges->v6[lo - 1].up;
        return NULL;
}

static struct upstream *
upstream_ranges_lookup_ip (const struct upstream_ranges *ranges,
                           const unsigned char ip[IPV6_LEN])
{
        if (!ranges)
                return NULL;
        if (is_v4_mapped (ip))
                return ranges_lookup4 (ranges, u32_from_bytes (ip + 12));
        return ranges_lookup6 (ranges, u128_from_bytes (ip));
}

void
upstream_ranges_free (struct upstream_ranges *ranges)
{
        if (!ranges)
                return;
        safefree (ranges->v4);
        safefree (ranges->v6);
        safefree (ranges);
}

/*
 * Check if a host is in the upstream list
 */
struct upstream *upstream_get (char *host, struct upstream *up,
                               struct upstream_ranges *ranges)
{
        unsigned char ip[IPV6_LEN];
        int is_ip;
        struct upstream *match = NULL;
        struct upstream *default_up = NULL;
        struct upstream *cur;

        /* Parse host to binary IP once */
        is_ip = (host && host[0] && full_inet_pton (host, ip) > 0);

        /* If host is a valid IP, check the CIDR ranges */
        if (is_ip) {
                match = upstream_ranges_lookup_ip (ranges, ip);
                if (match)
                        goto found;
        }

        /* Walk linked list checking only HST_STRING entries */
        for (cur = up; cur; cur = cur->next) {
                if (cur->target.type == HST_NONE) {
                        default_up = cur;
                        break;
                }
                if (cur->target.type == HST_STRING) {
                        if (hostspec_match (host, &cur->target)) {
                                match = cur;
                                goto found;
                        }
                }
        }

        /* If host is a domain name, resolve and check CIDR ranges */
        if (!is_ip && ranges) {
                struct addrinfo hints, *res = NULL;
                int n;
                char ipbuf[16] = {0};
                unsigned char resolved_ip[IPV6_LEN];

                memset (&hints, 0, sizeof (struct addrinfo));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;

                n = getaddrinfo (host, NULL, &hints, &res);
                if (n == 0) {
                        get_ip_string (res->ai_addr, ipbuf, sizeof (ipbuf));
                        freeaddrinfo (res);

                        if (ipbuf[0] && full_inet_pton (ipbuf, resolved_ip) > 0)
                                match = upstream_ranges_lookup_ip (ranges, resolved_ip);
                } else if (res) {
                        freeaddrinfo (res);
                }

                if (match)
                        goto found;
        }

        /* Fall through to default */
        match = default_up;

found:
        if (match && (!match->host))
                match = NULL;

        if (match)
                log_message (LOG_INFO, "Found upstream proxy %s %s:%d for %s",
                             proxy_type_name(match->type), match->host, match->port, host);
        else
                log_message (LOG_INFO, "No upstream proxy for %s", host);

        return match;
}

void free_upstream_list (struct upstream *up)
{
        while (up) {
                struct upstream *tmp = up;
                up = up->next;
                if(tmp->target.type == HST_STRING)
                        safefree (tmp->target.address.string);
                safefree (tmp->host);
                safefree (tmp);
        }
}

#endif
