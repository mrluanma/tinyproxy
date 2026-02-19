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
 * Binary prefix trie for O(W) CIDR upstream lookups (W=128 for IPv6).
 */
struct upstream_trie_node {
        struct upstream_trie_node *children[2];
        struct upstream *entry;   /* non-NULL if a CIDR prefix ends here */
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
upstream_trie_insert (struct upstream_trie_node **root, struct upstream *entry)
{
        int prefix_len, i;
        const unsigned char *network;
        struct upstream_trie_node *node;

        prefix_len = prefix_length_from_mask (entry->target.address.ip.mask);
        network = entry->target.address.ip.network;

        if (!*root) {
                *root = (struct upstream_trie_node *)
                        safecalloc (1, sizeof (struct upstream_trie_node));
                if (!*root)
                        return -1;
        }

        node = *root;
        for (i = 0; i < prefix_len; i++) {
                int bit = (network[i / 8] >> (7 - (i % 8))) & 1;

                if (!node->children[bit]) {
                        node->children[bit] = (struct upstream_trie_node *)
                                safecalloc (1, sizeof (struct upstream_trie_node));
                        if (!node->children[bit])
                                return -1;
                }
                node = node->children[bit];
        }

        /* First insertion for this prefix wins (matches list-scan order) */
        if (!node->entry)
                node->entry = entry;
        return 0;
}

struct upstream_trie_node *
upstream_trie_build (struct upstream *upstream_list)
{
        struct upstream_trie_node *root = NULL;
        struct upstream *up = upstream_list;

        while (up) {
                if (up->target.type == HST_NUMERIC) {
                        if (upstream_trie_insert (&root, up) < 0) {
                                upstream_trie_free (root);
                                return NULL;
                        }
                }
                up = up->next;
        }
        return root;
}

static struct upstream *
upstream_trie_lookup_ip (struct upstream_trie_node *root,
                         const unsigned char ip[IPV6_LEN])
{
        struct upstream_trie_node *node = root;
        struct upstream *best = NULL;
        int i;

        if (!node)
                return NULL;

        if (node->entry)
                best = node->entry;

        for (i = 0; i < IPV6_LEN * 8; i++) {
                int bit = (ip[i / 8] >> (7 - (i % 8))) & 1;

                node = node->children[bit];
                if (!node)
                        break;
                if (node->entry)
                        best = node->entry;
        }
        return best;
}

void
upstream_trie_free (struct upstream_trie_node *node)
{
        if (!node)
                return;
        upstream_trie_free (node->children[0]);
        upstream_trie_free (node->children[1]);
        safefree (node);
}

/*
 * Check if a host is in the upstream list
 */
struct upstream *upstream_get (char *host, struct upstream *up,
                               struct upstream_trie_node *trie)
{
        unsigned char ip[IPV6_LEN];
        int is_ip;
        struct upstream *match = NULL;
        struct upstream *default_up = NULL;
        struct upstream *cur;

        /* Parse host to binary IP once */
        is_ip = (host && host[0] && full_inet_pton (host, ip) > 0);

        /* If host is a valid IP, check the CIDR trie */
        if (is_ip) {
                match = upstream_trie_lookup_ip (trie, ip);
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

        /* If host is a domain name, resolve and check CIDR trie */
        if (!is_ip && trie) {
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
                                match = upstream_trie_lookup_ip (trie, resolved_ip);
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
