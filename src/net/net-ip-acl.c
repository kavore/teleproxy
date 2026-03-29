/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2026 Teleproxy contributors
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "net/net-ip-acl.h"
#include "common/kprintf.h"

struct ip_acl_rule {
  int family;          /* AF_INET or AF_INET6 */
  int prefix_len;
  union {
    unsigned v4;       /* host byte order */
    unsigned char v6[16];
  } addr;
};

struct ip_acl {
  struct ip_acl_rule *rules;
  int count;
  int capacity;
};

static struct ip_acl * volatile current_blocklist;
static struct ip_acl * volatile current_allowlist;
static struct ip_acl *stats_allowlist;
static char *blocklist_file;
static char *allowlist_file;

void ip_acl_set_blocklist_file (const char *path) {
  free (blocklist_file);
  blocklist_file = path ? strdup (path) : NULL;
  if (path && !blocklist_file) { kprintf ("ip_acl: strdup failed for blocklist path\n"); }
}

void ip_acl_set_allowlist_file (const char *path) {
  free (allowlist_file);
  allowlist_file = path ? strdup (path) : NULL;
  if (path && !allowlist_file) { kprintf ("ip_acl: strdup failed for allowlist path\n"); }
}

static void ip_acl_free (struct ip_acl *acl) {
  if (acl) {
    free (acl->rules);
    free (acl);
  }
}

/* Deferred free list: old ACLs freed after a grace period so readers
   that already loaded the pointer can finish without use-after-free. */
#define ACL_DEFER_SLOTS 4
static struct ip_acl * volatile acl_defer_list[ACL_DEFER_SLOTS];
static int acl_defer_pos;

static void acl_defer_free (struct ip_acl *old) {
  if (!old) return;
  struct ip_acl *very_old = acl_defer_list[acl_defer_pos];
  acl_defer_list[acl_defer_pos] = old;
  acl_defer_pos = (acl_defer_pos + 1) % ACL_DEFER_SLOTS;
  if (very_old) {
    ip_acl_free (very_old);
  }
}

static struct ip_acl *ip_acl_alloc (void) {
  struct ip_acl *acl = calloc (1, sizeof (struct ip_acl));
  return acl;
}

static int ip_acl_add_rule (struct ip_acl *acl, const struct ip_acl_rule *rule) {
  if (acl->count >= acl->capacity) {
    int new_cap = acl->capacity ? acl->capacity * 2 : 16;
    struct ip_acl_rule *new_rules = realloc (acl->rules, new_cap * sizeof (struct ip_acl_rule));
    if (!new_rules) {
      return -1;
    }
    acl->rules = new_rules;
    acl->capacity = new_cap;
  }
  acl->rules[acl->count++] = *rule;
  return 0;
}

/* Mask off host bits for an IPv4 address (host byte order). */
static unsigned mask_v4 (unsigned addr, int prefix_len) {
  if (prefix_len <= 0) {
    return 0;
  }
  if (prefix_len >= 32) {
    return addr;
  }
  unsigned mask = 0xFFFFFFFFu << (32 - prefix_len);
  return addr & mask;
}

/* Mask off host bits for an IPv6 address in-place. */
static void mask_v6 (unsigned char addr[16], int prefix_len) {
  int i;
  for (i = 0; i < 16; i++) {
    int bits = prefix_len - i * 8;
    if (bits >= 8) {
      /* full byte kept */
    } else if (bits > 0) {
      addr[i] &= (unsigned char)(0xFF << (8 - bits));
    } else {
      addr[i] = 0;
    }
  }
}

/* Parse a CIDR string into an ip_acl_rule.
   Modifies the input string (splits on '/').
   Returns 0 on success, -1 on parse error. */
static int ip_acl_parse_cidr (char *s, struct ip_acl_rule *rule) {
  memset (rule, 0, sizeof (*rule));

  char *slash = strchr (s, '/');
  int explicit_prefix = 0;
  if (slash) {
    *slash = '\0';
    char *endptr;
    rule->prefix_len = (int)strtol (slash + 1, &endptr, 10);
    if (*endptr && !isspace ((unsigned char)*endptr)) {
      return -1;
    }
    explicit_prefix = 1;
  }

  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton (AF_INET, s, &addr4) == 1) {
    rule->family = AF_INET;
    rule->addr.v4 = ntohl (addr4.s_addr);
    if (!explicit_prefix) {
      rule->prefix_len = 32;
    }
    if (rule->prefix_len < 0 || rule->prefix_len > 32) {
      return -1;
    }
    rule->addr.v4 = mask_v4 (rule->addr.v4, rule->prefix_len);
  } else if (inet_pton (AF_INET6, s, &addr6) == 1) {
    rule->family = AF_INET6;
    memcpy (rule->addr.v6, addr6.s6_addr, 16);
    if (!explicit_prefix) {
      rule->prefix_len = 128;
    }
    if (rule->prefix_len < 0 || rule->prefix_len > 128) {
      return -1;
    }
    mask_v6 (rule->addr.v6, rule->prefix_len);
  } else {
    return -1;
  }

  return 0;
}

static int match_v4 (const struct ip_acl_rule *rule, unsigned ip) {
  if (rule->family != AF_INET) {
    return 0;
  }
  return mask_v4 (ip, rule->prefix_len) == rule->addr.v4;
}

static int match_v6 (const struct ip_acl_rule *rule, const unsigned char ipv6[16]) {
  if (rule->family != AF_INET6) {
    return 0;
  }
  int i;
  for (i = 0; i < 16; i++) {
    int bits = rule->prefix_len - i * 8;
    unsigned char mask;
    if (bits >= 8) {
      mask = 0xFF;
    } else if (bits > 0) {
      mask = (unsigned char)(0xFF << (8 - bits));
    } else {
      mask = 0;
    }
    if ((ipv6[i] & mask) != rule->addr.v6[i]) {
      return 0;
    }
  }
  return 1;
}

static int acl_contains_v4 (const struct ip_acl *acl, unsigned ip) {
  if (!acl) {
    return 0;
  }
  int i;
  for (i = 0; i < acl->count; i++) {
    if (match_v4 (&acl->rules[i], ip)) {
      return 1;
    }
  }
  return 0;
}

static int acl_contains_v6 (const struct ip_acl *acl, const unsigned char ipv6[16]) {
  if (!acl) {
    return 0;
  }
  int i;
  for (i = 0; i < acl->count; i++) {
    if (match_v6 (&acl->rules[i], ipv6)) {
      return 1;
    }
  }
  return 0;
}

/* Check if an IPv6 address is a v4-mapped address (::ffff:x.x.x.x).
   Returns the IPv4 address in host byte order, or 0 if not v4-mapped. */
static unsigned v6_to_v4_mapped (const unsigned char ipv6[16]) {
  static const unsigned char v4mapped_prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xFF,0xFF};
  if (memcmp (ipv6, v4mapped_prefix, 12) == 0) {
    return ((unsigned)ipv6[12] << 24) | ((unsigned)ipv6[13] << 16) |
           ((unsigned)ipv6[14] << 8) | (unsigned)ipv6[15];
  }
  return 0;
}

int ip_acl_check_v4 (unsigned ip) {
  if (current_allowlist && current_allowlist->count > 0) {
    return acl_contains_v4 (current_allowlist, ip);
  }
  if (current_blocklist && current_blocklist->count > 0) {
    return !acl_contains_v4 (current_blocklist, ip);
  }
  return 1;
}

int ip_acl_check_v6 (const unsigned char ipv6[16]) {
  /* Check v4-mapped addresses against IPv4 rules too */
  unsigned v4 = v6_to_v4_mapped (ipv6);

  if (current_allowlist && current_allowlist->count > 0) {
    if (acl_contains_v6 (current_allowlist, ipv6)) {
      return 1;
    }
    if (v4 && acl_contains_v4 (current_allowlist, v4)) {
      return 1;
    }
    return 0;
  }
  if (current_blocklist && current_blocklist->count > 0) {
    if (acl_contains_v6 (current_blocklist, ipv6)) {
      return 0;
    }
    if (v4 && acl_contains_v4 (current_blocklist, v4)) {
      return 0;
    }
  }
  return 1;
}

static char *trim (char *s) {
  while (*s && isspace ((unsigned char)*s)) {
    s++;
  }
  char *end = s + strlen (s);
  while (end > s && isspace ((unsigned char)end[-1])) {
    end--;
  }
  *end = '\0';
  return s;
}

static struct ip_acl *ip_acl_load (const char *filename) {
  FILE *f = fopen (filename, "r");
  if (!f) {
    kprintf ("ip_acl: cannot open '%s': %m\n", filename);
    return NULL;
  }

  struct ip_acl *acl = ip_acl_alloc ();
  if (!acl) {
    fclose (f);
    return NULL;
  }

  char line[256];
  int lineno = 0;

  while (fgets (line, sizeof (line), f)) {
    lineno++;
    /* detect truncated lines */
    size_t ll = strlen (line);
    if (ll > 0 && line[ll - 1] != '\n' && !feof (f)) {
      kprintf ("ip_acl: %s:%d: line too long, skipping\n", filename, lineno);
      int ch;
      while ((ch = fgetc (f)) != EOF && ch != '\n') {}
      continue;
    }
    char *s = trim (line);

    /* skip empty lines and comments */
    if (!*s || *s == '#') {
      continue;
    }

    struct ip_acl_rule rule;
    if (ip_acl_parse_cidr (s, &rule) < 0) {
      kprintf ("ip_acl: %s:%d: cannot parse CIDR '%s'\n", filename, lineno, s);
      continue;
    }

    if (ip_acl_add_rule (acl, &rule) < 0) {
      kprintf ("ip_acl: %s:%d: out of memory\n", filename, lineno);
      ip_acl_free (acl);
      fclose (f);
      return NULL;
    }
  }

  fclose (f);
  kprintf ("ip_acl: loaded %d rules from '%s'\n", acl->count, filename);
  return acl;
}

int ip_acl_reload (void) {
  if (!blocklist_file && !allowlist_file) {
    return 0;
  }

  struct ip_acl *new_bl = NULL, *new_al = NULL;

  if (blocklist_file) {
    new_bl = ip_acl_load (blocklist_file);
    if (!new_bl && !current_blocklist) {
      return -1;
    }
    if (!new_bl) {
      kprintf ("ip_acl: keeping existing blocklist (%d rules)\n", current_blocklist->count);
    }
  }

  if (allowlist_file) {
    new_al = ip_acl_load (allowlist_file);
    if (!new_al && !current_allowlist) {
      ip_acl_free (new_bl);
      return -1;
    }
    if (!new_al) {
      kprintf ("ip_acl: keeping existing allowlist (%d rules)\n", current_allowlist->count);
    }
  }

  /* swap with deferred free: old ACLs are kept alive for a grace period
     so concurrent readers (ip_acl_check_v4/v6) don't hit use-after-free */
  struct ip_acl *old_bl = current_blocklist;
  struct ip_acl *old_al = current_allowlist;
  if (new_bl) { __sync_synchronize (); current_blocklist = new_bl; }
  if (new_al) { __sync_synchronize (); current_allowlist = new_al; }
  __sync_synchronize ();
  if (new_bl) { acl_defer_free ((struct ip_acl *)old_bl); }
  if (new_al) { acl_defer_free ((struct ip_acl *)old_al); }

  return 0;
}

int ip_acl_blocklist_count (void) {
  return current_blocklist ? current_blocklist->count : 0;
}

int ip_acl_allowlist_count (void) {
  return current_allowlist ? current_allowlist->count : 0;
}

int ip_acl_add_stats_net (const char *cidr) {
  char buf[256];
  int len = snprintf (buf, sizeof (buf), "%s", cidr);
  if (len <= 0 || len >= (int)sizeof (buf)) {
    return -1;
  }

  char *s = trim (buf);
  if (!*s) {
    return -1;
  }

  struct ip_acl_rule rule;
  if (ip_acl_parse_cidr (s, &rule) < 0) {
    return -1;
  }

  if (!stats_allowlist) {
    stats_allowlist = ip_acl_alloc ();
    if (!stats_allowlist) {
      return -1;
    }
  }

  return ip_acl_add_rule (stats_allowlist, &rule);
}

int ip_acl_check_stats_v4 (unsigned ip) {
  return acl_contains_v4 (stats_allowlist, ip);
}
