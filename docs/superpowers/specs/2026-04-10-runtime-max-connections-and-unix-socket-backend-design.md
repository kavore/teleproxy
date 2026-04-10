# Design: Runtime-configurable max connections + unix socket backend for fake-TLS

- **Author:** kavore
- **Date:** 2026-04-10
- **Status:** Draft (awaiting review)
- **Target branch:** `main` (repo: `kavore/teleproxy`)
- **Deploy target:** production MTProto proxy on `2.26.126.16` (teleproxy 4.10.0 @ 7ef583f)

## Motivation

Two intertwined problems surfaced during a production incident on 2026-04-10:

1. **Per-worker connection ceiling is compile-time fixed at 65536.** The `-C 1048576` CLI
   flag in the systemd unit turned out to be cosmetic — it sets
   `max_special_connections`, not `max_connection_fd`. The real enforcement sits in
   `max_connection_fd`, which defaults to `MAX_CONNECTIONS` (65536) because of the
   compile-time static array `ExtConnectionHead[MAX_CONNECTIONS]` in
   `src/mtproto/mtproto-proxy.c:225`. With 32 workers this caps the process at
   ~2.1M concurrent sessions, which was hit during the thundering-herd reconnect
   after a restart.

2. **Fake-TLS probe-forwarding goes through loopback TCP to nginx.** The conntrack
   table overflowed because every legitimate-but-probed connection allocates a new
   loopback TCP flow to the local nginx backend, doubling the conntrack load. Even
   with `nf_conntrack_max` bumped to 4M and `iptables -t raw -j CT --notrack` on
   `lo`, the architectural fix is to switch the backend transport to `AF_UNIX`,
   which conntrack never touches.

Both problems need to be solved in the same rebuild/redeploy cycle.

## Goals

- Make the per-worker hard connection ceiling runtime-configurable via the existing
  `-c` CLI flag (no recompile required to tune further).
- Allow fake-TLS backend (`-D`) to point at a unix-domain socket instead of a TCP
  hostname/port, preserving all existing verification and mimicry behavior.
- Stay backwards-compatible: legacy `-D example.com:443` continues to work
  unchanged, legacy `-c` continues to work unchanged.
- Minimal surgical changes. No unrelated refactoring.

## Non-goals

- Listening on unix sockets (inbound). Only outbound backend.
- Changing the fake-TLS protocol or the probe-detection heuristics.
- Making `MAX_TARGETS` runtime (it is already unused as an array bound).
- Adding new TOML fields beyond what the existing `domains = [...]` array
  naturally carries via the same string parser.

## Part 1 — Runtime-configurable max connections

### Current state

```c
// src/net/net-connections.h
#define MAX_CONNECTIONS 65536
#define MAX_TARGETS     65536
```

```c
// src/net/net-connections.c
static int max_connection_fd = MAX_CONNECTIONS;
int active_special_connections, max_special_connections = MAX_CONNECTIONS;
```

```c
// src/mtproto/mtproto-proxy.c
struct ext_connection ExtConnectionHead[MAX_CONNECTIONS];  // 225
// ...
assert ((unsigned) fd < MAX_CONNECTIONS);                  // ~10 sites
```

```c
// src/net/net-tcp-rpc-ext-drain.c
for (int fd = 0; fd < MAX_CONNECTIONS; fd++) { ... }       // 303
```

The binding runtime limit is `max_connection_fd` (checked in
`alloc_new_connection` at `net-connections.c:582`), but because
`ExtConnectionHead` is a C global static array, its size is fixed at compile
time at `MAX_CONNECTIONS`. Any runtime value above that would index out of
bounds on the very next assert.

### Target state

`ExtConnectionHead` becomes a heap-allocated pointer, sized from
`max_connection_fd` (which is driven by `-c <N>` or defaults to
`MAX_CONNECTIONS`). All compile-time bound checks switch to the runtime
variable. `MAX_CONNECTIONS` stays in the header as the default when no `-c`
flag is passed.

### Code changes

1. `src/net/net-connections.h`:
   - `MAX_CONNECTIONS` stays at `65536` — now documented as "default
     `max_connection_fd` when `-c` not set". No bump.
   - Add `extern int max_connection_fd;` declaration.

2. `src/net/net-connections.c:83`:
   - Remove `static` qualifier from `max_connection_fd`.

3. `src/mtproto/mtproto-proxy.c:225`:
   - Replace `struct ext_connection ExtConnectionHead[MAX_CONNECTIONS];` with
     `struct ext_connection *ExtConnectionHead;` (NULL at load time).

4. `src/mtproto/mtproto-proxy.c` — new init function:
   ```c
   static void init_ext_connection_head(void) {
     assert (ExtConnectionHead == NULL);
     assert (max_connection_fd > 0);
     ExtConnectionHead = calloc ((size_t) max_connection_fd,
                                 sizeof (struct ext_connection));
     if (!ExtConnectionHead) {
       kprintf ("fatal: cannot allocate ExtConnectionHead for %d connections "
                "(%zu bytes)\n",
                max_connection_fd,
                (size_t) max_connection_fd * sizeof (struct ext_connection));
       exit (1);
     }
     vkprintf (0, "ExtConnectionHead: allocated %d slots (%zu MB)\n",
               max_connection_fd,
               (size_t) max_connection_fd * sizeof (struct ext_connection) >> 20);
   }
   ```
   Called from `mtfront_pre_loop()` — the last server-functions callback
   before the event loop starts. At that point each worker has already
   forked, `engine_init` has finalized `max_connection_fd` (including the
   potential `raise_file_limit` clamp in non-root mode), and no connections
   have been accepted yet.

5. `src/mtproto/mtproto-proxy.c` — replace `MAX_CONNECTIONS` in asserts with
   `max_connection_fd`. Affected lines (per grep):
   - 242, 303, 347, 370, 380, 655, 674, 701, 717, 833

6. `src/mtproto/mtproto-proxy-http.c` — same replacement. Affected lines:
   112, 124, 134, 641.

7. `src/net/net-tcp-rpc-ext-drain.c:303`:
   - Replace `for (int fd = 0; fd < MAX_CONNECTIONS; fd++)` with
     `for (int fd = 0; fd < max_connection_fd; fd++)`.

### What stays unchanged

- `engine.c:621` `E->maxconn = MAX_CONNECTIONS` — correct, this is the
  default when `-c` isn't passed, before `set_maxconn` overrides it.
- `engine-net.c:137` `val = MAX_CONNECTIONS` in `set_maxconn(val<=0)` —
  same reasoning.
- `net-connections.c:85` `max_special_connections = MAX_CONNECTIONS` —
  default for inbound special limit. Overridable by `-C` (mtproto-proxy.c:1334).
  Not part of this change.

### Memory cost

`sizeof(struct ext_connection)` = **96 bytes** on x86_64: 7 pointers
(56 bytes) + 4 ints (16 bytes) + 3 long longs (24 bytes), naturally
8-byte aligned with no padding. Part 2 adds `unix_path` to
`struct domain_info`, not to `struct ext_connection`, so this figure is
unchanged by this design.

- At **1,048,576 entries** (recommended): 96 MB per worker × 32 workers
  ≈ **3 GB total**. Within the 107 GB headroom on the production host.
- At 262,144 entries: ~24 MB per worker.
- At 65,536 entries (default): ~6 MB per worker.

### Operator impact

The systemd unit currently has `-C 1048576`, which silently does nothing
useful: it sets `max_special_connections`, not `max_connection_fd`. The
recommended change is to **replace** `-C 1048576` with `-c 1048576`
(lowercase), which routes through `engine-net.c:f_parse_option_net` →
`set_maxconn` → `tcp_set_max_connections` and is the flag this design
actually reads. Example:

```
Before: /usr/local/bin/teleproxy ... -M 32 -C 1048576 ...
After:  /usr/local/bin/teleproxy ... -M 32 -c 1048576 ...
```

The uppercase `-C` can be dropped entirely or left as a duplicate — it
cannot be the bottleneck once `max_connection_fd` is raised.

`raise_file_limit` under root (systemd service) calls
`raise_file_rlimit(maxconn + 16) → setrlimit(RLIMIT_NOFILE, ...)`, which
attempts to bump the per-process fd limit to 1,048,592. **Kernel ceiling
check required:** `setrlimit` cannot raise `rlim_max` above
`fs.nr_open` (sysctl). On modern Linux the default is typically
`1073741816` or `1048576`. Verify on the production host before deploy:

```
cat /proc/sys/fs/nr_open
```

If the value is `< 1048592`, either raise it via `sysctl -w
fs.nr_open=2097152` (persist in `/etc/sysctl.d/`) or reduce `-c` to
`1048560` to stay under a 1,048,576 `fs.nr_open`. A `LimitNOFILE=1048592`
directive in the systemd unit is recommended for clarity — setting it
bounds both `rlim_cur` and `rlim_max` and surfaces misconfigurations at
service-start rather than at `alloc_new_connection` time.

### Risks

- **Init order bug.** If the allocation runs before `max_connection_fd` is
  finalized, we allocate the wrong size. Mitigated by placing the call in
  `mtfront_pre_loop`, which is after `engine_init`, after fork, and
  immediately before the event loop. The assert on `max_connection_fd > 0`
  catches gross misuse.
- **Missed assert site.** If any `assert (x < MAX_CONNECTIONS)` is left
  unchanged and the operator raises `-c` above 65536, the first connection
  with `fd >= 65536` crashes the worker. Mitigated by exhaustive grep across
  the tree (grep output enumerated above — 15 sites total) and by keeping
  `MAX_CONNECTIONS` as the default so legacy deployments stay at 65536 and
  never exercise the new code path.
- **Drain-loop cost.** `tcp_rpcs_drain_force_close_for_slot` is O(N) over the
  full fd table. At 1,048,576 this is 16× slower than the 65536 baseline —
  each iteration is a single `connection_get_by_fd` lookup + type check, so
  total cost is still sub-100 ms even at the top setting. Drain is a rare
  admin operation (secret removal).
- **Init order dependency.** The new allocation runs from a
  server-functions callback. The spec picks `mtfront_pre_loop` (after
  `pre_init`, which forks workers, and `pre_start`, which does config
  reload). **Implementation must verify** that `engine_init` — which calls
  `raise_file_limit` and can clamp `max_connection_fd` down to
  `rlim_cur - 16` in non-root mode — runs strictly before `pre_loop`. If it
  does not, move the call to `pre_start` or later. Grep
  `engine_server_init`, `server_init`, and the callback dispatch in
  `src/engine/engine.c` during implementation to confirm.

## Part 2 — Unix socket backend for fake-TLS

### Current state

`-D <domain>[:port]` → `tcp_rpc_add_proxy_domain` (net-tcp-rpc-ext-server.c:1061)
parses into:

```c
struct domain_info {
  const char *domain;              // SNI hostname
  int port;                        // backend port (default 443)
  struct in_addr target;           // resolved IPv4
  unsigned char target_ipv6[16];   // resolved IPv6
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};
```

At startup, `tcp_rpc_init_proxy_domains` calls `update_domain_info` which
opens 20 parallel raw TCP sockets via `socket(AF_INET/AF_INET6, SOCK_STREAM,
IPPROTO_TCP)` + `connect(sockaddr_in/sockaddr_in6)`, plays a TLS 1.3
handshake, and measures the backend's `ServerHello` encrypted data length to
drive DRS (dynamic record sizing) mimicry.

At runtime, `proxy_connection` (net-tcp-rpc-ext-server.c:1246) forwards
probe traffic by opening a new outbound TCP socket through
`client_socket` / `client_socket_ipv6` (net-events.c:637, 705) and wrapping
it in `alloc_new_connection(..., ct_proxy_pass, ...)`.

All of this is hard-wired to TCP families.

### Target state

A new unix-socket backend path runs in parallel to the existing TCP path.
Per-domain, selected by a new `@unix:` delimiter in the `-D` argument.

### Syntax

```
-D example.com@unix:/run/nginx-mtproxy.sock
```

- Left of `@unix:` — SNI hostname (unchanged semantics; used for
  `get_sni_domain_info` match and hash bucket).
- Right of `@unix:` — absolute filesystem path to the backend AF_UNIX
  stream socket. Max 107 bytes (`sizeof(sockaddr_un.sun_path) - 1`).
- No colon-port parsing on the right side; port concept is meaningless.
- Detection: `strstr(arg, "@unix:")`. If found and the path is non-empty,
  this is a unix-socket domain. Otherwise, fall through to legacy parsing.
- Works identically in the TOML `domains = [...]` array because the same
  `tcp_rpc_add_proxy_domain` parser handles it.

Legacy `-D example.com:443`, `-D [::1]:443`, `-D 127.0.0.1:8443` unchanged.

### Data structure change

```c
struct domain_info {
  const char *domain;
  int port;                        // 0 when unix_path is set
  struct in_addr target;           // zeroed when unix_path is set
  unsigned char target_ipv6[16];   // zeroed when unix_path is set
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  const char *unix_path;           // NEW — NULL for TCP domains
  struct domain_info *next;
};
```

### Parser change — `tcp_rpc_add_proxy_domain` (net-tcp-rpc-ext-server.c:1061)

At the top of the function, before the IPv6/host:port parsing, branch on
`@unix:` detection and wrap the legacy parser in an `else` so both paths
converge on the same bucket-insert / `default_domain_info` wiring at the
bottom of the function:

```c
const char *at_unix = strstr (domain, "@unix:");
if (at_unix != NULL && at_unix[6] != '\0') {
  size_t sni_len = at_unix - domain;
  if (sni_len == 0) {
    kprintf ("Invalid domain spec: empty SNI hostname before @unix: in %s\n", domain);
    free (info); return;
  }
  const char *path = at_unix + 6;
  /* reject paths that do not fit in sockaddr_un */
  if (strlen (path) >= sizeof (((struct sockaddr_un *)0)->sun_path)) {
    kprintf ("Invalid domain spec: unix socket path too long in %s\n", domain);
    free (info); return;
  }
  info->domain = strndup (domain, sni_len);
  info->unix_path = strdup (path);
  info->port = 0;
  kprintf ("Proxy domain: %s@unix:%s\n", info->domain, info->unix_path);
} else {
  /* existing legacy parsing unchanged — IPv6 bracketed form, host:port,
     or bare host; sets info->domain and info->port */
}

/* shared tail — bucket insert + default_domain_info wiring (unchanged) */
```

Detection is safe: `@` is not a valid character in DNS hostnames or in
bracketed-IPv6 literals, so no legacy input can accidentally match the
`@unix:` substring.

### Verification change — `update_domain_info` (net-tcp-rpc-ext-server.c:742)

At the top, add an early branch:

```c
int af;
if (info->unix_path != NULL) {
  af = AF_UNIX;
  /* skip DNS resolution */
} else {
  /* existing inet_pton + kdb_gethostbyname logic */
}
```

Inside the `TRIES` loop, the socket creation and connect become:

```c
if (af == AF_UNIX) {
  sockets[i] = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sockets[i] < 0) { ...fail... }
  if (fcntl (sockets[i], F_SETFL, O_NONBLOCK) == -1) { ...fail... }
  struct sockaddr_un addr;
  memset (&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  strcpy (addr.sun_path, info->unix_path);   /* length already validated */
  int e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof addr);
  if (e_connect == -1 && errno != EINPROGRESS) {
    kprintf ("Failed to connect to %s@unix:%s: %s\n",
             info->domain, info->unix_path, strerror (errno));
    return 0;
  }
} else {
  /* existing AF_INET / AF_INET6 branches unchanged */
}
```

The rest of `update_domain_info` (TLS request/response plumbing, response
size measurement, extension order detection) operates on file descriptors
and is address-family-agnostic — zero changes needed.

On verification failure, the same existing fallback applies:
`use_random_encrypted_size = 1; server_hello_encrypted_size = 2500 + rand()%1120`.
Startup does not fail. The operator sees a log warning and mimicry uses
randomized defaults.

### Forwarding change — `proxy_connection` (net-tcp-rpc-ext-server.c:1246)

Before the `target.s_addr == 0 && memcmp(target_ipv6, zero, 16) == 0`
bail-out check, add the unix branch:

```c
if (info->unix_path != NULL) {
  int cfd = client_socket_unix (info->unix_path);
  if (cfd < 0) {
    kprintf ("failed to connect to %s@unix:%s: %m", info->domain, info->unix_path);
    fail_connection (C, -27);
    return 0;
  }
  c->type->crypto_free (C);
  job_incref (C);
  const unsigned char zero_ipv6[16] = {};
  job_t EJ = alloc_new_connection (
      cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C,
      0, (void *) zero_ipv6, 0);
  if (!EJ) {
    kprintf ("failed to create proxy pass connection (unix) (2)");
    job_decref_f (C);
    fail_connection (C, -37);
    return 0;
  }
  c->type = &ct_proxy_pass;
  c->extra = job_incref (EJ);
  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));
  return c->type->parse_execute (C);
}
/* ...existing TCP path... */
```

### New helper — `client_socket_unix`

New function in `src/net/net-events.c`, declared in `src/net/net-events.h`:

```c
int client_socket_unix (const char *path) {
  if (!path || !*path) return -1;
  size_t plen = strlen (path);
  if (plen >= sizeof (((struct sockaddr_un *)0)->sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int flags;
  if ((flags = fcntl (fd, F_GETFL, 0)) < 0 ||
      fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close (fd);
    return -1;
  }
  struct sockaddr_un addr;
  memset (&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  memcpy (addr.sun_path, path, plen + 1);
  if (connect (fd, (struct sockaddr *)&addr, sizeof addr) == -1 &&
      errno != EINPROGRESS) {
    int saved = errno;
    close (fd);
    errno = saved;
    return -1;
  }
  return fd;
}
```

No `SO_KEEPALIVE`, `TCP_NODELAY`, or `TCP_KEEPIDLE` calls — those are
TCP-only and would set `errno = ENOPROTOOPT` on AF_UNIX. Required header:
`#include <sys/un.h>` in net-events.c (and in net-tcp-rpc-ext-server.c for
the inline `sockaddr_un` usage in `update_domain_info`).

### CLI help text

In `mtproto-proxy.c` wherever `-D` is documented in `parse_usage()` /
`mtfront_prepare_parse_options`, extend the description:

```
  -D <domain>[:port]             fake-TLS: mimic <domain>, forward to TCP backend
  -D <domain>@unix:<path>        fake-TLS: mimic <domain>, forward to unix socket
```

### Documentation

Add a new sub-section **"Unix socket backend"** under **"Custom TLS Backend
(TCP Splitting)"** in both:

- `docs/features/fake-tls.md`
- `docs/features/fake-tls.ru.md`

Content covers:

- Motivation (eliminates loopback TCP + conntrack overhead on high-traffic
  proxies).
- Syntax `-D example.com@unix:/run/nginx.sock`.
- nginx example listening on `listen unix:/run/nginx-mtproxy.sock ssl;`.
- Filesystem permissions: teleproxy process (typically `-u nobody`) must
  have rw access to the socket. Recommend `chmod 660` + a shared group,
  or systemd `ListenStream=/run/...` with `SocketUser=`/`SocketGroup=`.
- Note that the TLS 1.3 verification still runs at startup over the unix
  socket — the backend must already be listening when teleproxy starts.

CHANGELOG.md entry:

```
## [unreleased]
### Added
- `MAX_CONNECTIONS` is now runtime-configurable via existing `-c` flag;
  `ExtConnectionHead` is heap-allocated based on `-c` value.
- fake-TLS `-D` supports unix-socket backends: `-D domain@unix:/path/to/sock`.
### Fixed
- `-c` flag now actually controls the hard per-worker connection ceiling
  (previously capped at compile-time `MAX_CONNECTIONS = 65536`).
```

## Testing strategy

**Local (mandatory before touching prod):**
1. Build clean: `nice -n 19 make -j4` from a fresh clone.
2. Run with legacy flags (no `-c`): confirm behavior unchanged, startup
   log shows `ExtConnectionHead: allocated 65536 slots`.
3. Run with `-c 1048576`: confirm startup log shows `1048576 slots`, memory
   usage jumps by ~96 MB per process.
4. Run with `-D example.com@unix:/tmp/fake.sock` pointing at a local nginx
   on unix socket: confirm startup verification log line, confirm a probe
   request (`curl -k https://127.0.0.1:<teleproxy-port>/`) gets forwarded
   to nginx and returns the expected page.
5. Run with `-D example.com@unix:/nonexistent.sock`: confirm warning log
   and that startup does NOT fail, falls back to random encrypted sizes.
6. Stress: `-c 100000` plus open ~70000 concurrent connections (e.g. via
   `hping3` or a custom client), confirm none rejected by the fd ceiling.
   Confirm no assert crashes at fd > 65536.
7. Parser negative tests: `-D @unix:/foo` (empty SNI), `-D foo@unix:` (empty
   path), `-D foo@unix:/` + 200-char path (too long). All should log a
   clear error and not register the domain.

**On prod (post user approval only):**
1. Stop-copy-start one unit at a time (`mtproxy-dd` first, wait for
   stabilization via `--http-stats` `active_special_connections`, then
   `mtproxy-tls`).
2. Between restarts monitor `nf_conntrack` count + load average +
   `/proc/<pid>/fd` count to verify the fd ceiling lifted.

## Rollback plan

- Binary rollback: `/usr/local/bin/teleproxy` is a single file. Keep the
  previous binary at `/usr/local/bin/teleproxy.prev` before `install`.
  Rollback = copy back + `systemctl restart`.
- Config rollback: when `-c 1048576` (and optional `LimitNOFILE=1048592`)
  is added to the systemd unit, keep the old unit file staged as
  `/etc/systemd/system/mtproxy-*.service.prev` for one-command revert
  (`cp *.prev *.service && systemctl daemon-reload && systemctl restart`).
- No on-disk state changes (no migration), so rollback is binary-level only.

## Out of scope (explicit non-commitments)

- No `listen unix:` support (inbound unix sockets).
- No per-domain TOML schema extension (unix config piggy-backs on the
  existing `domains` string array through the same parser).
- No changes to probe detection, rate limiting, DRS, or protocol handling.
- No changes to `MAX_TARGETS`, `DOMAIN_HASH_MOD`, `EXT_CONN_TABLE_SIZE`,
  or any other constant that is not directly in scope.
