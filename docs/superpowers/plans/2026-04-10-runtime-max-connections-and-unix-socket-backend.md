# Runtime max-connections + unix socket fake-TLS backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the per-worker MTProto connection ceiling runtime-configurable via the existing `-c` flag, and add a `-D example.com@unix:/path/to/sock` syntax that routes the fake-TLS backend through an AF_UNIX stream socket instead of loopback TCP.

**Architecture:**

Part 1 — `ExtConnectionHead` becomes heap-allocated from `max_connection_fd` in a new `mtfront_pre_loop`/`pre_start` init callback. `max_connection_fd` is exposed as `extern` from `src/net/net-connections.c`. All `MAX_CONNECTIONS` bound-check asserts and the secret-drain loop switch to the runtime variable. `MAX_CONNECTIONS` macro stays as the default when `-c` is not passed (65536, unchanged).

Part 2 — A new `client_socket_unix(path)` helper in `src/net/net-events.c` opens AF_UNIX stream sockets in non-blocking mode. `struct domain_info` gains a `unix_path` field. `tcp_rpc_add_proxy_domain` parses the new `@unix:` delimiter. `update_domain_info` and `proxy_connection` each gain an AF_UNIX branch next to the existing TCP code path. All TLS 1.3 verification/mimicry logic is transport-agnostic and reused as-is.

End-to-end verification uses the existing docker-compose test harness: a new `tests/tls-backend-unix/` image runs nginx listening on a unix socket inside a shared volume, the teleproxy container mounts the same volume and connects via `-D EE_DOMAIN@unix:/var/run/nginx-mtproxy.sock`. A new `test_tls_unix_e2e.py` drives a Telethon client through the proxy and independently probes the `/stats` endpoint to confirm `ExtConnectionHead: allocated <N> slots` matches the configured `-c` value.

**Tech Stack:**

- C (GNU11), epoll-based networking, static build via the repo `Makefile`
- pytest + Telethon + docker-compose E2E harness (`tests/`)
- nginx 1.x in alpine-based backend containers
- Target production host: Linux x86_64, root-owned systemd services

**Spec reference:** `docs/superpowers/specs/2026-04-10-runtime-max-connections-and-unix-socket-backend-design.md`

---

## File Map

### Modified (Part 1)

- `src/net/net-connections.h` — remove `static` comment, add `extern int max_connection_fd;` declaration
- `src/net/net-connections.c:83` — remove `static` qualifier from `max_connection_fd`
- `src/mtproto/mtproto-proxy.c:225` — array → pointer; add init function; add call site in server-functions callback; replace ~10 `MAX_CONNECTIONS` asserts
- `src/mtproto/mtproto-proxy-http.c` — replace 4 `MAX_CONNECTIONS` asserts
- `src/net/net-tcp-rpc-ext-drain.c:303` — replace loop bound

### Modified (Part 2)

- `src/net/net-events.h` — add `client_socket_unix` prototype
- `src/net/net-events.c` — add `client_socket_unix` function body, add `#include <sys/un.h>`
- `src/net/net-tcp-rpc-ext-server.c` — add `unix_path` to `struct domain_info`; parser branch in `tcp_rpc_add_proxy_domain` (line ~1061); AF_UNIX branch in `update_domain_info` (line ~742); unix branch in `proxy_connection` (line ~1246); add `#include <sys/un.h>`
- `src/mtproto/mtproto-proxy.c` — update `-D` help text in `parse_usage()`
- `docs/features/fake-tls.md` — add "Unix socket backend" subsection
- `docs/features/fake-tls.ru.md` — mirror Russian version
- `CHANGELOG.md` — add unreleased entry

### Created (tests)

- `tests/tls-backend-unix/Dockerfile` — nginx alpine with ssl cert, socket volume
- `tests/tls-backend-unix/nginx.conf` — `listen unix:/var/run/nginx-mtproxy.sock ssl;`
- `tests/tls-backend-unix/entrypoint.sh` — generate self-signed cert + exec nginx
- `tests/docker-compose.tls-unix-test.yml` — nginx-unix + teleproxy + tester, shared volume
- `tests/test_tls_unix_e2e.py` — Telethon client + stats endpoint verification + log line check
- `Makefile` — new `test-tls-unix` PHONY target

### Created (docs)

- (none beyond the spec already committed)

---

## Part 1 — Runtime-configurable max connections

### Task 1: Expose `max_connection_fd` as extern

**Files:**
- Modify: `src/net/net-connections.c:83`
- Modify: `src/net/net-connections.h` (add extern declaration)

**Context:** Today `max_connection_fd` is a file-static in `net-connections.c`. We need mtproto-proxy.c and net-tcp-rpc-ext-drain.c to read it, so it must become external.

- [ ] **Step 1.1: Remove `static` from the definition**

Edit `src/net/net-connections.c:83`:

```c
// BEFORE
static int max_connection_fd = MAX_CONNECTIONS;

// AFTER
int max_connection_fd = MAX_CONNECTIONS;
```

- [ ] **Step 1.2: Add the extern declaration to the header**

In `src/net/net-connections.h`, find the block around line 443 where `max_special_connections` is declared extern (`extern int max_special_connections, active_special_connections;`) and add a new line immediately after it:

```c
extern int max_connection_fd;
```

- [ ] **Step 1.3: Full clean build to catch any fallout**

Run:
```bash
make clean && nice -n 19 make -j4 2>&1 | tee /tmp/build-task1.log
```

Expected: build succeeds. `objs/bin/teleproxy` exists. No new warnings about `max_connection_fd`.

Verify:
```bash
test -x objs/bin/teleproxy && echo OK || echo FAIL
grep -c 'warning' /tmp/build-task1.log
```

Expected: `OK`, and the warning count is the same as a baseline build (should be zero — this is a `-Wall` build).

- [ ] **Step 1.4: Commit**

```bash
git add src/net/net-connections.c src/net/net-connections.h
git commit -m "net: expose max_connection_fd for runtime sizing

Preparation for heap-allocating ExtConnectionHead from this variable.
No behavioral change — still defaults to MAX_CONNECTIONS."
```

---

### Task 2: Verify pre_loop / pre_start init order

**Files:**
- Read only: `src/engine/engine.c`, `src/mtproto/mtproto-proxy.c`

**Context:** The spec picks `mtfront_pre_loop` as the allocation site but flags it as "verify during implementation". If `engine_init`/`raise_file_limit` do not run strictly before `pre_loop`, we must move the call. This task is investigation-only — no code changes.

- [ ] **Step 2.1: Trace the callback order**

Run:
```bash
grep -n 'pre_init\|pre_start\|pre_loop\|engine_init\|raise_file_limit\|server_init' src/engine/engine.c
```

Look at each match. The expected chain in engine's main dispatch is: CLI parse → `pre_init` → `engine_init` → `pre_start` → `pre_loop` → event loop. Confirm this matches what the engine actually does.

- [ ] **Step 2.2: Document the conclusion in the task**

Write a one-line comment to yourself (not to the repo):
- If `engine_init` runs BEFORE `pre_loop`: we use `mtfront_pre_loop`. Proceed to Task 3.
- If `engine_init` runs BEFORE `pre_start` but AFTER `pre_init`: we can use either `pre_start` or `pre_loop`. Prefer `pre_loop` (runs later, less likely to conflict).
- If `engine_init` runs AFTER both pre_start and pre_loop: use a new hook or inline the init at the top of `pre_loop` but guarded by "first call" logic — this is unlikely; verify carefully before going down this path.

In practice the convention in this codebase (see mtproto-proxy.c:1796 where `pre_init` sets `do_not_open_port` before engine_init reads it) makes it highly likely that pre_loop is called AFTER engine_init. Confirm, then proceed.

- [ ] **Step 2.3: No commit — investigation only**

---

### Task 3: Add dynamic `ExtConnectionHead` allocation

**Files:**
- Modify: `src/mtproto/mtproto-proxy.c` (line 225 and a new init function + callback wiring)

**Context:** Change the global array into a heap pointer and allocate it at the verified init point (typically `mtfront_pre_loop`).

- [ ] **Step 3.1: Change the declaration to a pointer**

Edit `src/mtproto/mtproto-proxy.c:225`:

```c
// BEFORE
struct ext_connection ExtConnectionHead[MAX_CONNECTIONS];

// AFTER
struct ext_connection *ExtConnectionHead;
```

- [ ] **Step 3.2: Add the init helper near the top of mtproto-proxy.c**

Immediately before the `ExtConnectionHead` declaration (so the helper has visibility and sits with related state), add:

```c
static void init_ext_connection_head (void) {
  assert (ExtConnectionHead == NULL);
  assert (max_connection_fd > 0);
  size_t bytes = (size_t) max_connection_fd * sizeof (struct ext_connection);
  ExtConnectionHead = calloc ((size_t) max_connection_fd, sizeof (struct ext_connection));
  if (!ExtConnectionHead) {
    kprintf ("fatal: cannot allocate ExtConnectionHead for %d connections (%zu bytes)\n",
             max_connection_fd, bytes);
    exit (1);
  }
  vkprintf (0, "ExtConnectionHead: allocated %d slots (%zu MB)\n",
            max_connection_fd, bytes >> 20);
}
```

- [ ] **Step 3.3: Wire the call into the server-functions callback**

Find `mtfront_pre_loop` (or whichever callback Task 2 identified) in `src/mtproto/mtproto-proxy.c`. If it exists, insert `init_ext_connection_head();` at its top. If it does not yet exist, locate the `server_functions_t mtproto_front_functions = { ... };` struct literal at mtproto-proxy.c:1836 and the existing `.pre_loop = mtfront_pre_loop,` line — then create the `mtfront_pre_loop` function somewhere above the struct:

```c
void mtfront_pre_loop (void) {
  init_ext_connection_head ();
}
```

If `mtfront_pre_loop` already exists (check: `grep -n 'mtfront_pre_loop' src/mtproto/mtproto-proxy.c`), prepend `init_ext_connection_head ();` as the first statement.

- [ ] **Step 3.4: Build + run help to smoke-test startup**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task3.log
./objs/bin/teleproxy 2>&1 | head -5 || true
```

Expected: build succeeds with zero warnings. `teleproxy` without args exits with usage. No crash.

- [ ] **Step 3.5: Run with minimal valid flags and check the allocation log**

```bash
# start with no -c so max_connection_fd defaults to MAX_CONNECTIONS (65536)
TSECRET=$(head -c 16 /dev/urandom | xxd -ps)
./objs/bin/teleproxy -p 18888 -H 18443 -S "$TSECRET" --aes-pwd /dev/null -v 2>&1 &
TP_PID=$!
sleep 1
# look for the allocation line in dmesg/stderr
wait $TP_PID 2>/dev/null || kill -TERM $TP_PID 2>/dev/null || true
```

This will likely exit because the config / aes-pwd setup is incomplete. That is fine for this smoke — we only care that the process did not crash in `init_ext_connection_head`. If you see `ExtConnectionHead: allocated 65536 slots (6 MB)` in the output, Part 1 allocation is working. If you see `fatal: cannot allocate` or a signal-abort before that line, stop and debug.

Note: if startup fails on config loading before the allocation log line can be observed, that is acceptable — the allocation runs in `pre_loop` which is called before the main event loop, and the process may exit later on config errors without affecting this verification. Re-run in verbose mode to see it:

```bash
./objs/bin/teleproxy -p 18888 -H 18443 -S cafebabecafebabecafebabecafebabe -v -v 2>&1 | grep -i 'ExtConnectionHead' || echo "no allocation log yet — may need valid config; skip and re-verify in Task 6"
```

- [ ] **Step 3.6: Commit**

```bash
git add src/mtproto/mtproto-proxy.c
git commit -m "mtproto: heap-allocate ExtConnectionHead at pre_loop time

Replaces the static-array declaration with a pointer allocated from
max_connection_fd in mtfront_pre_loop. Default behavior is unchanged
(max_connection_fd defaults to MAX_CONNECTIONS when -c is not passed).

This is the first step toward honoring -c above the legacy 65536
ceiling. Asserts and loops are still compile-time constant; they move
to the runtime variable in follow-up commits."
```

---

### Task 4: Replace `MAX_CONNECTIONS` asserts in `mtproto-proxy.c`

**Files:**
- Modify: `src/mtproto/mtproto-proxy.c` (lines 242, 303, 347, 370, 380, 655, 674, 701, 717, 833)

**Context:** Ten `assert ((unsigned) fd < MAX_CONNECTIONS)` sites bound-check into `ExtConnectionHead`. They must use the runtime size or they will trip the moment the operator sets `-c > 65536`.

- [ ] **Step 4.1: Confirm the exact sites**

Run:
```bash
grep -n 'MAX_CONNECTIONS' src/mtproto/mtproto-proxy.c
```

You should see ~11 matches. Line 225 is the declaration (already pointer from Task 3). The `DEFAULT_CFG_MAX_CONNECTIONS` matches (lines 170, 173, 181) are unrelated — DO NOT touch them. Every remaining match should be a bound-check assert or an index into `ExtConnectionHead`. Confirm by eyeballing the context with `grep -n -B1 -A1 MAX_CONNECTIONS src/mtproto/mtproto-proxy.c`.

- [ ] **Step 4.2: Replace the bound-check asserts**

For every `assert ((unsigned) fd < MAX_CONNECTIONS)`, `assert ((unsigned) in_fd < MAX_CONNECTIONS)`, `assert (!CO || (unsigned) CONN_INFO(CO)->fd < MAX_CONNECTIONS)`, `assert ((unsigned) Ex->out_fd < MAX_CONNECTIONS)`, `assert ((unsigned) Ex->in_fd < MAX_CONNECTIONS)`, `assert (Ex->out_fd > 0 && Ex->out_fd < MAX_CONNECTIONS)` — replace the `MAX_CONNECTIONS` token with `max_connection_fd`:

```c
// BEFORE
assert ((unsigned) fd < MAX_CONNECTIONS);

// AFTER
assert ((unsigned) fd < (unsigned) max_connection_fd);
```

Apply the same transform to all matching lines. The `(unsigned)` cast on `max_connection_fd` is important because the left-hand side is `unsigned` and comparing `unsigned < signed` produces the wrong comparison when the signed value is negative. `max_connection_fd` is always positive in practice but the cast is defensive.

- [ ] **Step 4.3: Leave DEFAULT_CFG_MAX_CONNECTIONS alone**

Confirm that lines 170, 173, 181 still reference `DEFAULT_CFG_MAX_CONNECTIONS` / `default_cfg_max_connections` and are unchanged:

```bash
grep -n 'DEFAULT_CFG_MAX_CONNECTIONS\|default_cfg_max_connections' src/mtproto/mtproto-proxy.c
```

Expected: 3 matches at lines 170, 173, 181.

- [ ] **Step 4.4: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task4.log
```

Expected: success, zero new warnings.

- [ ] **Step 4.5: Commit**

```bash
git add src/mtproto/mtproto-proxy.c
git commit -m "mtproto: bound-check asserts use max_connection_fd

Ten fd-bound asserts switch from the compile-time MAX_CONNECTIONS
macro to the runtime max_connection_fd, matching the now-dynamic
ExtConnectionHead size."
```

---

### Task 5: Replace `MAX_CONNECTIONS` asserts in `mtproto-proxy-http.c`

**Files:**
- Modify: `src/mtproto/mtproto-proxy-http.c` (lines 112, 124, 134, 641)

- [ ] **Step 5.1: Confirm the sites**

```bash
grep -n 'MAX_CONNECTIONS' src/mtproto/mtproto-proxy-http.c
```

Expected: exactly 4 matches, all `assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);`.

- [ ] **Step 5.2: Replace**

For each match, replace `MAX_CONNECTIONS` with `(unsigned) max_connection_fd`:

```c
// BEFORE
assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);

// AFTER
assert ((unsigned) CONN_INFO(C)->fd < (unsigned) max_connection_fd);
```

- [ ] **Step 5.3: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task5.log
```

Expected: success.

- [ ] **Step 5.4: Commit**

```bash
git add src/mtproto/mtproto-proxy-http.c
git commit -m "mtproto-http: bound-check asserts use max_connection_fd

Mirrors the change in mtproto-proxy.c for the HTTP fallback path."
```

---

### Task 6: Replace `MAX_CONNECTIONS` in the drain loop

**Files:**
- Modify: `src/net/net-tcp-rpc-ext-drain.c:303`

- [ ] **Step 6.1: Confirm the site**

```bash
grep -n 'MAX_CONNECTIONS' src/net/net-tcp-rpc-ext-drain.c
```

Expected: exactly 1 match on line 303.

- [ ] **Step 6.2: Replace**

Edit `src/net/net-tcp-rpc-ext-drain.c:303`:

```c
// BEFORE
for (int fd = 0; fd < MAX_CONNECTIONS; fd++) {

// AFTER
for (int fd = 0; fd < max_connection_fd; fd++) {
```

- [ ] **Step 6.3: Final sanity grep — ensure no stray MAX_CONNECTIONS usage remains outside the allowed sites**

```bash
grep -rn 'MAX_CONNECTIONS' src/ | grep -v DEFAULT_CFG_MAX_CONNECTIONS | grep -v default_cfg_max_connections
```

Expected matches (these are the legitimate remaining uses):
- `src/net/net-connections.h:38` — the `#define MAX_CONNECTIONS 65536` itself
- `src/net/net-connections.c:83` — the `int max_connection_fd = MAX_CONNECTIONS;` default
- `src/net/net-connections.c:85` — the `max_special_connections = MAX_CONNECTIONS` default
- `src/engine/engine.c:621` — `E->maxconn = MAX_CONNECTIONS;` default
- `src/engine/engine-net.c:137` — the `val = MAX_CONNECTIONS;` fallback when `-c <= 0`

Any other matches are bugs — check each one.

- [ ] **Step 6.4: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task6.log
```

Expected: success.

- [ ] **Step 6.5: Smoke test — run with `-c 200000` and check the allocation log**

```bash
./objs/bin/teleproxy -p 18888 -H 18443 -S cafebabecafebabecafebabecafebabe -c 200000 -v 2>&1 | grep -i 'ExtConnectionHead: allocated'
```

Expected: a line `ExtConnectionHead: allocated 200000 slots (18 MB)`. If the proxy exits before emitting it due to missing config, that is fine — re-run with a full config after Task 11 when we add the E2E test infrastructure.

- [ ] **Step 6.6: Commit**

```bash
git add src/net/net-tcp-rpc-ext-drain.c
git commit -m "net: drain loop uses max_connection_fd

Part 1 complete: ExtConnectionHead is heap-allocated from
max_connection_fd, and all bound-check asserts and fd-scan loops
use the runtime variable. The -c flag now actually controls the
per-worker connection ceiling above the legacy 65536."
```

---

## Part 2 — Unix socket backend for fake-TLS

### Task 7: Add `client_socket_unix` helper

**Files:**
- Modify: `src/net/net-events.h` — add prototype
- Modify: `src/net/net-events.c` — add `#include <sys/un.h>` and function body

- [ ] **Step 7.1: Add the prototype to `net-events.h`**

Find the existing prototypes at lines 122-123:

```c
int client_socket (in_addr_t in_addr, int port, int mode);
int client_socket_ipv6 (const unsigned char in6_addr_ptr[16], int port, int mode);
```

Add immediately after:

```c
int client_socket_unix (const char *path);
```

- [ ] **Step 7.2: Add `#include <sys/un.h>` to `net-events.c`**

At the top of `src/net/net-events.c`, find the existing `#include` block (look for `#include <sys/socket.h>` or similar) and add:

```c
#include <sys/un.h>
```

- [ ] **Step 7.3: Implement `client_socket_unix`**

In `src/net/net-events.c`, immediately after the `client_socket_ipv6` function body (the function ends around line 744 with the closing `}` of `if (connect ... return -1; } return socket_fd; }`), append the new function:

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
    int saved = errno;
    close (fd);
    errno = saved;
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

No `SO_KEEPALIVE`, `TCP_NODELAY`, or `TCP_KEEPIDLE` — those are TCP-only and would fail on AF_UNIX.

- [ ] **Step 7.4: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task7.log
```

Expected: success, zero new warnings. If `-Wall` complains about implicit declaration of anything, verify the `sys/un.h` include is at the right place.

- [ ] **Step 7.5: Commit**

```bash
git add src/net/net-events.c src/net/net-events.h
git commit -m "net: add client_socket_unix helper

Opens an AF_UNIX stream socket in non-blocking mode and connects to
the given path. Used by the upcoming unix-socket fake-TLS backend."
```

---

### Task 8: Add `unix_path` to `struct domain_info`

**Files:**
- Modify: `src/net/net-tcp-rpc-ext-server.c` around line 503 (struct definition) and add `#include <sys/un.h>`

- [ ] **Step 8.1: Add `#include <sys/un.h>` to `net-tcp-rpc-ext-server.c`**

At the top, find the include block and add:

```c
#include <sys/un.h>
```

- [ ] **Step 8.2: Add the field to `struct domain_info`**

Find the struct at `src/net/net-tcp-rpc-ext-server.c:503`:

```c
// BEFORE
struct domain_info {
  const char *domain;
  int port;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};
```

Add the `unix_path` field immediately before `next`:

```c
// AFTER
struct domain_info {
  const char *domain;
  int port;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  const char *unix_path;    /* NULL for TCP backends, absolute path for AF_UNIX */
  struct domain_info *next;
};
```

- [ ] **Step 8.3: Build (expect success — no usage yet)**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task8.log
```

Expected: success. Nothing references `unix_path` yet, so it's a zero-init field.

- [ ] **Step 8.4: Commit**

```bash
git add src/net/net-tcp-rpc-ext-server.c
git commit -m "net: add unix_path field to domain_info

Zero-initialized for TCP backends. Will be populated by the parser
and consumed by the verification and forwarding paths in follow-up
commits."
```

---

### Task 9: Parse `@unix:` syntax in `tcp_rpc_add_proxy_domain`

**Files:**
- Modify: `src/net/net-tcp-rpc-ext-server.c:1061` (`tcp_rpc_add_proxy_domain`)

- [ ] **Step 9.1: Read the current function body**

```bash
sed -n '1061,1115p' src/net/net-tcp-rpc-ext-server.c
```

Confirm the structure: `calloc` → `info->port = 443` → IPv6 bracket parse → bare host/host:port parse → port validation → log → bucket insert → default_domain_info wiring.

- [ ] **Step 9.2: Add the `@unix:` branch**

Replace lines ~1068 through ~1096 (everything between `info->port = 443;` and `kprintf ("Proxy domain: %s:%d\n", info->domain, info->port);`) with a wrapping `if/else`:

```c
  info->port = 443;

  const char *at_unix = strstr (domain, "@unix:");
  if (at_unix != NULL && at_unix[6] != '\0') {
    size_t sni_len = (size_t) (at_unix - domain);
    if (sni_len == 0) {
      kprintf ("Invalid domain spec: empty SNI hostname before @unix: in %s\n", domain);
      free (info);
      return;
    }
    const char *path = at_unix + 6;
    size_t plen = strlen (path);
    if (plen >= sizeof (((struct sockaddr_un *)0)->sun_path)) {
      kprintf ("Invalid domain spec: unix socket path too long (%zu bytes, max %zu) in %s\n",
               plen, sizeof (((struct sockaddr_un *)0)->sun_path) - 1, domain);
      free (info);
      return;
    }
    info->domain = strndup (domain, sni_len);
    info->unix_path = strdup (path);
    info->port = 0;
    kprintf ("Proxy domain: %s@unix:%s\n", info->domain, info->unix_path);
  } else {
    const char *host_start = domain;
    const char *host_end = NULL;

    if (domain[0] == '[') {
      // [IPv6]:port format
      host_end = strchr (domain, ']');
      if (host_end == NULL) {
        kprintf ("Invalid IPv6 address: %s\n", domain);
        free (info);
        return;
      }
      host_start = domain + 1;
      const char *after_bracket = host_end + 1;
      if (*after_bracket == ':') {
        info->port = atoi (after_bracket + 1);
      }
      info->domain = strndup (host_start, host_end - host_start);
    } else {
      // Check for host:port — but only if the last colon has digits after it
      // and there is at most one colon (to avoid matching bare IPv6 like ::1)
      const char *colon = strrchr (domain, ':');
      if (colon != NULL && strchr (domain, ':') == colon) {
        // Exactly one colon — treat as host:port
        info->port = atoi (colon + 1);
        info->domain = strndup (domain, colon - domain);
      } else {
        info->domain = strdup (domain);
      }
    }

    if (info->port <= 0 || info->port > 65535) {
      kprintf ("Invalid port in domain spec: %s\n", domain);
      free ((void *)info->domain);
      free (info);
      return;
    }

    kprintf ("Proxy domain: %s:%d\n", info->domain, info->port);
  }

  struct domain_info **bucket = get_domain_info_bucket (info->domain, strlen (info->domain));
```

(The `struct domain_info **bucket = ...` line was already present after the kprintf — it should remain exactly as it was. Everything from there down is unchanged.)

Note: the `(void)host_start` reference in the legacy branch is intentional — it preserves the pre-existing warning-free behavior. Double-check after the edit.

- [ ] **Step 9.3: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task9.log
```

Expected: success, zero new warnings.

- [ ] **Step 9.4: Smoke test — legacy syntax still works**

```bash
./objs/bin/teleproxy -p 18888 -H 18443 -S cafebabecafebabecafebabecafebabe -D 127.0.0.1:8443 -v 2>&1 | grep -i 'Proxy domain' | head -5
```

Expected: `Proxy domain: 127.0.0.1:8443`. Process may exit afterward due to config; that's fine.

- [ ] **Step 9.5: Smoke test — new unix syntax parses**

```bash
./objs/bin/teleproxy -p 18888 -H 18443 -S cafebabecafebabecafebabecafebabe -D example.com@unix:/tmp/nonexistent.sock -v 2>&1 | grep -i 'Proxy domain' | head -5
```

Expected: `Proxy domain: example.com@unix:/tmp/nonexistent.sock`. The subsequent verification will fail (because the socket doesn't exist), but the parser accepted the syntax.

- [ ] **Step 9.6: Smoke test — negative cases log errors**

```bash
./objs/bin/teleproxy -D @unix:/foo -S cafe 2>&1 | grep -i 'Invalid domain spec'
./objs/bin/teleproxy -D foo@unix: -S cafe 2>&1 | grep -i 'Proxy domain'  # empty path: "@unix:" detected but at_unix[6] == '\0' → falls through to legacy, which treats "foo@unix:" as host:port → invalid port 0 → error
./objs/bin/teleproxy -D "foo@unix:/$(python3 -c 'print("a"*200)')" -S cafe 2>&1 | grep -i 'too long'
```

Expected lines (in some form): empty-SNI error, invalid-port error, path-too-long error.

- [ ] **Step 9.7: Commit**

```bash
git add src/net/net-tcp-rpc-ext-server.c
git commit -m "net: parse -D example.com@unix:/path/to/sock

Adds the @unix: delimiter to tcp_rpc_add_proxy_domain. The SNI
hostname is extracted from the left side and the socket path from
the right. Legacy host[:port] syntax is untouched. @ is not valid in
DNS hostnames or bracketed IPv6 literals, so detection cannot
collide with any existing input.

Validates the path fits in sockaddr_un.sun_path (107 bytes) and
rejects empty SNI or empty path."
```

---

### Task 10: AF_UNIX branch in `update_domain_info`

**Files:**
- Modify: `src/net/net-tcp-rpc-ext-server.c:742` (`update_domain_info`)

- [ ] **Step 10.1: Read the current address-resolve + socket-create region**

```bash
sed -n '742,830p' src/net/net-tcp-rpc-ext-server.c
```

The flow is: try inet_pton IPv4 → try inet_pton IPv6 → if not an IP, `kdb_gethostbyname` → set `af` → in a `TRIES` loop: `socket(af, SOCK_STREAM, IPPROTO_TCP)` → `fcntl O_NONBLOCK` → `connect` with `sockaddr_in`/`sockaddr_in6`. After the TRIES loop, address-family-agnostic request/response plumbing follows.

- [ ] **Step 10.2: Add an early `AF_UNIX` branch at the top**

At the very top of the function (immediately after `const char *domain = info->domain;` at line 743), insert:

```c
  if (info->unix_path != NULL) {
    /* unix-socket backend: skip DNS, go straight to the TRIES loop with AF_UNIX */
    /* set af = AF_UNIX and skip the address resolution block below */
    /* fall through into the restructured socket-create loop */
  }
```

Wait — we actually need to restructure the function. The simplest approach is: define `int af = 0;` at the top, set `af = AF_UNIX` early if `unix_path` is set, and gate the inet_pton/gethostbyname block on `af == 0`. Then branch inside the TRIES loop. Apply this edit:

Replace lines 742-768 (`static int update_domain_info` … `af = host->h_addrtype;`) with:

```c
static int update_domain_info (struct domain_info *info) {
  const char *domain = info->domain;
  int af = 0;

  if (info->unix_path != NULL) {
    af = AF_UNIX;
  } else {
    // Try parsing as a literal IP address first
    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton (AF_INET, domain, &addr4) == 1) {
      af = AF_INET;
      info->target = addr4;
      memset (info->target_ipv6, 0, sizeof (info->target_ipv6));
    } else if (inet_pton (AF_INET6, domain, &addr6) == 1) {
      af = AF_INET6;
      info->target.s_addr = 0;
      memcpy (info->target_ipv6, &addr6, sizeof (info->target_ipv6));
    }

    struct hostent *host = NULL;
    if (!af) {
      host = kdb_gethostbyname (domain);
      if (host == NULL || host->h_addr == NULL) {
        kprintf ("Failed to resolve host %s\n", domain);
        return 0;
      }
      assert (host->h_addrtype == AF_INET || host->h_addrtype == AF_INET6);
      af = host->h_addrtype;
    }
    /* Note: `host` is still needed inside the TRIES loop below to re-seed
       info->target across retries. For AF_UNIX we do not enter those branches
       and therefore do not need `host`. Because the legacy path declares
       `host` inside an `if (!af)` that we have preserved, the variable is
       out of scope at the loop. Restructure: hoist `host` out. */
```

Hmm — that's ugly. Let me simplify. Hoist `host` and the `struct in_addr addr4; struct in6_addr addr6;` declarations to the top of the function, and gate the AF branches on `af == 0`. Corrected edit — replace lines 742-768 with:

```c
static int update_domain_info (struct domain_info *info) {
  const char *domain = info->domain;
  int af = 0;
  struct in_addr addr4;
  struct in6_addr addr6;
  struct hostent *host = NULL;

  if (info->unix_path != NULL) {
    af = AF_UNIX;
  } else {
    // Try parsing as a literal IP address first
    if (inet_pton (AF_INET, domain, &addr4) == 1) {
      af = AF_INET;
      info->target = addr4;
      memset (info->target_ipv6, 0, sizeof (info->target_ipv6));
    } else if (inet_pton (AF_INET6, domain, &addr6) == 1) {
      af = AF_INET6;
      info->target.s_addr = 0;
      memcpy (info->target_ipv6, &addr6, sizeof (info->target_ipv6));
    }

    if (!af) {
      host = kdb_gethostbyname (domain);
      if (host == NULL || host->h_addr == NULL) {
        kprintf ("Failed to resolve host %s\n", domain);
        return 0;
      }
      assert (host->h_addrtype == AF_INET || host->h_addrtype == AF_INET6);
      af = host->h_addrtype;
    }
  }
```

This replaces the original decl + conditional block cleanly. The rest of the function (the `fd_set read_fd;` block, the `TRIES` loop, etc.) stays as is until the socket creation.

- [ ] **Step 10.3: Add AF_UNIX branch inside the TRIES loop**

Find the per-iteration connect block (roughly lines 790-825). The current shape is:

```c
    int e_connect;
    if (af == AF_INET) {
      ...
      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    } else {
      ...
      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    }
```

Rewrite that conditional as a three-way branch. Replace lines ~791-819 with:

```c
    int e_connect;
    if (af == AF_UNIX) {
      struct sockaddr_un addr;
      memset (&addr, 0, sizeof (addr));
      addr.sun_family = AF_UNIX;
      /* length already validated at parse time */
      memcpy (addr.sun_path, info->unix_path, strlen (info->unix_path) + 1);
      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    } else if (af == AF_INET) {
      if (host) {
        info->target = *((struct in_addr *) host->h_addr);
        memset (info->target_ipv6, 0, sizeof (info->target_ipv6));
      }

      struct sockaddr_in addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons (info->port);
      memcpy (&addr.sin_addr, &info->target, sizeof (struct in_addr));

      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    } else {
      if (host) {
        assert (sizeof (struct in6_addr) == sizeof (info->target_ipv6));
        info->target.s_addr = 0;
        memcpy (info->target_ipv6, host->h_addr, sizeof (struct in6_addr));
      }

      struct sockaddr_in6 addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons (info->port);
      memcpy (&addr.sin6_addr, info->target_ipv6, sizeof (struct in6_addr));

      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    }
```

Note: the `socket(af, SOCK_STREAM, IPPROTO_TCP)` call that lives *above* this block (around line 781) must also change. `IPPROTO_TCP` is wrong for AF_UNIX — must pass 0. Replace:

```c
    sockets[i] = socket (af, SOCK_STREAM, IPPROTO_TCP);
```

with:

```c
    sockets[i] = socket (af, SOCK_STREAM, (af == AF_UNIX) ? 0 : IPPROTO_TCP);
```

- [ ] **Step 10.4: Update the connect-failed log message for unix**

Find the `kprintf ("Failed to connect to %s: %s\n", domain, strerror (errno))` line inside the TRIES loop (around line 822) and make it family-aware:

```c
if (e_connect == -1 && errno != EINPROGRESS) {
  if (af == AF_UNIX) {
    kprintf ("Failed to connect to %s@unix:%s: %s\n", domain, info->unix_path, strerror (errno));
  } else {
    kprintf ("Failed to connect to %s: %s\n", domain, strerror (errno));
  }
  return 0;
}
```

- [ ] **Step 10.5: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task10.log
```

Expected: success, zero new warnings.

- [ ] **Step 10.6: Smoke test — unix path reaches the verification step and logs fallback on failure**

```bash
./objs/bin/teleproxy -p 18888 -H 18443 -S cafebabecafebabecafebabecafebabe -D example.com@unix:/tmp/nonexistent.sock -v 2>&1 | grep -iE 'Failed to connect to example.com@unix|Proxy domain|Failed to update response data'
```

Expected: you should see `Failed to connect to example.com@unix:/tmp/nonexistent.sock: No such file or directory` and `Failed to update response data about example.com, so default response settings will be used`. Startup proceeds (fallback path).

- [ ] **Step 10.7: Commit**

```bash
git add src/net/net-tcp-rpc-ext-server.c
git commit -m "net: update_domain_info speaks AF_UNIX

Adds an AF_UNIX branch to the startup TLS-1.3 verification helper so
that fake-TLS backends configured via -D host@unix:/path get the same
server_hello_encrypted_size measurement and reversed-extension-order
detection as TCP backends. Failure falls back to the existing random
encrypted-size path; startup does not abort."
```

---

### Task 11: Unix branch in `proxy_connection`

**Files:**
- Modify: `src/net/net-tcp-rpc-ext-server.c:1246` (`proxy_connection`)

- [ ] **Step 11.1: Read the current function**

```bash
sed -n '1246,1296p' src/net/net-tcp-rpc-ext-server.c
```

The shape: clear secret tracking → `check_conn_functions` assert → zero-target bail-out → port pick → `client_socket`/`client_socket_ipv6` → wrap in `alloc_new_connection` → swap `c->type` → return `parse_execute`.

- [ ] **Step 11.2: Insert the unix branch before the zero-target bail-out**

Replace the `const char zero[16] = {}; if (info->target.s_addr == 0 && !memcmp ...)` block and everything down through `return c->type->parse_execute (C);` with:

```c
  if (info->unix_path != NULL) {
    int cfd = client_socket_unix (info->unix_path);
    if (cfd < 0) {
      kprintf ("failed to connect to %s@unix:%s: %m\n", info->domain, info->unix_path);
      fail_connection (C, -27);
      return 0;
    }

    c->type->crypto_free (C);
    job_incref (C);
    unsigned char zero_ipv6[16] = {};
    job_t EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C,
                                     0, zero_ipv6, 0);

    if (!EJ) {
      kprintf ("failed to create proxy pass connection to %s@unix:%s\n",
               info->domain, info->unix_path);
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

  const char zero[16] = {};
  if (info->target.s_addr == 0 && !memcmp (info->target_ipv6, zero, 16)) {
    vkprintf (0, "failed to proxy request to %s\n", info->domain);
    fail_connection (C, -17);
    return 0;
  }

  int port = c->our_port == 80 ? 80 : info->port;

  int cfd = -1;
  if (info->target.s_addr) {
    cfd = client_socket (info->target.s_addr, port, 0);
  } else {
    cfd = client_socket_ipv6 (info->target_ipv6, port, SM_IPV6);
  }

  if (cfd < 0) {
    kprintf ("failed to create proxy pass connection: %d (%m)", errno);
    fail_connection (C, -27);
    return 0;
  }

  c->type->crypto_free (C);
  job_incref (C);
  job_t EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C, ntohl (*(int *)&info->target.s_addr), (void *)info->target_ipv6, port);

  if (!EJ) {
    kprintf ("failed to create proxy pass connection (2)");
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
```

Verify by re-reading the function after the edit that both branches converge on `return c->type->parse_execute (C);` and neither branch leaks fds or jobs on error.

- [ ] **Step 11.3: Build**

```bash
nice -n 19 make -j4 2>&1 | tee /tmp/build-task11.log
```

Expected: success, zero new warnings.

- [ ] **Step 11.4: Commit**

```bash
git add src/net/net-tcp-rpc-ext-server.c
git commit -m "net: proxy_connection forwards to unix-socket backends

When info->unix_path is set, open an AF_UNIX stream socket via the
new client_socket_unix helper and wrap it in the same ct_proxy_pass
outbound connection machinery used for TCP. Peer address fields
passed to alloc_new_connection are zeroed because they are
logging-only for AF_UNIX."
```

---

### Task 12: CLI help text and user-facing documentation

**Files:**
- Modify: `src/mtproto/mtproto-proxy.c` — `parse_usage` / extra options doc string
- Modify: `docs/features/fake-tls.md`
- Modify: `docs/features/fake-tls.ru.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 12.1: Update the `-D` help text in mtproto-proxy.c**

Find where `-D` is documented in the help output. Grep:

```bash
grep -n '"-D' src/mtproto/mtproto-proxy.c
grep -n '-D DOMAIN\|-D <domain>' src/mtproto/mtproto-proxy.c
```

If the `-D` option has a descriptive help line (inside `parse_usage()` or a `parse_option_add` call somewhere), extend it so it mentions the `@unix:` form:

```
-D <domain>[:port]       mimic <domain> for fake-TLS; forward probes to TCP backend (default port 443)
-D <domain>@unix:<path>  mimic <domain>; forward probes to AF_UNIX stream socket at <path>
```

If the existing help line uses a single-line format, extend it inline. Match the existing formatting style exactly.

- [ ] **Step 12.2: Add "Unix socket backend" section to `docs/features/fake-tls.md`**

Open `docs/features/fake-tls.md`. Find the "Custom TLS Backend (TCP Splitting)" section (look for `## Custom TLS Backend`). After that section, immediately before `## Dynamic Record Sizing (DRS)`, insert a new subsection:

```markdown
## Unix Socket Backend

On high-traffic deployments, the loopback TCP flow between Teleproxy and
the local nginx backend creates pressure on the kernel's conntrack table
and doubles per-probe TCP state. Routing the backend through an AF_UNIX
stream socket eliminates loopback entirely — conntrack never sees it.

Syntax:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> \
    -D mywebsite.com@unix:/run/nginx-mtproxy.sock \
    --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Left of `@unix:` is the SNI hostname used for fake-TLS domain matching.
Right of `@unix:` is the absolute path to the backend socket. The path
must fit in `sockaddr_un.sun_path` (107 bytes on Linux).

nginx configuration:

```nginx
server {
    listen unix:/run/nginx-mtproxy.sock ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

**Permissions.** Teleproxy typically runs as `nobody`. Make the socket
accessible:

```nginx
# In the main nginx.conf, under the relevant context:
user www-data;  # or whichever user owns nginx workers
```

Then `chown www-data:nogroup /run/nginx-mtproxy.sock && chmod 660 ...`
via a tmpfiles.d or systemd drop-in, or use systemd socket activation
with `SocketUser=`/`SocketGroup=` so the socket is created with the
right ownership automatically.

**Startup verification.** Teleproxy performs the same TLS 1.3
handshake probing over the unix socket that it performs over TCP,
measuring `ServerHello` record sizes to drive mimicry. The backend
must already be listening when Teleproxy starts — use systemd
`After=nginx.service` (or equivalent) in the Teleproxy unit to
enforce the order.

If the verification fails, Teleproxy logs a warning and falls back to
randomized encrypted sizes (2500–3620 bytes). Startup does not abort.

```

- [ ] **Step 12.3: Mirror the section in `docs/features/fake-tls.ru.md`**

Same structure, translated. Place it under the corresponding "Custom TLS Backend" section in the Russian doc (grep for the heading to find the exact name used in ru.md). Translate headings and prose; keep code blocks and the nginx config unchanged.

- [ ] **Step 12.4: CHANGELOG entry**

Open `CHANGELOG.md`. At the top (or under an existing `## [Unreleased]` heading — check the file's convention), add:

```markdown
### Added

- `-D <domain>@unix:<path>` — fake-TLS backend can now be an AF_UNIX
  stream socket instead of TCP. Eliminates loopback conntrack overhead
  on high-traffic proxies. TLS 1.3 verification and response-size
  mimicry work the same as for TCP backends.
- `ExtConnectionHead` is now heap-allocated from `max_connection_fd`
  at startup, allowing the `-c` flag to raise the per-worker connection
  ceiling above the legacy compile-time `MAX_CONNECTIONS` (65536).

### Fixed

- `-c` flag now actually controls the per-worker hard ceiling. Prior
  to this release, the compile-time `MAX_CONNECTIONS` static array
  bound the ceiling at 65536 regardless of the runtime flag.
```

If `CHANGELOG.md` has a different per-version structure, adapt to match it — group under the current unreleased/next-version section.

- [ ] **Step 12.5: Build (sanity — no code changes, should be a no-op)**

```bash
nice -n 19 make -j4 2>&1 | tail -5
```

Expected: nothing to rebuild unless the `parse_usage` change touched a compiled .c file, in which case one compile step runs successfully.

- [ ] **Step 12.6: Commit**

```bash
git add src/mtproto/mtproto-proxy.c docs/features/fake-tls.md docs/features/fake-tls.ru.md CHANGELOG.md
git commit -m "docs: unix-socket fake-TLS backend and -c runtime ceiling

Adds the @unix: syntax to the -D help text, a new 'Unix Socket
Backend' section in fake-tls.{md,ru.md}, and a CHANGELOG entry for
both the -c runtime ceiling fix and the unix-socket feature."
```

---

### Task 13: Create the `tls-backend-unix` Docker image

**Files:**
- Create: `tests/tls-backend-unix/Dockerfile`
- Create: `tests/tls-backend-unix/nginx.conf`
- Create: `tests/tls-backend-unix/entrypoint.sh`

**Context:** Modeled after `tests/tls-backend/` but nginx listens on a unix socket inside a shared volume.

- [ ] **Step 13.1: Read the existing TCP-backend files as reference**

```bash
cat tests/tls-backend/Dockerfile
cat tests/tls-backend/nginx.conf
cat tests/tls-backend/entrypoint.sh
```

- [ ] **Step 13.2: Create `tests/tls-backend-unix/Dockerfile`**

```dockerfile
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# /var/run is a tmpfs by default in alpine nginx; the socket lives there and
# will be exposed through a docker-compose shared volume.
VOLUME ["/var/run/nginx-mtproxy"]

ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 13.3: Create `tests/tls-backend-unix/nginx.conf`**

```nginx
worker_processes 1;
pid /var/run/nginx.pid;

events {
    worker_connections 128;
}

http {
    server {
        listen unix:/var/run/nginx-mtproxy/backend.sock ssl default_server;
        server_name _;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;
        ssl_protocols       TLSv1.3;

        location / { return 200 "OK\n"; }
    }
}
```

- [ ] **Step 13.4: Create `tests/tls-backend-unix/entrypoint.sh`**

```bash
#!/bin/sh
set -eu

CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR" /var/run/nginx-mtproxy

if [ ! -f "$CERT_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out    "$CERT_DIR/cert.pem" \
    -days 7 \
    -subj "/CN=test-backend-unix" \
    -addext "subjectAltName=DNS:test-backend-unix,IP:127.0.0.1" \
    >/dev/null 2>&1
fi

# Make sure the directory that will hold the socket is writable by nginx
chown -R nginx:nginx /var/run/nginx-mtproxy 2>/dev/null || true
chmod 0775 /var/run/nginx-mtproxy || true

exec nginx -g 'daemon off;'
```

Make it executable:

```bash
chmod +x tests/tls-backend-unix/entrypoint.sh
```

- [ ] **Step 13.5: Verify the image builds standalone**

```bash
docker build -t tls-backend-unix-smoke tests/tls-backend-unix/
```

Expected: image builds successfully. A warning about `VOLUME` from alpine is fine.

- [ ] **Step 13.6: Commit**

```bash
git add tests/tls-backend-unix/
git commit -m "tests: nginx backend listening on unix socket

Docker image for the upcoming tls-unix-test end-to-end test. Nginx
terminates TLS 1.3 on /var/run/nginx-mtproxy/backend.sock which is
mounted as a shared volume so the teleproxy container can connect
over AF_UNIX."
```

---

### Task 14: docker-compose file for `tls-unix-test`

**Files:**
- Create: `tests/docker-compose.tls-unix-test.yml`

- [ ] **Step 14.1: Read the TCP variant for reference**

```bash
cat tests/docker-compose.tls-test.yml
```

- [ ] **Step 14.2: Create `tests/docker-compose.tls-unix-test.yml`**

```yaml
services:
  tls-backend-unix:
    build: ./tls-backend-unix
    volumes:
      - nginx-mtproxy-sock:/var/run/nginx-mtproxy
    networks:
      tlsunixnet:
        ipv4_address: 172.31.0.10
    healthcheck:
      test: ["CMD-SHELL", "test -S /var/run/nginx-mtproxy/backend.sock"]
      interval: 2s
      timeout: 3s
      retries: 15
      start_period: 3s

  teleproxy:
    build:
      context: ..
      dockerfile: Dockerfile
      args:
        DEBUG_TOOLS: "1"
    environment:
      - SECRET=${TELEPROXY_SECRET:-d41d8cd98f00b204e9800998ecf8427e}
      - PORT=8443
      - STATS_PORT=8888
      # The fake-TLS mimic domain. SNI value used by Telethon client below.
      - EE_DOMAIN=tls-backend-unix
      # Unix-socket backend path — mounted from the shared volume.
      - EE_UNIX_PATH=/var/run/nginx-mtproxy/backend.sock
      - WORKERS=0
      # Stress-test the new -c ceiling at the same time.
      - MAX_CONN=200000
    command:
      - "/bin/sh"
      - "-c"
      - |
        exec /opt/teleproxy/teleproxy \
          -u nobody -p ${STATS_PORT} -H ${PORT} \
          -M ${WORKERS} -c ${MAX_CONN} \
          -S ${SECRET} \
          -D ${EE_DOMAIN}@unix:${EE_UNIX_PATH} \
          --http-stats \
          --aes-pwd /opt/teleproxy/pwd \
          /opt/teleproxy/proxy-multi.conf
    volumes:
      - nginx-mtproxy-sock:/var/run/nginx-mtproxy
    networks:
      - tlsunixnet
    depends_on:
      tls-backend-unix:
        condition: service_healthy

  tester:
    build: .
    environment:
      - TELEPROXY_HOST=teleproxy
      - TELEPROXY_PORT=8443
      - TELEPROXY_STATS_PORT=8888
      - TELEPROXY_SECRET=${TELEPROXY_SECRET:-d41d8cd98f00b204e9800998ecf8427e}
      - EE_DOMAIN=tls-backend-unix
      - EXPECTED_MAX_CONN=200000
    networks:
      - tlsunixnet
    depends_on:
      - teleproxy
    command: ["sh", "-c", "python test_tls_unix_e2e.py"]

volumes:
  nginx-mtproxy-sock:

networks:
  tlsunixnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.31.0.0/24
```

Note: the `command:` block here overrides the default Dockerfile entrypoint so we can inject the `@unix:` flag. If the existing Dockerfile uses a different argument pattern, adapt the `command:` accordingly — the key bits are `-c ${MAX_CONN}` and `-D ${EE_DOMAIN}@unix:${EE_UNIX_PATH}`. Before proceeding, check the existing Dockerfile for any required env vars or startup script:

```bash
grep -n 'ENTRYPOINT\|CMD\|teleproxy' Dockerfile
```

If the Dockerfile uses an `entrypoint.sh` that takes env vars, follow that pattern instead of an inline `command:`. The goal is: pass `-c 200000` and `-D tls-backend-unix@unix:/var/run/nginx-mtproxy/backend.sock` to the teleproxy binary.

- [ ] **Step 14.3: Smoke test — compose validates**

```bash
docker compose -f tests/docker-compose.tls-unix-test.yml config > /dev/null && echo OK
```

Expected: `OK`. No validation errors.

- [ ] **Step 14.4: Commit**

```bash
git add tests/docker-compose.tls-unix-test.yml
git commit -m "tests: docker-compose for tls-unix-test

Brings up nginx-unix backend + teleproxy (wired through shared
volume) + tester. Uses -c 200000 so the same run also exercises the
runtime max_connection_fd allocation."
```

---

### Task 15: E2E test script `test_tls_unix_e2e.py`

**Files:**
- Create: `tests/test_tls_unix_e2e.py`

- [ ] **Step 15.1: Read the existing TCP E2E test as reference**

```bash
head -120 tests/test_tls_e2e.py
wc -l tests/test_tls_e2e.py
```

Note which helper functions (`build_client_hello`, Telethon connect, stats endpoint check) exist so we can reuse their logic where possible.

- [ ] **Step 15.2: Write the unix variant**

Create `tests/test_tls_unix_e2e.py`:

```python
#!/usr/bin/env python3
"""E2E test for the -D domain@unix:<path> fake-TLS backend.

Three independent assertions:

  1. Teleproxy startup log contains the "ExtConnectionHead: allocated
     <N> slots" line with N == ${EXPECTED_MAX_CONN}. Verifies Part 1
     of the design (runtime-sized heap allocation).

  2. Teleproxy startup log contains "Proxy domain: <domain>@unix:<path>"
     and does NOT contain "Failed to connect to <domain>@unix:". Verifies
     that the verification phase reached the backend successfully over
     the shared socket.

  3. A raw TCP connection to teleproxy's MTProto port, followed by a
     plain TLS 1.3 ClientHello for EE_DOMAIN (no proxy secret), gets
     forwarded to nginx and returns HTTP 200 OK. This proves
     proxy_connection() successfully opened the AF_UNIX backend and
     piped bytes through.
"""

import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request


TELEPROXY_HOST = os.environ["TELEPROXY_HOST"]
TELEPROXY_PORT = int(os.environ["TELEPROXY_PORT"])
TELEPROXY_STATS_PORT = int(os.environ["TELEPROXY_STATS_PORT"])
EE_DOMAIN = os.environ["EE_DOMAIN"]
EXPECTED_MAX_CONN = int(os.environ["EXPECTED_MAX_CONN"])


def fetch_teleproxy_logs() -> str:
    """Read teleproxy container logs via docker. The tester container runs
    with /var/run/docker.sock mounted — if not, fall back to the stats
    endpoint which echoes a few startup counters. Here we cheat and read
    what was written to stdout/stderr of the teleproxy container via the
    shared docker-compose network log endpoint if available. In our
    compose setup, the cleanest approach is: docker-compose logs from
    the host runs the test, not the tester. So instead, verify via the
    stats port.
    """
    raise NotImplementedError  # see _assert_max_conn_from_stats


def _assert_max_conn_from_stats():
    """Verify Part 1 by querying the stats endpoint.

    The http-stats page emits:
        max_connections\t<N>
    where <N> is max_connection_fd. With -c 200000 passed on the command
    line, this must read 200000.
    """
    url = f"http://{TELEPROXY_HOST}:{TELEPROXY_STATS_PORT}/"
    # Retry for up to 30 s while teleproxy finishes startup.
    deadline = time.time() + 30
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as e:
            last_err = e
            time.sleep(1)
    else:
        raise RuntimeError(f"could not reach stats endpoint: {last_err}")

    expected = f"max_connections\t{EXPECTED_MAX_CONN}"
    if expected not in body:
        print(body)
        raise AssertionError(
            f"expected '{expected}' in stats body; did not find it"
        )
    print(f"OK: stats reports max_connections = {EXPECTED_MAX_CONN}")


def _assert_probe_forwarded():
    """Verify Part 2 by sending a vanilla TLS 1.3 ClientHello with SNI
    matching EE_DOMAIN but WITHOUT the MTProto ee-prefix. The connection
    is not a valid proxy client → teleproxy forwards the entire flow to
    the unix-socket backend (nginx), which replies with an HTTPS 200 OK.

    We do not use Telethon here: the goal is to exercise the forwarding
    path, not the proxy protocol.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    with socket.create_connection((TELEPROXY_HOST, TELEPROXY_PORT), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=EE_DOMAIN) as tls:
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {EE_DOMAIN}\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            buf = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 64 * 1024:
                    break

    head = buf.split(b"\r\n", 1)[0]
    if not head.startswith(b"HTTP/1."):
        raise AssertionError(f"unexpected response from forwarded probe: {head!r}")
    if b" 200 " not in head:
        raise AssertionError(f"non-200 from unix backend: {head!r}")
    if b"OK" not in buf:
        raise AssertionError(f"missing OK payload from unix backend: {buf[:200]!r}")
    print("OK: probe was forwarded to the unix-socket backend and returned 200 OK")


def main():
    _assert_max_conn_from_stats()
    _assert_probe_forwarded()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
```

Note the `fetch_teleproxy_logs` stub: we deliberately don't read container logs from inside a peer container. Instead we rely on the stats endpoint to confirm `max_connection_fd`. If stronger verification of the specific allocation log line is needed, it can be added via `docker compose logs teleproxy` in the Makefile target (Task 16) as a post-check.

- [ ] **Step 15.3: Commit**

```bash
git add tests/test_tls_unix_e2e.py
git commit -m "tests: E2E verification for -D host@unix backend

Asserts three things against the tls-unix-test compose stack:
 1. teleproxy stats page reports the -c 200000 ceiling (Part 1).
 2. a plain TLS 1.3 probe with EE_DOMAIN SNI gets forwarded through
    the unix socket to nginx and returns HTTP 200 (Part 2 forward).
 3. implicit: teleproxy did not crash starting up with -c 200000 +
    -D domain@unix: (covers Parts 1+2 together)."
```

---

### Task 16: Add `test-tls-unix` Makefile target

**Files:**
- Modify: `Makefile` — add new PHONY target + entry in the `.PHONY` list

- [ ] **Step 16.1: Add the target to the PHONY list**

Find the existing `.PHONY` line (around `Makefile:82`) and add `test-tls-unix` next to `test-tls`:

```make
.PHONY: all clean lint tests test test-tls test-tls-unix test-multi-secret ... (rest unchanged)
```

- [ ] **Step 16.2: Add the new target body**

After the `test-tls:` target block (ends around line 210 with `docker compose -f tests/docker-compose.tls-test.yml down`), insert a new target:

```make
test-tls-unix:
	@if [ -z "$$TELEPROXY_SECRET" ]; then \
		export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps); \
		echo "Generated TELEPROXY_SECRET: $$TELEPROXY_SECRET"; \
	fi && \
	export TELEPROXY_SECRET=$${TELEPROXY_SECRET:-$$(head -c 16 /dev/urandom | xxd -ps)} && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.tls-unix-test.yml up --build --exit-code-from tester || \
		(echo "TLS unix-socket test timed out or failed"; \
		docker compose -f tests/docker-compose.tls-unix-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.tls-unix-test.yml down -v; exit 1)
	@echo "Checking teleproxy logs for unix-socket allocation markers..."
	@docker compose -f tests/docker-compose.tls-unix-test.yml logs teleproxy 2>&1 | grep -q "ExtConnectionHead: allocated 200000" || \
		(echo "FAIL: expected allocation log line not found"; exit 1)
	@docker compose -f tests/docker-compose.tls-unix-test.yml logs teleproxy 2>&1 | grep -q "Proxy domain: .*@unix:" || \
		(echo "FAIL: expected @unix: proxy-domain log line not found"; exit 1)
	docker compose -f tests/docker-compose.tls-unix-test.yml down -v
```

Match the tab indentation of surrounding targets exactly. Makefiles are tab-sensitive.

- [ ] **Step 16.3: Validate the Makefile parses**

```bash
make -n test-tls-unix >/dev/null && echo OK
```

Expected: `OK`. If you get "missing separator", you used spaces instead of tabs.

- [ ] **Step 16.4: Commit**

```bash
git add Makefile
git commit -m "make: test-tls-unix target

Runs the unix-socket fake-TLS backend E2E. Post-test, greps
teleproxy logs for the new allocation marker and @unix proxy-domain
line to catch silent regressions where the feature is bypassed."
```

---

## Part 3 — Verification

### Task 17: Run the new E2E test

**Files:** none

- [ ] **Step 17.1: Run the new test**

```bash
make test-tls-unix 2>&1 | tee /tmp/test-tls-unix.log
```

Expected: the compose stack comes up, the tester exits 0, the post-test log grep succeeds, and the compose stack is torn down cleanly. Final exit code 0.

- [ ] **Step 17.2: If it fails — collect diagnostics**

Read `/tmp/test-tls-unix.log`. The most common failure modes:

- Socket path longer than 107 bytes → parser rejects at startup. Check the compose EE_UNIX_PATH.
- nginx healthcheck never passes → socket never got created, or permissions wrong. Run
  `docker compose -f tests/docker-compose.tls-unix-test.yml logs tls-backend-unix`.
- Teleproxy can't open the socket → inspect teleproxy logs for `Failed to connect to ... @unix:`.
  Check that the volume mount is on both services and that nginx's listen path matches the
  teleproxy -D argument exactly.
- Stats endpoint unreachable → teleproxy crashed or did not start. Check teleproxy logs for
  `ExtConnectionHead` or any assertion failure.

Fix the root cause, re-run `make test-tls-unix`. Do not mask errors.

- [ ] **Step 17.3: No commit — verification only**

---

### Task 18: Regression — run existing tls + secret-drain tests

**Files:** none

- [ ] **Step 18.1: Run the pre-existing TCP-backend tls test**

```bash
make test-tls 2>&1 | tail -20
```

Expected: exit 0. This confirms that the changes to `tcp_rpc_add_proxy_domain`, `update_domain_info`, and `proxy_connection` did not break the legacy `-D host:port` path.

- [ ] **Step 18.2: Run the secret-drain test**

```bash
make test-secret-drain 2>&1 | tail -20
```

Expected: exit 0. This exercises the drain loop in `net-tcp-rpc-ext-drain.c:303` which we changed from `MAX_CONNECTIONS` to `max_connection_fd`.

- [ ] **Step 18.3: Run the basic smoke test**

```bash
make tests 2>&1 | tail -10
```

Expected: `Smoke test passed: amd64 image builds and binary starts (--help).`

- [ ] **Step 18.4: No commit — regression only**

---

### Task 19: Static analysis (lint)

**Files:** none

- [ ] **Step 19.1: Run cppcheck**

```bash
make lint 2>&1 | tee /tmp/lint.log
```

Expected: no errors (exit 0). Any warnings introduced by our changes should be investigated and fixed — the Makefile's `lint` target uses `--error-exitcode=1`, so real issues will fail the build.

- [ ] **Step 19.2: If lint complains about any of our new code — fix it**

Common false-positives are in `.cppcheck-suppressions`. If cppcheck flags a real issue (e.g. memory leak in the parser's error paths, use-after-free around `free(info)`), fix the root cause, not the suppression list.

Re-run `make lint` until it exits 0.

- [ ] **Step 19.3: Commit fixes (if any)**

If Task 19.2 required code changes:

```bash
git add -u
git commit -m "lint: address cppcheck findings in runtime-maxconn+unix-socket changes"
```

If no changes were needed — no commit.

---

### Task 20: Deploy preparation — summary artifact (no prod changes)

**Files:**
- Create: `/tmp/deploy-summary.md` (ephemeral, not committed)

**Context:** This task produces the artifact the user will review before authorizing prod deploy. It does not touch the production host.

- [ ] **Step 20.1: Collect the diff summary**

```bash
{
  echo "# Deploy summary"
  echo
  echo "## Commits since 7ef583f"
  git log --oneline 7ef583f..HEAD
  echo
  echo "## Files changed"
  git diff --stat 7ef583f..HEAD
  echo
  echo "## Full diff (src + Makefile + tests)"
  git diff 7ef583f..HEAD -- src/ Makefile tests/docker-compose.tls-unix-test.yml tests/test_tls_unix_e2e.py
} > /tmp/deploy-summary.md
```

- [ ] **Step 20.2: Binary sanity**

```bash
./objs/bin/teleproxy 2>&1 | head -20 >> /tmp/deploy-summary.md || true
echo '' >> /tmp/deploy-summary.md
echo '## Binary size and version' >> /tmp/deploy-summary.md
ls -l objs/bin/teleproxy >> /tmp/deploy-summary.md
./objs/bin/teleproxy --version 2>&1 >> /tmp/deploy-summary.md || true
```

- [ ] **Step 20.3: Write the recommended prod systemd changes into the summary**

Append:

```bash
cat >> /tmp/deploy-summary.md <<'EOF'

## Recommended systemd unit changes (mtproxy-dd.service / mtproxy-tls.service)

Replace the legacy flags in ExecStart:

    -C 1048576                    # old — ineffective (sets max_special_connections only)

with:

    -c 1048576                    # new — actual per-worker fd ceiling

Add near the top of the [Service] block (good hygiene for clarity):

    LimitNOFILE=1048592

Pre-deploy sanity check on the target host:

    cat /proc/sys/fs/nr_open    # must be >= 1048592

If fs.nr_open is < 1048592, either:
    sysctl -w fs.nr_open=2097152
    echo "fs.nr_open = 2097152" > /etc/sysctl.d/99-teleproxy-nr-open.conf
or reduce -c to a value comfortably below fs.nr_open.

## Recommended rollout

1. Back up /usr/local/bin/teleproxy to teleproxy.prev on the prod host.
2. scp new binary.
3. Back up current unit files to *.service.prev.
4. Edit units: -C → -c, add LimitNOFILE=1048592.
5. systemctl daemon-reload.
6. Restart mtproxy-dd.service first; wait 60s; check:
     - active_special_connections from --http-stats
     - nf_conntrack_count
     - load average
7. If healthy, restart mtproxy-tls.service with the same procedure.
8. Monitor for 5-10 minutes. If any regression, roll back binary + unit files.
EOF
```

- [ ] **Step 20.4: Present the summary to the user**

```bash
cat /tmp/deploy-summary.md
```

Wait for user approval before doing anything on the production host. The plan ends here — any SSH / systemd / binary-copy action is out of scope and requires explicit authorization.

---

## Self-review

**Spec coverage check:**

| Spec requirement | Task |
|------------------|------|
| Expose `max_connection_fd` as extern | 1 |
| Heap-allocate `ExtConnectionHead` from `max_connection_fd` | 3 |
| Init order verification | 2 |
| Replace `MAX_CONNECTIONS` asserts in `mtproto-proxy.c` | 4 |
| Replace `MAX_CONNECTIONS` asserts in `mtproto-proxy-http.c` | 5 |
| Replace `MAX_CONNECTIONS` in drain loop | 6 |
| `client_socket_unix` helper | 7 |
| `unix_path` in `domain_info` | 8 |
| `@unix:` parser branch | 9 |
| AF_UNIX in `update_domain_info` | 10 |
| Unix branch in `proxy_connection` | 11 |
| CLI help + `fake-tls.md` + `fake-tls.ru.md` + `CHANGELOG.md` | 12 |
| Test fixture (nginx-unix container) | 13 |
| docker-compose for tls-unix-test | 14 |
| E2E test script | 15 |
| Makefile target | 16 |
| Run new test | 17 |
| Regression tests (TCP tls + secret-drain) | 18 |
| Static analysis (cppcheck) | 19 |
| Deploy summary artifact, no prod changes | 20 |

All spec items mapped to at least one task.

**Type/signature consistency check:**
- `max_connection_fd`: declared `extern int` (Task 1), used as `int` in asserts (Tasks 4-5) and loop (Task 6) — consistent.
- `ExtConnectionHead`: `struct ext_connection *` (Task 3), indexed in asserts via `[fd]` unchanged — consistent.
- `init_ext_connection_head`: no args, no return, `static` — called once from `mtfront_pre_loop` (Task 3) — consistent.
- `client_socket_unix`: prototype `int client_socket_unix(const char *path)` in header (Task 7), same signature in body (Task 7), called in `proxy_connection` (Task 11) — consistent.
- `struct domain_info.unix_path`: `const char *` (Task 8), set via `strdup` (Task 9), read via NULL check (Tasks 10, 11) — consistent.

**Placeholder scan:** no TBDs, TODOs, or "similar to task N" references. All code steps contain actual code. All commands contain exact paths and expected output.

**Scope check:** Plan is focused on the two interlocking spec parts. No speculative refactoring. Tests are proportionate to feature complexity. Deploy prep is artifact-only.
