/*
 * Unit tests for Unix socket target and PROXY protocol v1 support.
 *
 * Build:
 *   gcc -std=gnu11 -O2 -o test_unix_socket test_unix_socket.c -lpthread
 *
 * Run:
 *   ./test_unix_socket
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCK_PATH "/tmp/teleproxy_test.sock"
#define TEST_MSG  "hello from client"

static int tests_passed;
static int tests_failed;

#define ASSERT_MSG(cond, msg) do { \
  if (!(cond)) { \
    fprintf (stderr, "  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
    tests_failed++; \
    return; \
  } \
} while (0)

#define PASS() do { tests_passed++; } while (0)

/* Minimal reimplementation of client_socket_unix for testing
   (same logic as in net-events.c, but standalone). */
static int client_socket_unix (const char *path) {
  if (!path || strlen (path) >= sizeof (((struct sockaddr_un *)0)->sun_path)) {
    return -1;
  }

  int socket_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    return -1;
  }

  int flags = fcntl (socket_fd, F_GETFL, 0);
  if (flags < 0 || fcntl (socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close (socket_fd);
    return -1;
  }

  struct sockaddr_un addr;
  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, path, sizeof (addr.sun_path) - 1);

  if (connect (socket_fd, (struct sockaddr *) &addr, sizeof (addr)) == -1 && errno != EINPROGRESS) {
    close (socket_fd);
    return -1;
  }

  return socket_fd;
}

/* Format PROXY protocol v1 header (same logic as in net-tcp-rpc-ext-server.c). */
static int format_proxy_protocol_v1 (char *buf, size_t bufsize,
                                      int is_ipv6,
                                      const void *src_addr, const void *dst_addr,
                                      unsigned src_port, unsigned dst_port) {
  if (is_ipv6) {
    char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];
    inet_ntop (AF_INET6, src_addr, src_buf, sizeof (src_buf));
    inet_ntop (AF_INET6, dst_addr, dst_buf, sizeof (dst_buf));
    return snprintf (buf, bufsize, "PROXY TCP6 %s %s %u %u\r\n",
                     src_buf, dst_buf, src_port, dst_port);
  } else {
    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    inet_ntop (AF_INET, src_addr, src_buf, sizeof (src_buf));
    inet_ntop (AF_INET, dst_addr, dst_buf, sizeof (dst_buf));
    return snprintf (buf, bufsize, "PROXY TCP4 %s %s %u %u\r\n",
                     src_buf, dst_buf, src_port, dst_port);
  }
}

/* Create a listening Unix socket, return its fd. */
static int create_listener (const char *path) {
  unlink (path);

  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  assert (fd >= 0);

  struct sockaddr_un addr;
  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, path, sizeof (addr.sun_path) - 1);

  assert (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) == 0);
  assert (listen (fd, 5) == 0);
  return fd;
}

/* --- Test: basic connection to Unix socket --- */

struct accept_ctx {
  int listen_fd;
  int accepted_fd;
  char received[256];
  int received_len;
};

static void *accept_thread (void *arg) {
  struct accept_ctx *ctx = arg;
  ctx->accepted_fd = accept (ctx->listen_fd, NULL, NULL);
  if (ctx->accepted_fd >= 0) {
    ctx->received_len = read (ctx->accepted_fd, ctx->received, sizeof (ctx->received) - 1);
    if (ctx->received_len > 0) {
      ctx->received[ctx->received_len] = '\0';
    }
  }
  return NULL;
}

static void test_unix_socket_connect (void) {
  printf ("test_unix_socket_connect... ");

  int listener = create_listener (SOCK_PATH);
  struct accept_ctx ctx = { .listen_fd = listener };

  pthread_t tid;
  pthread_create (&tid, NULL, accept_thread, &ctx);

  /* Give the listener thread a moment to start */
  usleep (50000);

  int cfd = client_socket_unix (SOCK_PATH);
  ASSERT_MSG (cfd >= 0, "client_socket_unix should succeed");

  /* Wait for connection to complete (non-blocking) */
  fd_set wfds;
  FD_ZERO (&wfds);
  FD_SET (cfd, &wfds);
  struct timeval tv = { .tv_sec = 2 };
  int r = select (cfd + 1, NULL, &wfds, NULL, &tv);
  ASSERT_MSG (r > 0, "socket should become writable");

  /* Send test data */
  ssize_t written = write (cfd, TEST_MSG, strlen (TEST_MSG));
  ASSERT_MSG (written == (ssize_t)strlen (TEST_MSG), "write should succeed");

  pthread_join (tid, NULL);

  ASSERT_MSG (ctx.accepted_fd >= 0, "accept should succeed");
  ASSERT_MSG (ctx.received_len == (int)strlen (TEST_MSG), "should receive all data");
  ASSERT_MSG (strcmp (ctx.received, TEST_MSG) == 0, "data should match");

  close (cfd);
  close (ctx.accepted_fd);
  close (listener);
  unlink (SOCK_PATH);
  printf ("OK\n");
  PASS ();
}

/* --- Test: bidirectional relay over Unix socket --- */

static void test_unix_socket_bidirectional (void) {
  printf ("test_unix_socket_bidirectional... ");

  int listener = create_listener (SOCK_PATH);
  struct accept_ctx ctx = { .listen_fd = listener };

  pthread_t tid;
  pthread_create (&tid, NULL, accept_thread, &ctx);
  usleep (50000);

  int cfd = client_socket_unix (SOCK_PATH);
  ASSERT_MSG (cfd >= 0, "client_socket_unix should succeed");

  fd_set wfds;
  FD_ZERO (&wfds);
  FD_SET (cfd, &wfds);
  struct timeval tv = { .tv_sec = 2 };
  select (cfd + 1, NULL, &wfds, NULL, &tv);

  write (cfd, "ping", 4);
  pthread_join (tid, NULL);

  ASSERT_MSG (ctx.accepted_fd >= 0, "accept should succeed");

  /* Server sends reply */
  write (ctx.accepted_fd, "pong", 4);

  /* Client reads reply (may need to wait for non-blocking socket) */
  usleep (50000);
  /* Set blocking for the read */
  int flags = fcntl (cfd, F_GETFL, 0);
  fcntl (cfd, F_SETFL, flags & ~O_NONBLOCK);

  char reply[16] = {};
  struct timeval read_tv = { .tv_sec = 2 };
  setsockopt (cfd, SOL_SOCKET, SO_RCVTIMEO, &read_tv, sizeof (read_tv));
  ssize_t n = read (cfd, reply, sizeof (reply));
  ASSERT_MSG (n == 4, "should receive reply");
  ASSERT_MSG (memcmp (reply, "pong", 4) == 0, "reply should match");

  close (cfd);
  close (ctx.accepted_fd);
  close (listener);
  unlink (SOCK_PATH);
  printf ("OK\n");
  PASS ();
}

/* --- Test: client_socket_unix fails on non-existent path --- */

static void test_unix_socket_nonexistent (void) {
  printf ("test_unix_socket_nonexistent... ");

  int cfd = client_socket_unix ("/tmp/teleproxy_no_such_socket_12345.sock");
  ASSERT_MSG (cfd < 0, "should fail on non-existent socket");

  printf ("OK\n");
  PASS ();
}

/* --- Test: client_socket_unix rejects NULL path --- */

static void test_unix_socket_null_path (void) {
  printf ("test_unix_socket_null_path... ");

  int cfd = client_socket_unix (NULL);
  ASSERT_MSG (cfd < 0, "should fail with NULL path");

  printf ("OK\n");
  PASS ();
}

/* --- Test: client_socket_unix rejects path that's too long --- */

static void test_unix_socket_path_too_long (void) {
  printf ("test_unix_socket_path_too_long... ");

  /* sockaddr_un.sun_path is typically 108 bytes */
  char long_path[256];
  memset (long_path, 'a', sizeof (long_path) - 1);
  long_path[sizeof (long_path) - 1] = '\0';

  int cfd = client_socket_unix (long_path);
  ASSERT_MSG (cfd < 0, "should fail with too-long path");

  printf ("OK\n");
  PASS ();
}

/* --- Test: getsockname returns AF_UNIX for unix socket --- */

static void test_unix_getsockname (void) {
  printf ("test_unix_getsockname... ");

  int listener = create_listener (SOCK_PATH);

  pthread_t tid;
  struct accept_ctx ctx = { .listen_fd = listener };
  pthread_create (&tid, NULL, accept_thread, &ctx);
  usleep (50000);

  int cfd = client_socket_unix (SOCK_PATH);
  ASSERT_MSG (cfd >= 0, "connect should succeed");

  /* Wait for connect */
  fd_set wfds;
  FD_ZERO (&wfds);
  FD_SET (cfd, &wfds);
  struct timeval tv = { .tv_sec = 2 };
  select (cfd + 1, NULL, &wfds, NULL, &tv);

  /* Verify getsockname returns AF_UNIX — this is what alloc_new_connection checks */
  struct sockaddr_un sa;
  socklen_t sa_len = sizeof (sa);
  memset (&sa, 0, sizeof (sa));
  int r = getsockname (cfd, (struct sockaddr *) &sa, &sa_len);
  ASSERT_MSG (r == 0, "getsockname should succeed");
  ASSERT_MSG (sa.sun_family == AF_UNIX, "family should be AF_UNIX");

  write (cfd, "x", 1);
  pthread_join (tid, NULL);

  close (cfd);
  close (ctx.accepted_fd);
  close (listener);
  unlink (SOCK_PATH);
  printf ("OK\n");
  PASS ();
}

/* --- Test: PROXY protocol v1 format (IPv4) --- */

static void test_proxy_protocol_v1_ipv4 (void) {
  printf ("test_proxy_protocol_v1_ipv4... ");

  struct in_addr src, dst;
  inet_pton (AF_INET, "192.168.1.100", &src);
  inet_pton (AF_INET, "10.0.0.1", &dst);

  char buf[256];
  int len = format_proxy_protocol_v1 (buf, sizeof (buf), 0, &src, &dst, 12345, 443);

  ASSERT_MSG (len > 0, "format should succeed");
  ASSERT_MSG (strcmp (buf, "PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n") == 0,
              "header should match expected format");

  printf ("OK\n");
  PASS ();
}

/* --- Test: PROXY protocol v1 format (IPv6) --- */

static void test_proxy_protocol_v1_ipv6 (void) {
  printf ("test_proxy_protocol_v1_ipv6... ");

  struct in6_addr src, dst;
  inet_pton (AF_INET6, "2001:db8::1", &src);
  inet_pton (AF_INET6, "::1", &dst);

  char buf[256];
  int len = format_proxy_protocol_v1 (buf, sizeof (buf), 1, &src, &dst, 54321, 8080);

  ASSERT_MSG (len > 0, "format should succeed");

  /* Check that it starts with PROXY TCP6 and ends with \r\n */
  ASSERT_MSG (strncmp (buf, "PROXY TCP6 ", 11) == 0, "should start with PROXY TCP6");
  ASSERT_MSG (buf[len - 2] == '\r' && buf[len - 1] == '\n', "should end with \\r\\n");
  ASSERT_MSG (strstr (buf, "54321") != NULL, "should contain source port");
  ASSERT_MSG (strstr (buf, "8080") != NULL, "should contain dest port");

  printf ("OK\n");
  PASS ();
}

/* --- Test: PROXY protocol sent through Unix socket --- */

struct proxy_accept_ctx {
  int listen_fd;
  int accepted_fd;
  char received[512];
  int received_len;
};

static void *proxy_accept_thread (void *arg) {
  struct proxy_accept_ctx *ctx = arg;
  ctx->accepted_fd = accept (ctx->listen_fd, NULL, NULL);
  if (ctx->accepted_fd >= 0) {
    /* Read all available data (header + payload) */
    usleep (100000);
    ctx->received_len = read (ctx->accepted_fd, ctx->received, sizeof (ctx->received) - 1);
    if (ctx->received_len > 0) {
      ctx->received[ctx->received_len] = '\0';
    }
  }
  return NULL;
}

static void test_proxy_protocol_over_unix (void) {
  printf ("test_proxy_protocol_over_unix... ");

  int listener = create_listener (SOCK_PATH);
  struct proxy_accept_ctx ctx = { .listen_fd = listener };

  pthread_t tid;
  pthread_create (&tid, NULL, proxy_accept_thread, &ctx);
  usleep (50000);

  int cfd = client_socket_unix (SOCK_PATH);
  ASSERT_MSG (cfd >= 0, "connect should succeed");

  fd_set wfds;
  FD_ZERO (&wfds);
  FD_SET (cfd, &wfds);
  struct timeval tv = { .tv_sec = 2 };
  select (cfd + 1, NULL, &wfds, NULL, &tv);

  /* Format and send PROXY header + payload */
  struct in_addr src, dst;
  inet_pton (AF_INET, "1.2.3.4", &src);
  inet_pton (AF_INET, "5.6.7.8", &dst);

  char header[256];
  int hlen = format_proxy_protocol_v1 (header, sizeof (header), 0, &src, &dst, 9999, 443);
  ASSERT_MSG (hlen > 0, "header format should succeed");

  write (cfd, header, hlen);
  write (cfd, "PAYLOAD", 7);

  pthread_join (tid, NULL);

  ASSERT_MSG (ctx.accepted_fd >= 0, "accept should succeed");
  ASSERT_MSG (ctx.received_len > hlen, "should receive header + payload");

  /* Verify the PROXY header is at the start */
  const char *expected_hdr = "PROXY TCP4 1.2.3.4 5.6.7.8 9999 443\r\n";
  int expected_hdr_len = (int)strlen (expected_hdr);
  ASSERT_MSG (strncmp (ctx.received, expected_hdr, expected_hdr_len) == 0,
              "PROXY header should be at start of stream");

  /* Verify payload follows */
  ASSERT_MSG (strncmp (ctx.received + expected_hdr_len, "PAYLOAD", 7) == 0,
              "payload should follow header");

  close (cfd);
  close (ctx.accepted_fd);
  close (listener);
  unlink (SOCK_PATH);
  printf ("OK\n");
  PASS ();
}

/* Format PROXY protocol v2 header (same logic as in net-tcp-rpc-ext-server.c). */
static int format_proxy_protocol_v2 (unsigned char *buf, size_t bufsize,
                                      int is_ipv6,
                                      const void *src_addr, const void *dst_addr,
                                      unsigned src_port, unsigned dst_port) {
  static const unsigned char v2_sig[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  };
  int len = is_ipv6 ? 52 : 28;
  if ((int)bufsize < len) { return -1; }

  memcpy (buf, v2_sig, 12);
  buf[12] = 0x21; /* version 2, command PROXY */

  if (is_ipv6) {
    buf[13] = 0x21; /* AF_INET6, STREAM */
    buf[14] = 0;
    buf[15] = 36;
    memcpy (buf + 16, src_addr, 16);
    memcpy (buf + 32, dst_addr, 16);
    *(unsigned short *)(buf + 48) = htons ((unsigned short)src_port);
    *(unsigned short *)(buf + 50) = htons ((unsigned short)dst_port);
  } else {
    buf[13] = 0x11; /* AF_INET, STREAM */
    buf[14] = 0;
    buf[15] = 12;
    memcpy (buf + 16, src_addr, 4);
    memcpy (buf + 20, dst_addr, 4);
    *(unsigned short *)(buf + 24) = htons ((unsigned short)src_port);
    *(unsigned short *)(buf + 26) = htons ((unsigned short)dst_port);
  }
  return len;
}

/* --- Test: PROXY protocol v2 format (IPv4) --- */

static void test_proxy_protocol_v2_ipv4 (void) {
  printf ("test_proxy_protocol_v2_ipv4... ");

  struct in_addr src, dst;
  inet_pton (AF_INET, "192.168.1.100", &src);
  inet_pton (AF_INET, "10.0.0.1", &dst);

  unsigned char buf[64];
  int len = format_proxy_protocol_v2 (buf, sizeof (buf), 0, &src, &dst, 12345, 443);

  ASSERT_MSG (len == 28, "IPv4 v2 header should be 28 bytes");

  /* Check signature */
  static const unsigned char expected_sig[] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  };
  ASSERT_MSG (memcmp (buf, expected_sig, 12) == 0, "signature should match");

  ASSERT_MSG (buf[12] == 0x21, "version+command should be 0x21");
  ASSERT_MSG (buf[13] == 0x11, "family+proto should be 0x11 (AF_INET+STREAM)");
  ASSERT_MSG (buf[14] == 0 && buf[15] == 12, "addr length should be 12");

  /* Check addresses */
  ASSERT_MSG (memcmp (buf + 16, &src, 4) == 0, "src addr should match");
  ASSERT_MSG (memcmp (buf + 20, &dst, 4) == 0, "dst addr should match");
  ASSERT_MSG (ntohs (*(unsigned short *)(buf + 24)) == 12345, "src port should be 12345");
  ASSERT_MSG (ntohs (*(unsigned short *)(buf + 26)) == 443, "dst port should be 443");

  printf ("OK\n");
  PASS ();
}

/* --- Test: PROXY protocol v2 format (IPv6) --- */

static void test_proxy_protocol_v2_ipv6 (void) {
  printf ("test_proxy_protocol_v2_ipv6... ");

  struct in6_addr src, dst;
  inet_pton (AF_INET6, "2001:db8::1", &src);
  inet_pton (AF_INET6, "::1", &dst);

  unsigned char buf[64];
  int len = format_proxy_protocol_v2 (buf, sizeof (buf), 1, &src, &dst, 54321, 8080);

  ASSERT_MSG (len == 52, "IPv6 v2 header should be 52 bytes");
  ASSERT_MSG (buf[12] == 0x21, "version+command should be 0x21");
  ASSERT_MSG (buf[13] == 0x21, "family+proto should be 0x21 (AF_INET6+STREAM)");
  ASSERT_MSG (buf[14] == 0 && buf[15] == 36, "addr length should be 36");

  ASSERT_MSG (memcmp (buf + 16, &src, 16) == 0, "src addr should match");
  ASSERT_MSG (memcmp (buf + 32, &dst, 16) == 0, "dst addr should match");
  ASSERT_MSG (ntohs (*(unsigned short *)(buf + 48)) == 54321, "src port should be 54321");
  ASSERT_MSG (ntohs (*(unsigned short *)(buf + 50)) == 8080, "dst port should be 8080");

  printf ("OK\n");
  PASS ();
}

/* --- Test: PROXY protocol v2 sent through Unix socket --- */

static void test_proxy_protocol_v2_over_unix (void) {
  printf ("test_proxy_protocol_v2_over_unix... ");

  int listener = create_listener (SOCK_PATH);
  struct proxy_accept_ctx ctx = { .listen_fd = listener };

  pthread_t tid;
  pthread_create (&tid, NULL, proxy_accept_thread, &ctx);
  usleep (50000);

  int cfd = client_socket_unix (SOCK_PATH);
  ASSERT_MSG (cfd >= 0, "connect should succeed");

  fd_set wfds;
  FD_ZERO (&wfds);
  FD_SET (cfd, &wfds);
  struct timeval tv = { .tv_sec = 2 };
  select (cfd + 1, NULL, &wfds, NULL, &tv);

  struct in_addr src, dst;
  inet_pton (AF_INET, "1.2.3.4", &src);
  inet_pton (AF_INET, "5.6.7.8", &dst);

  unsigned char header[64];
  int hlen = format_proxy_protocol_v2 (header, sizeof (header), 0, &src, &dst, 9999, 443);
  ASSERT_MSG (hlen == 28, "v2 header should be 28 bytes");

  write (cfd, header, hlen);
  write (cfd, "PAYLOAD", 7);

  pthread_join (tid, NULL);

  ASSERT_MSG (ctx.accepted_fd >= 0, "accept should succeed");
  ASSERT_MSG (ctx.received_len >= hlen + 7, "should receive header + payload");

  /* Verify v2 signature at start */
  static const unsigned char expected_sig[] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  };
  ASSERT_MSG (memcmp (ctx.received, expected_sig, 12) == 0, "v2 signature at start");

  /* Verify payload follows after 28-byte header */
  ASSERT_MSG (memcmp (ctx.received + 28, "PAYLOAD", 7) == 0, "payload should follow v2 header");

  close (cfd);
  close (ctx.accepted_fd);
  close (listener);
  unlink (SOCK_PATH);
  printf ("OK\n");
  PASS ();
}

int main (void) {
  printf ("=== Unix socket + PROXY protocol tests ===\n\n");

  test_unix_socket_connect ();
  test_unix_socket_bidirectional ();
  test_unix_socket_nonexistent ();
  test_unix_socket_null_path ();
  test_unix_socket_path_too_long ();
  test_unix_getsockname ();
  test_proxy_protocol_v1_ipv4 ();
  test_proxy_protocol_v1_ipv6 ();
  test_proxy_protocol_over_unix ();
  test_proxy_protocol_v2_ipv4 ();
  test_proxy_protocol_v2_ipv6 ();
  test_proxy_protocol_v2_over_unix ();

  printf ("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
