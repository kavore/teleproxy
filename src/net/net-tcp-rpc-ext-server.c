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

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2018 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman
                    2016-2018 Nikolai Durov
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "common/kprintf.h"
#include "common/precise-time.h"
#include "common/resolver.h"
#include "common/rpc-const.h"
#include "common/sha256.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-events.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-drs.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tls-parse.h"
#include "net/net-thread.h"
#include "mtproto/mtproto-dc-table.h"

#include "vv/vv-io.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern char *unix_target_path;
extern int proxy_protocol_enabled;

/*
 *
 *                EXTERNAL RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_compact_parse_execute (connection_job_t c);
int tcp_rpcs_ext_alarm (connection_job_t c);
static int tcp_rpcs_ext_drs_alarm (connection_job_t c);
int tcp_rpcs_ext_init_accepted (connection_job_t c);

conn_type_t ct_tcp_rpc_ext_server = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server",
  .init_accepted = tcp_rpcs_ext_init_accepted,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_ext_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DRS variant: uses dynamic record sizing for TLS connections */
conn_type_t ct_tcp_rpc_ext_server_drs = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server_drs",
  .init_accepted = tcp_rpcs_ext_init_accepted,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_ext_drs_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output_drs,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

int tcp_proxy_pass_parse_execute (connection_job_t C);
int tcp_proxy_pass_close (connection_job_t C, int who);
int tcp_proxy_pass_connected (connection_job_t C);
int tcp_proxy_pass_write_packet (connection_job_t c, struct raw_message *raw); 

conn_type_t ct_proxy_pass = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "proxypass",
  .init_accepted = server_failed,
  .parse_execute = tcp_proxy_pass_parse_execute,
  .connected = tcp_proxy_pass_connected,
  .close = tcp_proxy_pass_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
};

static int tcp_proxy_pass_unix_connected (connection_job_t C);

/* Unix socket variant of proxy pass: logs unix connection events */
conn_type_t ct_proxy_pass_unix = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "proxypass_unix",
  .init_accepted = server_failed,
  .parse_execute = tcp_proxy_pass_parse_execute,
  .connected = tcp_proxy_pass_unix_connected,
  .close = tcp_proxy_pass_close,
  .write_packet = tcp_proxy_pass_write_packet,
};

int tcp_proxy_pass_connected (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "proxy pass connected #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  return 0;
}

int tcp_proxy_pass_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    fail_connection (C, -1);
    return 0;
  }
  job_t E = job_incref (c->extra);
  struct connection_info *e = CONN_INFO(E);

  struct raw_message *r = malloc (sizeof (*r));
  rwm_move (r, &c->in);
  rwm_init (&c->in, 0);
  vkprintf (3, "proxying %d bytes to %s:%d\n", r->total_bytes, show_remote_ip (E), e->remote_port);
  mpq_push_w (e->out_queue, PTR_MOVE(r), 0);
  job_signal (JOB_REF_PASS (E), JS_RUN);
  return 0;
}

int tcp_proxy_pass_close (connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "closing proxy pass connection #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  if (c->extra) {
    job_t E = PTR_MOVE (c->extra);
    fail_connection (E, -23);
    job_decref (JOB_REF_PASS (E));
  }
  return cpu_server_close_connection (C, who);
}

int tcp_proxy_pass_write_packet (connection_job_t C, struct raw_message *raw) {
  rwm_union (&CONN_INFO(C)->out, raw);
  return 0;
}

/* Called when proxy_pass Unix socket connection is established.
   Sends PROXY protocol v1 header if enabled, then flushes any pending data. */
static int tcp_proxy_pass_unix_connected (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "proxy pass unix connected #%d to %s\n", c->fd,
            unix_target_path ? unix_target_path : "(unknown)");
  return 0;
}

/*
 *
 *      DIRECT-TO-DC RELAY
 *
 */

extern int direct_mode;
extern int ipv6_enabled;
extern int workers;
extern long long direct_dc_connections_created, direct_dc_connections_active;
extern long long direct_dc_connections_failed, direct_dc_connections_dc_closed;
extern long long direct_dc_retries;
extern long long per_secret_connections[16], per_secret_connections_created[16];
extern long long per_secret_connections_rejected[16];
extern long long transport_errors_received;
extern long long quickack_packets_received;

#define DIRECT_MAX_RETRIES 3
#define DIRECT_RETRY_BASE_SEC 0.2  /* 200ms, 400ms, 800ms */

static int tcp_direct_client_parse_execute (connection_job_t C);
static int tcp_direct_dc_parse_execute (connection_job_t C);
static int tcp_direct_dc_connected (connection_job_t C);
static int tcp_direct_close (connection_job_t C, int who);
static int tcp_direct_client_alarm (connection_job_t C);

/* Client-side relay: keeps the client's AES-CTR crypto active */
conn_type_t ct_direct_client = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_client",
  .parse_execute = tcp_direct_client_parse_execute,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
  .alarm = tcp_direct_client_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DRS variant of client-side relay for TLS connections */
conn_type_t ct_direct_client_drs = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_client_drs",
  .parse_execute = tcp_direct_client_parse_execute,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
  .alarm = tcp_rpcs_ext_drs_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output_drs,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DC-side relay: its own AES-CTR crypto for the proxy→DC obfuscated2 connection */
conn_type_t ct_direct_dc = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_dc",
  .init_accepted = server_failed,
  .parse_execute = tcp_direct_dc_parse_execute,
  .connected = tcp_direct_dc_connected,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* Relay bytes from one end to the other (client→DC or DC→client).
   Identical to tcp_proxy_pass_parse_execute but the paired connection
   has crypto enabled, so the engine will encrypt before flushing. */
static int tcp_direct_relay (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    fail_connection (C, -1);
    return 0;
  }
  job_t E = job_incref (c->extra);
  struct connection_info *e = CONN_INFO(E);

  struct raw_message *r = malloc (sizeof (*r));
  rwm_move (r, &c->in);
  rwm_init (&c->in, 0);
  vkprintf (3, "direct relay %d bytes to %s:%d\n", r->total_bytes, show_remote_ip (E), e->remote_port);
  mpq_push_w (e->out_queue, PTR_MOVE(r), 0);
  job_signal (JOB_REF_PASS (E), JS_RUN);
  return 0;
}

static int tcp_direct_client_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    /* No DC connection — either retry pending or permanent failure */
    if (TCP_RPC_DATA(C)->extra_int > 0) {
      return NEED_MORE_BYTES;  /* retry timer will fire */
    }
    fail_connection (C, -1);
    return 0;
  }
  /* Don't relay until the DC connection has sent its obfuscated2 init.
     The connected callback sets crypto when it's done and signals us. */
  struct connection_info *dc = CONN_INFO((connection_job_t) c->extra);
  if (!dc->crypto) {
    vkprintf (2, "direct client: DC not ready yet, deferring %d bytes\n", c->in.total_bytes);
    return NEED_MORE_BYTES;
  }
  return tcp_direct_relay (C);
}

static int tcp_direct_dc_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);

  /* Detect transport error codes from DC: a single 4-byte negative int
     (e.g. -404 "auth key not found", -429 "flood", -444 "invalid DC") */
  if (c->in.total_bytes == 4) {
    int code;
    if (rwm_fetch_lookup (&c->in, &code, 4) == 4 && code < 0 && code > -1000) {
      int target_dc = TCP_RPC_DATA(C)->extra_int4;
      kprintf ("direct mode: DC %d sent transport error %d\n", target_dc, code);
      transport_errors_received++;
    }
  }

  return tcp_direct_relay (C);
}

static int direct_schedule_retry (connection_job_t C, int target_dc, int attempt);
static void direct_retry_dc_connection (connection_job_t C);

static int tcp_direct_close (connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  int is_client = (c->type == &ct_direct_client || c->type == &ct_direct_client_drs);
  int is_dc = (c->type == &ct_direct_dc);
  int target_dc = TCP_RPC_DATA(C)->extra_int4;
  double duration = precise_now - c->query_start_time;

  vkprintf (1, "direct: closing %s connection #%d (DC %d) after %.1fs, %s:%d -> %s:%d, who=%d\n",
            is_client ? "client" : "DC", c->fd, target_dc, duration,
            show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port, who);

  /* DC connection failed before handshake completed — eligible for retry */
  if (is_dc && c->extra && !c->crypto) {
    connection_job_t client = (connection_job_t) c->extra;
    int attempt = TCP_RPC_DATA(client)->extra_int;
    if (attempt < DIRECT_MAX_RETRIES) {
      vkprintf (1, "direct mode: DC %d connection failed (async), scheduling retry %d/%d\n",
                target_dc, attempt + 1, DIRECT_MAX_RETRIES);
      /* Detach client from this dying DC connection */
      CONN_INFO(client)->extra = NULL;
      job_t E = PTR_MOVE (c->extra);
      direct_dc_connections_failed++;
      direct_schedule_retry (client, target_dc, attempt);
      job_decref (JOB_REF_PASS (E));
      return cpu_server_close_connection (C, who);
    }
  }

  if (is_client && direct_dc_connections_active > 0) {
    direct_dc_connections_active--;
    int sid = TCP_RPC_DATA(C)->extra_int2;
    if (sid > 0 && sid <= 16) {
      per_secret_connections[sid - 1]--;
    }
  }
  if (is_dc && who != 0) {
    /* DC side closed unexpectedly (not by us tearing down the pair) */
    direct_dc_connections_dc_closed++;
  }
  if (c->extra) {
    job_t E = PTR_MOVE (c->extra);
    fail_connection (E, -23);
    job_decref (JOB_REF_PASS (E));
  }
  return cpu_server_close_connection (C, who);
}

/* Alarm handler for non-DRS direct client connections (obfs2).
   Handles retry when DC connection is not yet established. */
static int tcp_direct_client_alarm (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra && TCP_RPC_DATA(C)->extra_int > 0) {
    direct_retry_dc_connection (C);
    return 0;
  }
  return 0;
}

/* Called when the outbound TCP connection to the DC is established.
   Generates and sends the obfuscated2 init payload. */
static int tcp_direct_dc_connected (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int target_dc = D->extra_int4;

  vkprintf (1, "direct DC connection established (fd=%d), target DC=%d, sending obfuscated2 init\n", c->fd, target_dc);

  /* Generate 64-byte obfuscated2 init payload */
  unsigned char init[64];
  int tries = 0;
  do {
    RAND_bytes (init, 64);
    tries++;
  } while (
    init[0] == 0xef ||
    *(unsigned *)init == 0x44414548 ||   /* "HEAD" */
    *(unsigned *)init == 0x54534f50 ||   /* "POST" */
    *(unsigned *)init == 0x20544547 ||   /* "GET " */
    *(unsigned *)init == 0x4954504f ||   /* "OPTI" */
    *(unsigned *)init == 0xeeeeeeee ||
    *(unsigned *)init == 0xdddddddd ||
    *(unsigned *)init == 0xefefefef ||
    *(unsigned *)(init + 4) == 0x00000000
  );

  /* Set protocol tag matching the client's transport and target DC */
  unsigned client_tag = (unsigned)D->extra_int3;
  if (!client_tag) {
    client_tag = 0xeeeeeeee;  /* fallback: intermediate */
  }
  *(unsigned *)(init + 56) = client_tag;
  *(short *)(init + 60) = (short)target_dc;

  /* Derive AES keys -- NO secret mixing (DCs don't know proxy secret).
     Proxy is acting as client:
       write (encrypt outgoing) = forward direction from init
       read (decrypt incoming)  = reversed direction from init */
  struct aes_key_data key_data;
  memcpy (key_data.write_key, init + 8, 32);
  memcpy (key_data.write_iv, init + 40, 16);
  int i;
  for (i = 0; i < 32; i++) {
    key_data.read_key[i] = init[55 - i];
  }
  for (i = 0; i < 16; i++) {
    key_data.read_iv[i] = init[23 - i];
  }

  /* Encrypt all 64 bytes with write key to produce the encrypted init.
     Only bytes 56-63 get replaced in the sent payload (obfuscated2 protocol). */
  unsigned char encrypted[64];
  EVP_CIPHER_CTX *tmp_ctx = EVP_CIPHER_CTX_new ();
  assert (tmp_ctx);
  assert (EVP_EncryptInit_ex (tmp_ctx, EVP_aes_256_ctr (), NULL, key_data.write_key, key_data.write_iv));
  int outlen = 0;
  assert (EVP_EncryptUpdate (tmp_ctx, encrypted, &outlen, init, 64));
  assert (outlen == 64);

  /* Replace bytes 56-63 with their encrypted version */
  memcpy (init + 56, encrypted + 56, 8);

  /* Send the 64-byte init as raw bytes, bypassing the crypto layer.
     We write to out_p (post-crypto buffer) because c->crypto will be set
     below — anything in c->out would be AES-encrypted on flush. */
  assert (rwm_push_data (&c->out_p, init, 64) == 64);

  /* Now set up the AES-CTR crypto context for ongoing communication.
     The write counter must start at position 64 (we already "used" 64 bytes
     for the init). We achieve this by using the temp context's state. */
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  T->write_aeskey = tmp_ctx;   /* counter already at 64 */
  T->read_aeskey = evp_cipher_ctx_init (EVP_aes_256_ctr (), key_data.read_key, key_data.read_iv, 1);
  c->crypto = T;

  /* Flush deferred client data: the client's parse_execute returned
     NEED_MORE_BYTES while waiting for this DC init, which set skip_bytes.
     Reset it so the reader re-enters parse_execute on the next signal. */
  if (c->extra) {
    CONN_INFO((connection_job_t) c->extra)->skip_bytes = 0;
    job_signal (JOB_REF_CREATE_PASS (c->extra), JS_RUN);
  }

  return 0;
}

/* Try to establish a DC connection using one of the entry's addresses.
   Returns the connection job on success, or NULL if all addresses failed. */
static job_t direct_try_dc_addrs (connection_job_t C, const struct dc_entry *dc, int target_dc) {
  static const unsigned char zero_ipv6[16] = {};

  for (int i = 0; i < dc->addr_count; i++) {
    const struct dc_addr *addr = &dc->addrs[i];
    int has_ipv6 = memcmp (addr->ipv6, zero_ipv6, 16) != 0;
    int use_ipv6 = ipv6_enabled && has_ipv6;

    if (use_ipv6) {
      char addr_buf[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, addr->ipv6, addr_buf, sizeof (addr_buf));
      vkprintf (1, "direct mode: trying DC %d addr %d/%d ([%s]:%d) via IPv6\n",
                target_dc, i + 1, dc->addr_count, addr_buf, addr->port);
    } else if (addr->ipv4) {
      vkprintf (1, "direct mode: trying DC %d addr %d/%d (%s:%d)\n",
                target_dc, i + 1, dc->addr_count,
                inet_ntoa (*(struct in_addr *)&addr->ipv4), addr->port);
    } else {
      continue;  /* no usable address */
    }

    int cfd;
    if (use_ipv6) {
      cfd = client_socket_ipv6 (addr->ipv6, addr->port, SM_IPV6);
    } else {
      cfd = client_socket (addr->ipv4, addr->port, 0);
    }
    if (cfd < 0) {
      vkprintf (1, "direct mode: DC %d addr %d/%d connect failed: %m\n",
                target_dc, i + 1, dc->addr_count);
      continue;
    }

    job_incref (C);
    job_t EJ;
    if (use_ipv6) {
      EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_direct_dc, C,
                                  0, (unsigned char *)addr->ipv6, addr->port);
    } else {
      EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_direct_dc, C,
                                  ntohl (addr->ipv4), NULL, addr->port);
    }
    if (!EJ) {
      vkprintf (1, "direct mode: DC %d addr %d/%d alloc_new_connection failed\n",
                target_dc, i + 1, dc->addr_count);
      job_decref_f (C);
      continue;
    }
    return EJ;
  }
  return NULL;
}

static int direct_schedule_retry (connection_job_t C, int target_dc, int attempt) {
  if (attempt >= DIRECT_MAX_RETRIES) {
    kprintf ("direct mode: all %d retries exhausted for DC %d\n", DIRECT_MAX_RETRIES, target_dc);
    direct_dc_connections_failed++;
    fail_connection (C, -27);
    return 0;
  }
  TCP_RPC_DATA(C)->extra_int = attempt + 1;
  double backoff = DIRECT_RETRY_BASE_SEC * (1 << attempt);
  job_timer_insert (C, precise_now + backoff);
  direct_dc_retries++;
  vkprintf (1, "direct mode: DC %d connect failed, retry %d/%d in %.0fms\n",
            target_dc, attempt + 1, DIRECT_MAX_RETRIES, backoff * 1000.0);
  return 0;
}

static void direct_retry_dc_connection (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  int target_dc = TCP_RPC_DATA(C)->extra_int4;
  int attempt = TCP_RPC_DATA(C)->extra_int;

  const struct dc_entry *dc = direct_dc_lookup (target_dc);
  if (!dc) {
    kprintf ("direct mode: DC %d not found during retry\n", target_dc);
    direct_dc_connections_failed++;
    TCP_RPC_DATA(C)->extra_int = 0;
    fail_connection (C, -1);
    return;
  }

  job_t EJ = direct_try_dc_addrs (C, dc, target_dc);
  if (EJ) {
    int outbound_dc = (target_dc < 0 ? -1 : 1) * dc->dc_id;
    TCP_RPC_DATA(EJ)->extra_int4 = outbound_dc;
    TCP_RPC_DATA(EJ)->extra_int3 = TCP_RPC_DATA(C)->extra_int3;
    c->extra = job_incref (EJ);
    CONN_INFO(EJ)->extra = job_incref (C);
    TCP_RPC_DATA(C)->extra_int = 0;  /* clear retry state */
    direct_dc_connections_created++;
    direct_dc_connections_active++;
    vkprintf (1, "direct mode: retry %d succeeded for DC %d\n", attempt, target_dc);
    assert (CONN_INFO(EJ)->io_conn);
    unlock_job (JOB_REF_PASS (EJ));
    return;
  }

  /* All addresses failed again */
  direct_dc_connections_failed++;
  direct_schedule_retry (C, target_dc, attempt);
}

/* Route a client connection directly to a Telegram DC.
   Called after the obfuscated2 handshake is parsed and the target DC is known. */
static int direct_connect_to_dc (connection_job_t C, int target_dc) {
  struct connection_info *c = CONN_INFO(C);

  const struct dc_entry *dc = direct_dc_lookup (target_dc);
  if (!dc) {
    kprintf ("direct mode: unknown DC %d, closing connection\n", target_dc);
    direct_dc_connections_failed++;
    fail_connection (C, -1);
    return 0;
  }

  static int direct_types_checked;
  if (!direct_types_checked) {
    assert (check_conn_functions (&ct_direct_dc, 0) >= 0);
    assert (check_conn_functions (&ct_direct_client, 0) >= 0);
    assert (check_conn_functions (&ct_direct_client_drs, 0) >= 0);
    direct_types_checked = 1;
  }

  /* Switch client type early so alarm handler is available for retries */
  if (c->flags & C_IS_TLS) {
    c->type = &ct_direct_client_drs;
    struct drs_state *drs = DRS_STATE (C);
    drs->record_index = 0;
    drs->total_records = 0;
    drs->last_record_time = precise_now;
    drs->delay_pending = 0;
  } else {
    c->type = &ct_direct_client;
  }

  job_t EJ = direct_try_dc_addrs (C, dc, target_dc);
  if (!EJ) {
    /* All addresses failed synchronously — schedule retry */
    direct_dc_connections_failed++;
    return direct_schedule_retry (C, target_dc, 0);
  }

  /* Store resolved DC for the outbound init header.
     Preserve the media flag (negative sign) from the original target.
     CDN/test offsets are already stripped by direct_dc_lookup(). */
  int outbound_dc = (target_dc < 0 ? -1 : 1) * dc->dc_id;
  TCP_RPC_DATA(EJ)->extra_int4 = outbound_dc;
  TCP_RPC_DATA(EJ)->extra_int3 = TCP_RPC_DATA(C)->extra_int3;  /* client transport tag */

  c->extra = job_incref (EJ);

  /* Link DC connection back to client */
  CONN_INFO(EJ)->extra = job_incref (C);

  direct_dc_connections_created++;
  direct_dc_connections_active++;

  /* Per-secret increment already done in tcp_rpcs_compact_parse_execute
     before direct_connect_to_dc is called. */

  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return 0;
}

/*
 *
 *      END DIRECT-TO-DC RELAY
 *
 */

int tcp_rpcs_default_execute (connection_job_t c, int op, struct raw_message *msg);

static unsigned char ext_secret[16][16];
static int ext_secret_cnt = 0;
static int ext_rand_pad_only = 0;
static char ext_secret_label[16][EXT_SECRET_LABEL_MAX + 1];
static int ext_secret_limit[16];  /* 0 = unlimited */

void tcp_rpcs_set_ext_secret (unsigned char secret[16], const char *label, int limit) {
  assert (ext_secret_cnt < 16);
  int idx = ext_secret_cnt++;
  memcpy (ext_secret[idx], secret, 16);
  if (label && label[0]) {
    snprintf (ext_secret_label[idx], sizeof (ext_secret_label[idx]), "%s", label);
  } else {
    snprintf (ext_secret_label[idx], sizeof (ext_secret_label[idx]), "secret_%d", idx);
  }
  ext_secret_limit[idx] = limit;
  if (limit > 0) {
    vkprintf (0, "Added secret #%d label=[%s] limit=%d\n", idx, ext_secret_label[idx], limit);
  } else {
    vkprintf (0, "Added secret #%d label=[%s] (unlimited)\n", idx, ext_secret_label[idx]);
  }
}

const char *tcp_rpcs_get_ext_secret_label (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_label[index];
}

int tcp_rpcs_get_ext_secret_limit (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_limit[index];
}

int tcp_rpcs_get_ext_secret_count (void) {
  return ext_secret_cnt;
}

static int secret_over_limit (int secret_id) {
  int limit = ext_secret_limit[secret_id];
  if (limit <= 0) { return 0; }
  int eff = workers > 1 ? limit / workers : limit;
  if (eff < 1) { eff = 1; }
  return per_secret_connections[secret_id] >= eff;
}

void tcp_rpcs_set_ext_rand_pad_only(int set) {
  ext_rand_pad_only = set;
}

static int allow_only_tls;

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

static struct domain_info *default_domain_info;

#define DOMAIN_HASH_MOD 257
static struct domain_info *domains[DOMAIN_HASH_MOD];

static struct domain_info **get_domain_info_bucket (const char *domain, size_t len) {
  size_t i;
  unsigned hash = 0;
  for (i = 0; i < len; i++) {
    hash = hash * 239017 + (unsigned char)domain[i];
  }
  return domains + hash % DOMAIN_HASH_MOD;
}

static const struct domain_info *get_domain_info (const char *domain, size_t len) {
  struct domain_info *info = *get_domain_info_bucket (domain, len);
  while (info != NULL) {
    if (strlen (info->domain) == len && memcmp (domain, info->domain, len) == 0) {
      return info;
    }
    info = info->next;
  }
  return NULL;
}

static int get_domain_server_hello_encrypted_size (const struct domain_info *info) {
  if (info->use_random_encrypted_size) {
    int r = rand();
    return info->server_hello_encrypted_size + ((r >> 1) & 1) - (r & 1);
  } else {
    return info->server_hello_encrypted_size;
  }
}

#define TLS_REQUEST_LENGTH 517

static BIGNUM *get_y2 (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns y^2 = x^3 + 486662 * x^2 + x
  BIGNUM *y = BN_dup (x);
  assert (y != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 486662) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  BN_clear_free (coef);
  return y;
}

static BIGNUM *get_double_x (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns x_2 = (x^2 - 1)^2/(4*y^2)
  BIGNUM *denominator = get_y2 (x, mod, big_num_context);
  assert (denominator != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 4) == 1);
  assert (BN_mod_mul (denominator, denominator, coef, mod, big_num_context) == 1);

  BIGNUM *numerator = BN_new();
  assert (numerator != NULL);
  assert (BN_mod_mul (numerator, x, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_sub (numerator, numerator, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (numerator, numerator, numerator, mod, big_num_context) == 1);

  assert (BN_mod_inverse (denominator, denominator, mod, big_num_context) == denominator);
  assert (BN_mod_mul (numerator, numerator, denominator, mod, big_num_context) == 1);

  BN_clear_free (coef);
  BN_clear_free (denominator);
  return numerator;
}

static void generate_public_key (unsigned char key[32]) {
  BIGNUM *mod = NULL;
  assert (BN_hex2bn (&mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") == 64);
  BIGNUM *pow = NULL;
  assert (BN_hex2bn (&pow, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6") == 64);
  BN_CTX *big_num_context = BN_CTX_new();
  assert (big_num_context != NULL);

  BIGNUM *x = BN_new();
  while (1) {
    assert (RAND_bytes (key, 32) == 1);
    key[31] &= 127;
    BN_bin2bn (key, 32, x);
    assert (x != NULL);
    assert (BN_mod_mul (x, x, x, mod, big_num_context) == 1);

    BIGNUM *y = get_y2 (x, mod, big_num_context);

    BIGNUM *r = BN_new();
    assert (BN_mod_exp (r, y, pow, mod, big_num_context) == 1);
    BN_clear_free (y);
    if (BN_is_one (r)) {
      BN_clear_free (r);
      break;
    }
    BN_clear_free (r);
  }

  int i;
  for (i = 0; i < 3; i++) {
    BIGNUM *x2 = get_double_x (x, mod, big_num_context);
    BN_clear_free (x);
    x = x2;
  }

  int num_size = BN_num_bytes (x);
  assert (num_size <= 32);
  memset (key, '\0', 32 - num_size);
  assert (BN_bn2bin (x, key + (32 - num_size)) == num_size);
  for (i = 0; i < 16; i++) {
    unsigned char t = key[i];
    key[i] = key[31 - i];
    key[31 - i] = t;
  }

  BN_clear_free (x);
  BN_CTX_free (big_num_context);
  BN_clear_free (pow);
  BN_clear_free (mod);
}

static void add_string (unsigned char *str, int *pos, const char *data, int data_len) {
  assert (*pos + data_len <= TLS_REQUEST_LENGTH);
  memcpy (str + (*pos), data, data_len);
  (*pos) += data_len;
}

static void add_random (unsigned char *str, int *pos, int random_len) {
  assert (*pos + random_len <= TLS_REQUEST_LENGTH);
  assert (RAND_bytes (str + (*pos), random_len) == 1);
  (*pos) += random_len;
}

static void add_length (unsigned char *str, int *pos, int length) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = (unsigned char)(length / 256);
  str[*pos + 1] = (unsigned char)(length % 256);
  (*pos) += 2;
}

static void add_grease (unsigned char *str, int *pos, const unsigned char *greases, int num) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = greases[num];
  str[*pos + 1] = greases[num];
  (*pos) += 2;
}

static void add_public_key (unsigned char *str, int *pos) {
  assert (*pos + 32 <= TLS_REQUEST_LENGTH);
  generate_public_key (str + (*pos));
  (*pos) += 32;
}

static unsigned char *create_request (const char *domain) {
  unsigned char *result = malloc (TLS_REQUEST_LENGTH);
  int pos = 0;

#define MAX_GREASE 7
  unsigned char greases[MAX_GREASE];
  assert (RAND_bytes (greases, MAX_GREASE) == 1);
  int i;
  for (i = 0; i < MAX_GREASE; i++) {
    greases[i] = (unsigned char)((greases[i] & 0xF0) + 0x0A);
  }
  for (i = 1; i < MAX_GREASE; i += 2) {
    if (greases[i] == greases[i - 1]) {
      greases[i] = (unsigned char)(0x10 ^ greases[i]);
    }
  }
#undef MAX_GREASE

  int domain_length = (int)strlen (domain);

  add_string (result, &pos, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", 11);
  add_random (result, &pos, 32);
  add_string (result, &pos, "\x20", 1);
  add_random (result, &pos, 32);
  add_string (result, &pos, "\x00\x22", 2);
  add_grease (result, &pos, greases, 0);
  add_string (result, &pos, "\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
                            "\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91", 36);
  add_grease (result, &pos, greases, 2);
  add_string (result, &pos, "\x00\x00\x00\x00", 4);
  add_length (result, &pos, domain_length + 5);
  add_length (result, &pos, domain_length + 3);
  add_string (result, &pos, "\x00", 1);
  add_length (result, &pos, domain_length);
  add_string (result, &pos, domain, domain_length);
  add_string (result, &pos, "\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08", 15);
  add_grease (result, &pos, greases, 4);
  add_string (result, &pos, "\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10"
                            "\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05"
                            "\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04"
                            "\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00"
                            "\x33\x00\x2b\x00\x29", 77);
  add_grease (result, &pos, greases, 4);
  add_string (result, &pos, "\x00\x01\x00\x00\x1d\x00\x20", 7);
  add_public_key (result, &pos);
  add_string (result, &pos, "\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a", 11);
  add_grease (result, &pos, greases, 6);
  add_string (result, &pos, "\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02", 15);
  add_grease (result, &pos, greases, 3);
  add_string (result, &pos, "\x00\x01\x00\x00\x15", 5);

  int padding_length = TLS_REQUEST_LENGTH - 2 - pos;
  assert (padding_length >= 0);
  add_length (result, &pos, padding_length);
  memset (result + pos, 0, TLS_REQUEST_LENGTH - pos);
  return result;
}

static int update_domain_info (struct domain_info *info) {
  const char *domain = info->domain;

  // Try parsing as a literal IP address first
  struct in_addr addr4;
  struct in6_addr addr6;
  int af = 0;
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

  fd_set read_fd;
  fd_set write_fd;
  fd_set except_fd;
  FD_ZERO(&read_fd);
  FD_ZERO(&write_fd);
  FD_ZERO(&except_fd);

#define TRIES 20
  int sockets[TRIES];
  int i;
  for (i = 0; i < TRIES; i++) {
    sockets[i] = socket (af, SOCK_STREAM, IPPROTO_TCP);
    if (sockets[i] < 0) {
      kprintf ("Failed to open socket for %s: %s\n", domain, strerror (errno));
      return 0;
    }
    if (fcntl (sockets[i], F_SETFL, O_NONBLOCK) == -1) {
      kprintf ("Failed to make socket non-blocking: %s\n", strerror (errno));
      return 0;
    }

    int e_connect;
    if (af == AF_INET) {
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

    if (e_connect == -1 && errno != EINPROGRESS) {
      kprintf ("Failed to connect to %s: %s\n", domain, strerror (errno));
      return 0;
    }
  }

  unsigned char *requests[TRIES];
  for (i = 0; i < TRIES; i++) {
    requests[i] = create_request (domain);
  }
  unsigned char *responses[TRIES] = {};
  int response_len[TRIES] = {};
  int is_encrypted_application_data_length_read[TRIES] = {};

  int finished_count = 0;
  int is_written[TRIES] = {};
  int is_finished[TRIES] = {};
  int read_pos[TRIES] = {};
  double finish_time = get_utime_monotonic() + 5.0;
  int is_reversed_extension_order_min = 0;
  int is_reversed_extension_order_max = 0;
  int all_record_counts[TRIES] = {};
  int all_total_encrypted[TRIES] = {};
  int have_error = 0;
  while (get_utime_monotonic() < finish_time && finished_count < TRIES && !have_error) {
    struct timeval timeout_data;
    timeout_data.tv_sec = (int)(finish_time - precise_now + 1);
    timeout_data.tv_usec = 0;

    int max_fd = 0;
    for (i = 0; i < TRIES; i++) {
      if (is_finished[i]) {
        continue;
      }
      if (is_written[i]) {
        FD_SET(sockets[i], &read_fd);
        FD_CLR(sockets[i], &write_fd);
      } else {
        FD_CLR(sockets[i], &read_fd);
        FD_SET(sockets[i], &write_fd);
      }
      FD_SET(sockets[i], &except_fd);
      if (sockets[i] > max_fd) {
        max_fd = sockets[i];
      }
    }

    select (max_fd + 1, &read_fd, &write_fd, &except_fd, &timeout_data);

    for (i = 0; i < TRIES; i++) {
      if (is_finished[i]) {
        continue;
      }
      if (FD_ISSET(sockets[i], &read_fd)) {
        assert (is_written[i]);

        unsigned char header[5];
        if (responses[i] == NULL) {
          ssize_t read_res = read (sockets[i], header, sizeof (header));
          if (read_res != sizeof (header)) {
            kprintf ("Failed to read response header for checking domain %s: %s\n", domain, read_res == -1 ? strerror (errno) : "Read less bytes than expected");
            have_error = 1;
            break;
          }
          if (memcmp (header, "\x16\x03\x03", 3) != 0) {
            kprintf ("Non-TLS response, or TLS <= 1.1, or unsuccessful request to %s: receive \\x%02x\\x%02x\\x%02x\\x%02x\\x%02x...\n",
                     domain, header[0], header[1], header[2], header[3], header[4]);
            have_error = 1;
            break;
          }
          response_len[i] = 5 + header[3] * 256 + header[4] + 6 + 5;
          responses[i] = malloc (response_len[i]);
          memcpy (responses[i], header, sizeof (header));
          read_pos[i] = 5;
        } else {
          ssize_t read_res = read (sockets[i], responses[i] + read_pos[i], response_len[i] - read_pos[i]);
          if (read_res == -1) {
            kprintf ("Failed to read response from %s: %s\n", domain, strerror (errno));
            have_error = 1;
            break;
          }
          read_pos[i] += read_res;

          if (read_pos[i] == response_len[i]) {
            if (!is_encrypted_application_data_length_read[i]) {
              if (memcmp (responses[i] + response_len[i] - 11, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
                kprintf ("Not found TLS 1.3 support on domain %s\n", domain);
                have_error = 1;
                break;
              }

              is_encrypted_application_data_length_read[i] = 1;
              int encrypted_application_data_length = responses[i][response_len[i] - 2] * 256 + responses[i][response_len[i] - 1];
              response_len[i] += encrypted_application_data_length;
              unsigned char *new_buffer = realloc (responses[i], response_len[i]);
              assert (new_buffer != NULL);
              responses[i] = new_buffer;
              continue;
            }

            // Capture additional encrypted records from kernel buffer
            for (;;) {
              unsigned char extra_buf[16384];
              ssize_t extra = read (sockets[i], extra_buf, sizeof (extra_buf));
              if (extra <= 0) {
                break;
              }
              unsigned char *new_buf = realloc (responses[i], response_len[i] + extra);
              assert (new_buf != NULL);
              responses[i] = new_buf;
              memcpy (responses[i] + response_len[i], extra_buf, extra);
              response_len[i] += extra;
              read_pos[i] = response_len[i];
            }

            int is_reversed_extension_order = -1;
            int probe_record_sizes[MAX_ENCRYPTED_RECORDS];
            int probe_record_count = 0;
            if (tls_check_server_hello (responses[i], response_len[i], requests[i] + 44, &is_reversed_extension_order, probe_record_sizes, &probe_record_count)) {
              assert (is_reversed_extension_order != -1);
              assert (probe_record_count > 0);
              // Sum all record sizes into total encrypted size for this probe
              int total_encrypted = 0;
              int j;
              for (j = 0; j < probe_record_count && j < MAX_ENCRYPTED_RECORDS; j++) {
                total_encrypted += probe_record_sizes[j];
              }
              all_record_counts[finished_count] = probe_record_count;
              all_total_encrypted[finished_count] = total_encrypted;
              if (finished_count == 0) {
                is_reversed_extension_order_min = is_reversed_extension_order;
                is_reversed_extension_order_max = is_reversed_extension_order;
              } else {
                if (is_reversed_extension_order < is_reversed_extension_order_min) {
                  is_reversed_extension_order_min = is_reversed_extension_order;
                }
                if (is_reversed_extension_order > is_reversed_extension_order_max) {
                  is_reversed_extension_order_max = is_reversed_extension_order;
                }
              }

              FD_CLR(sockets[i], &write_fd);
              FD_CLR(sockets[i], &read_fd);
              FD_CLR(sockets[i], &except_fd);
              is_finished[i] = 1;
              finished_count++;
            } else {
              have_error = 1;
              break;
            }
          }
        }
      }
      if (FD_ISSET(sockets[i], &write_fd)) {
        assert (!is_written[i]);
        ssize_t write_res = write (sockets[i], requests[i], TLS_REQUEST_LENGTH);
        if (write_res != TLS_REQUEST_LENGTH) {
          kprintf ("Failed to write request for checking domain %s: %s", domain, write_res == -1 ? strerror (errno) : "Written less bytes than expected");
          have_error = 1;
          break;
        }
        is_written[i] = 1;
      }
      if (FD_ISSET(sockets[i], &except_fd)) {
        kprintf ("Failed to check domain %s: %s\n", domain, strerror (errno));
        have_error = 1;
        break;
      }
    }
  }

  for (i = 0; i < TRIES; i++) {
    close (sockets[i]);
    free (requests[i]);
    free (responses[i]);
  }

  if (finished_count != TRIES) {
    if (!have_error) {
      kprintf ("Failed to check domain %s in 5 seconds\n", domain);
    }
    return 0;
  }

  if (is_reversed_extension_order_min != is_reversed_extension_order_max) {
    kprintf ("Upstream server %s uses non-deterministic extension order\n", domain);
  }

  info->is_reversed_extension_order = (char)is_reversed_extension_order_min;

  // Aggregate total encrypted size across all probes
  int encrypted_size_min = all_total_encrypted[0];
  int encrypted_size_max = all_total_encrypted[0];
  int encrypted_size_sum = all_total_encrypted[0];
  for (i = 1; i < TRIES; i++) {
    if (all_total_encrypted[i] < encrypted_size_min) {
      encrypted_size_min = all_total_encrypted[i];
    }
    if (all_total_encrypted[i] > encrypted_size_max) {
      encrypted_size_max = all_total_encrypted[i];
    }
    encrypted_size_sum += all_total_encrypted[i];
  }

  if (encrypted_size_min == encrypted_size_max) {
    info->server_hello_encrypted_size = encrypted_size_min;
    info->use_random_encrypted_size = 0;
  } else if (encrypted_size_max - encrypted_size_min <= 3) {
    info->server_hello_encrypted_size = encrypted_size_max - 1;
    info->use_random_encrypted_size = 1;
  } else {
    kprintf ("Unrecognized encrypted application data length pattern with min = %d, max = %d, mean = %.3lf\n",
             encrypted_size_min, encrypted_size_max, encrypted_size_sum * 1.0 / TRIES);
    info->server_hello_encrypted_size = (int)(encrypted_size_sum * 1.0 / TRIES + 0.5);
    info->use_random_encrypted_size = 1;
  }

  vkprintf (0, "Successfully checked domain %s in %.3lf seconds: is_reversed_extension_order = %d, "
            "server_hello_encrypted_size = %d (from %d record(s)), use_random_encrypted_size = %d\n",
            domain, get_utime_monotonic() - (finish_time - 5.0), info->is_reversed_extension_order,
            info->server_hello_encrypted_size, all_record_counts[0], info->use_random_encrypted_size);
  return 1;
#undef TRIES
}

#undef TLS_REQUEST_LENGTH

static const struct domain_info *get_sni_domain_info (const unsigned char *request, int len) {
  char domain_buf[256];
  int domain_length = tls_parse_sni (request, len, domain_buf, sizeof (domain_buf));
  if (domain_length < 0) {
    return NULL;
  }
  const struct domain_info *info = get_domain_info (domain_buf, domain_length);
  if (info == NULL) {
    vkprintf (1, "Receive request for unknown domain %.*s\n", domain_length, domain_buf);
  }
  return info;
}

void tcp_rpc_add_proxy_domain (const char *domain) {
  assert (domain != NULL);

  struct domain_info *info = calloc (1, sizeof (struct domain_info));
  assert (info != NULL);
  info->port = 443;

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

  struct domain_info **bucket = get_domain_info_bucket (info->domain, strlen (info->domain));
  info->next = *bucket;
  *bucket = info;

  if (!allow_only_tls) {
    allow_only_tls = 1;
    default_domain_info = info;
  }
}

void tcp_rpc_init_proxy_domains() {
  int i;
  for (i = 0; i < DOMAIN_HASH_MOD; i++) {
    struct domain_info *info = domains[i];
    while (info != NULL) {
      if (!update_domain_info (info)) {
        kprintf ("Failed to update response data about %s, so default response settings wiil be used\n", info->domain);
        // keep target addresses as is
        info->is_reversed_extension_order = 0;
        info->use_random_encrypted_size = 1;
        info->server_hello_encrypted_size = 2500 + rand() % 1120;
      }

      info = info->next;
    }
  }
}

// --- Replay cache: shared across workers via mmap, per-process fallback otherwise ---
//
// At 2-day TTL (MAX_CLIENT_RANDOM_CACHE_TIME), pool capacity determines the
// max sustained TLS handshake rate:  rate = pool_size / 172800.
// Default 1M slots ≈ 5.8 handshakes/s; 4M ≈ 23/s.  Use --replay-cache-size
// to raise for high-traffic deployments.

#define RANDOM_HASH_BITS 14
#define RANDOM_HASH_SIZE (1 << RANDOM_HASH_BITS)
#define REPLAY_POOL_DEFAULT (1 << 20)  // 1M entries, ~28 MB
#define REPLAY_NIL (-1)
#define MAX_CLIENT_RANDOM_CACHE_TIME (2 * 86400)

struct replay_entry {
  unsigned char random[16];
  int time;
  int next_by_time;
  int next_by_hash;
};

struct replay_cache {
  volatile int lock;
  int first;
  int last;
  int free_head;
  int pool_size;
  int buckets[RANDOM_HASH_SIZE];
  struct replay_entry pool[];  // flexible array, pool_size entries
};

static struct replay_cache *replay_cache;
static int replay_pool_size = REPLAY_POOL_DEFAULT;

static size_t replay_cache_bytes (int pool_size) {
  return sizeof (struct replay_cache) + (size_t)pool_size * sizeof (struct replay_entry);
}

static inline void replay_lock (void) {
  while (__sync_lock_test_and_set (&replay_cache->lock, 1)) {
    while (replay_cache->lock) {
      #if defined(__x86_64__) || defined(__i386__)
      __asm__ __volatile__ ("pause" ::: "memory");
      #elif defined(__aarch64__)
      __asm__ __volatile__ ("yield" ::: "memory");
      #endif
    }
  }
}

static inline void replay_unlock (void) {
  __sync_lock_release (&replay_cache->lock);
}

static void replay_cache_setup (int pool_size) {
  replay_cache->lock = 0;
  replay_cache->pool_size = pool_size;
  replay_cache->first = REPLAY_NIL;
  replay_cache->last = REPLAY_NIL;
  for (int i = 0; i < RANDOM_HASH_SIZE; i++) {
    replay_cache->buckets[i] = REPLAY_NIL;
  }
  for (int i = 0; i < pool_size - 1; i++) {
    replay_cache->pool[i].next_by_time = i + 1;
  }
  replay_cache->pool[pool_size - 1].next_by_time = REPLAY_NIL;
  replay_cache->free_head = 0;
  vkprintf (0, "replay cache: %d slots, %.1f MB\n",
    pool_size, (double)replay_cache_bytes (pool_size) / (1 << 20));
}

void replay_cache_set_size (int size) {
  replay_pool_size = size;
}

void replay_cache_init_shared (void) {
  size_t sz = replay_cache_bytes (replay_pool_size);
  replay_cache = mmap (NULL, sz,
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  assert (replay_cache != MAP_FAILED);
  replay_cache_setup (replay_pool_size);
}

void replay_cache_init_local (void) {
  size_t sz = replay_cache_bytes (replay_pool_size);
  replay_cache = malloc (sz);
  assert (replay_cache != NULL);
  replay_cache_setup (replay_pool_size);
}

static int get_bucket_id (unsigned char random[16]) {
  int i = RANDOM_HASH_BITS;
  int pos = 0;
  int id = 0;
  while (i > 0) {
    int bits = i < 8 ? i : 8;
    id = (id << bits) | (random[pos++] & ((1 << bits) - 1));
    i -= bits;
  }
  return id;
}

static void replay_unlink_from_hash (int idx) {
  struct replay_entry *e = &replay_cache->pool[idx];
  int bid = get_bucket_id (e->random);
  int *cur = &replay_cache->buckets[bid];
  while (*cur != idx) {
    assert (*cur != REPLAY_NIL);
    cur = &replay_cache->pool[*cur].next_by_hash;
  }
  *cur = e->next_by_hash;
}

static void replay_evict_oldest (void) {
  int idx = replay_cache->first;
  if (idx == REPLAY_NIL) { return; }
  struct replay_entry *e = &replay_cache->pool[idx];
  replay_cache->first = e->next_by_time;
  if (replay_cache->first == REPLAY_NIL) {
    replay_cache->last = REPLAY_NIL;
  }
  replay_unlink_from_hash (idx);
  e->next_by_time = replay_cache->free_head;
  replay_cache->free_head = idx;
}

static void delete_old_client_randoms (void) {
  while (replay_cache->first != REPLAY_NIL && replay_cache->first != replay_cache->last) {
    struct replay_entry *e = &replay_cache->pool[replay_cache->first];
    if (e->time > now - MAX_CLIENT_RANDOM_CACHE_TIME) {
      return;
    }
    replay_evict_oldest ();
  }
}

static int have_client_random (unsigned char random[16]) {
  int bid = get_bucket_id (random);
  int cur = replay_cache->buckets[bid];
  while (cur != REPLAY_NIL) {
    if (memcmp (random, replay_cache->pool[cur].random, 16) == 0) {
      return 1;
    }
    cur = replay_cache->pool[cur].next_by_hash;
  }
  return 0;
}

static void add_client_random (unsigned char random[16]) {
  if (replay_cache->free_head == REPLAY_NIL) {
    replay_evict_oldest ();
  }
  assert (replay_cache->free_head != REPLAY_NIL);

  int idx = replay_cache->free_head;
  struct replay_entry *e = &replay_cache->pool[idx];
  replay_cache->free_head = e->next_by_time;

  memcpy (e->random, random, 16);
  e->time = now;
  e->next_by_time = REPLAY_NIL;

  if (replay_cache->last == REPLAY_NIL) {
    replay_cache->first = replay_cache->last = idx;
  } else {
    replay_cache->pool[replay_cache->last].next_by_time = idx;
    replay_cache->last = idx;
  }

  int bid = get_bucket_id (random);
  e->next_by_hash = replay_cache->buckets[bid];
  replay_cache->buckets[bid] = idx;
}

static int get_oldest_time (void) {
  if (replay_cache->first == REPLAY_NIL) { return 0; }
  return replay_cache->pool[replay_cache->first].time;
}

static int is_allowed_timestamp (int timestamp, int oldest_cache_time) {
  // do not allow timestamps in the future;
  // after time synchronization client should always have time in the past
  if (timestamp > now + 3) {
    vkprintf (1, "Disallow request with timestamp %d from the future, now is %d\n", timestamp, now);
    return 0;
  }

  // oldest_cache_time is the receive-time of the oldest cached client_random.
  // If the new timestamp is beyond (oldest_cache_time + 3), the request could only have
  // been created after that entry, so its client_random must still be in the cache —
  // any duplicate would have been caught by have_client_random() already.
  if (oldest_cache_time && timestamp > oldest_cache_time + 3) {
    vkprintf (1, "Allow new request with timestamp %d\n", timestamp);
    return 1;
  }

  // Allow all requests with a recent timestamp regardless of cache coverage.
  // The window must be large enough to tolerate client clock drift after NTP sync.
  const int MAX_ALLOWED_TIMESTAMP_ERROR = 2 * 60;
  if (timestamp > now - MAX_ALLOWED_TIMESTAMP_ERROR) {
    vkprintf (1, "Allow recent request with timestamp %d without full check for client random duplication\n", timestamp);
    return 1;
  }

  // Too old to verify against the cache — reject to force client to resync time.
  vkprintf (1, "Disallow too old request with timestamp %d\n", timestamp);
  return 0;
}

static int proxy_connection (connection_job_t C, const struct domain_info *info) {
  struct connection_info *c = CONN_INFO(C);

  /* No longer an MTProxy connection — clear secret tracking to prevent
     spurious decrement in mtproto_ext_rpc_close on failure paths. */
  TCP_RPC_DATA(C)->extra_int2 = 0;

  assert (check_conn_functions (&ct_proxy_pass, 0) >= 0);
  assert (check_conn_functions (&ct_proxy_pass_unix, 0) >= 0);

  int use_unix = (unix_target_path != NULL);

  if (!use_unix) {
    const char zero[16] = {};
    if (info->target.s_addr == 0 && !memcmp (info->target_ipv6, zero, 16)) {
      vkprintf (0, "failed to proxy request to %s\n", info->domain);
      fail_connection (C, -17);
      return 0;
    }
  }

  int port = c->our_port == 80 ? 80 : info->port;

  int cfd = -1;
  if (use_unix) {
    cfd = client_socket_unix (unix_target_path);
  } else if (info->target.s_addr) {
    cfd = client_socket (info->target.s_addr, port, 0);
  } else {
    cfd = client_socket_ipv6 (info->target_ipv6, port, SM_IPV6);
  }

  if (cfd < 0) {
    if (use_unix) {
      kprintf ("failed to create proxy pass connection to unix:%s: %d (%m)\n", unix_target_path, errno);
    } else {
      kprintf ("failed to create proxy pass connection: %d (%m)\n", errno);
    }
    fail_connection (C, -27);
    return 0;
  }

  c->type->crypto_free (C);
  job_incref (C);

  job_t EJ;
  if (use_unix) {
    EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass_unix, C, 0, NULL, 0);
  } else {
    EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C, ntohl (*(int *)&info->target.s_addr), (void *)info->target_ipv6, port);
  }

  if (!EJ) {
    kprintf ("failed to create proxy pass connection (2)");
    job_decref_f (C);
    fail_connection (C, -37);
    return 0;
  }

  c->type = &ct_proxy_pass;
  c->extra = job_incref (EJ);

  /* For unix target: write PROXY protocol header directly to the outbound connection's
     output buffer BEFORE any relay data. This ensures correct ordering because
     unix socket connect() is instant (no EINPROGRESS), so we can write immediately. */
  if (use_unix && proxy_protocol_enabled == 1) {
    /* PROXY protocol v1 (text) */
    struct connection_info *ej = CONN_INFO(EJ);
    char header[256];
    int len;

    if (c->flags & C_IPV6) {
      char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, c->remote_ipv6, src_buf, sizeof (src_buf));
      inet_ntop (AF_INET6, c->our_ipv6, dst_buf, sizeof (dst_buf));
      len = snprintf (header, sizeof (header), "PROXY TCP6 %s %s %u %u\r\n",
                      src_buf, dst_buf, c->remote_port, c->our_port);
    } else {
      struct in_addr src_addr, dst_addr;
      char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
      src_addr.s_addr = htonl (c->remote_ip);
      dst_addr.s_addr = htonl (c->our_ip);
      inet_ntop (AF_INET, &src_addr, src_buf, sizeof (src_buf));
      inet_ntop (AF_INET, &dst_addr, dst_buf, sizeof (dst_buf));
      len = snprintf (header, sizeof (header), "PROXY TCP4 %s %s %u %u\r\n",
                      src_buf, dst_buf, c->remote_port, c->our_port);
    }

    if (len > 0 && len < (int)sizeof (header)) {
      rwm_push_data (&ej->out, header, len);
      vkprintf (1, "PROXY protocol v1: %.*s\n", len - 2, header);
    }
  } else if (use_unix && proxy_protocol_enabled == 2) {
    /* PROXY protocol v2 (binary) */
    struct connection_info *ej = CONN_INFO(EJ);
    static const unsigned char v2_sig[12] = {
      0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    unsigned char header[52]; /* max: 16 hdr + 36 ipv6 addrs */
    int len;

    memcpy (header, v2_sig, 12);
    header[12] = 0x21; /* version 2, command PROXY */

    if (c->flags & C_IPV6) {
      header[13] = 0x21; /* AF_INET6, STREAM */
      header[14] = 0;    /* addr len high byte */
      header[15] = 36;   /* addr len: 2*16 + 2*2 */
      memcpy (header + 16, c->remote_ipv6, 16);
      memcpy (header + 32, c->our_ipv6, 16);
      *(unsigned short *)(header + 48) = htons ((unsigned short)c->remote_port);
      *(unsigned short *)(header + 50) = htons ((unsigned short)c->our_port);
      len = 52;
    } else {
      header[13] = 0x11; /* AF_INET, STREAM */
      header[14] = 0;    /* addr len high byte */
      header[15] = 12;   /* addr len: 2*4 + 2*2 */
      *(unsigned *)(header + 16) = htonl (c->remote_ip);
      *(unsigned *)(header + 20) = htonl (c->our_ip);
      *(unsigned short *)(header + 24) = htons ((unsigned short)c->remote_port);
      *(unsigned short *)(header + 26) = htons ((unsigned short)c->our_port);
      len = 28;
    }

    rwm_push_data (&ej->out, header, len);
    vkprintf (1, "PROXY protocol v2: %d bytes (%s)\n", len, (c->flags & C_IPV6) ? "IPv6" : "IPv4");
  }

  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return c->type->parse_execute (C);
}

int tcp_rpcs_ext_alarm (connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    return proxy_connection (C, default_domain_info);
  } else {
    return 0;
  }
}

/* DRS alarm handler: handles both handshake timeout and inter-record delay resume.
   Both JS_RUN and JS_ALARM run on the NET-CPU thread, so calling read_write is safe. */
static int tcp_rpcs_ext_drs_alarm (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);

  /* Direct client retry: DC connection not yet established */
  if (c->type == &ct_direct_client_drs && !c->extra && D->extra_int > 0) {
    direct_retry_dc_connection (C);
    return 0;
  }

  /* Handshake timeout (pre-handshake state) */
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    return proxy_connection (C, default_domain_info);
  }

  /* DRS delay resume: timer fired, process next record */
  if (c->flags & C_IS_TLS) {
    struct drs_state *drs = DRS_STATE (C);
    if (drs->delay_pending) {
      drs->delay_pending = 0;
      c->type->read_write (C);
    }
  }
  return 0;
}

int tcp_rpcs_ext_init_accepted (connection_job_t C) {
  job_timer_insert (C, precise_now + 10);
  return tcp_rpcs_init_accepted_nohs (C);
}

int tcp_rpcs_compact_parse_execute (connection_job_t C) {
#define RETURN_TLS_ERROR(info) \
  return proxy_connection (C, info);  

  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->crypto_flags & RPCF_COMPACT_OFF) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    return tcp_rpcs_parse_execute (C);
  }

  struct connection_info *c = CONN_INFO (C);
  int len;

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);

  while (1) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    if (c->flags & C_ERROR) {
      return NEED_MORE_BYTES;
    }
    if (c->flags & C_STOPPARSE) {
      return NEED_MORE_BYTES;
    }
    len = c->in.total_bytes; 
    if (len <= 0) {
      return NEED_MORE_BYTES;
    }

    int min_len = (D->flags & RPC_F_MEDIUM) ? 4 : 1;
    if (len < min_len + 8) {
      return min_len + 8 - len;
    }

    int packet_len = 0;
    assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

    if (D->in_packet_num == -3) {
      vkprintf (1, "trying to determine type of connection from %s:%d\n", show_remote_ip (C), c->remote_port);
#if __ALLOW_UNOBFS__
      if ((packet_len & 0xff) == 0xef) {
        D->flags |= RPC_F_COMPACT;
        assert (rwm_skip_data (&c->in, 1) == 1);
        D->in_packet_num = 0;
        vkprintf (1, "Short type\n");
        continue;
      } 
      if (packet_len == 0xeeeeeeee) {
        D->flags |= RPC_F_MEDIUM;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
      if (packet_len == 0xdddddddd) {
        D->flags |= RPC_F_MEDIUM | RPC_F_PAD;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
        
      // http
      if ((packet_len == *(int *)"HEAD" || packet_len == *(int *)"POST" || packet_len == *(int *)"GET " || packet_len == *(int *)"OPTI") && TCP_RPCS_FUNC(C)->http_fallback_type) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "HTTP type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      // fake tls
      if (c->flags & C_IS_TLS) {
        if (len < 11) {
          return 11 - len;
        }

        vkprintf (1, "Established TLS connection from %s:%d\n", show_remote_ip (C), c->remote_port);
        unsigned char header[11];
        assert (rwm_fetch_lookup (&c->in, header, 11) == 11);
        if (memcmp (header, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
          vkprintf (1, "error while parsing packet: bad client dummy ChangeCipherSpec\n");
          fail_connection (C, -1);
          return 0;
        }

        min_len = 11 + 256 * header[9] + header[10];
        if (len < min_len) {
          vkprintf (2, "Need %d bytes, but have only %d\n", min_len, len);
          return min_len - len;
        }

        assert (rwm_skip_data (&c->in, 11) == 11);
        len -= 11;
        c->left_tls_packet_length = 256 * header[9] + header[10]; // store left length of current TLS packet in extra_int3
        vkprintf (2, "Receive first TLS packet of length %d\n", c->left_tls_packet_length);

        if (c->left_tls_packet_length < 64) {
          vkprintf (1, "error while parsing packet: too short first TLS packet: %d\n", c->left_tls_packet_length);
          fail_connection (C, -1);
          return 0;
        }
        // now len >= c->left_tls_packet_length >= 64

        assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

        c->left_tls_packet_length -= 64; // skip header length
      } else if ((packet_len & 0xFFFFFF) == 0x010316 && (packet_len >> 24) >= 2 && ext_secret_cnt > 0 && allow_only_tls) {
        unsigned char header[5];
        assert (rwm_fetch_lookup (&c->in, header, 5) == 5);
        min_len = 5 + 256 * header[3] + header[4];
        if (len < min_len) {
          return min_len - len;
        }

        int read_len = len <= 4096 ? len : 4096;
        unsigned char client_hello[read_len + 1]; // VLA
        assert (rwm_fetch_lookup (&c->in, client_hello, read_len) == read_len);

        const struct domain_info *info = get_sni_domain_info (client_hello, read_len);
        if (info == NULL) {
          RETURN_TLS_ERROR(default_domain_info);
        }

        vkprintf (1, "TLS type with domain %s from %s:%d\n", info->domain, show_remote_ip (C), c->remote_port);

        if (c->our_port == 80) {
          vkprintf (1, "Receive TLS request on port %d, proxying to %s\n", c->our_port, info->domain);
          RETURN_TLS_ERROR(info);
        }

        if (len > min_len) {
          vkprintf (1, "Too much data in ClientHello, receive %d instead of %d\n", len, min_len);
          RETURN_TLS_ERROR(info);
        }
        if (len != read_len) {
          vkprintf (1, "Too big ClientHello: receive %d bytes\n", len);
          RETURN_TLS_ERROR(info);
        }

        unsigned char client_random[32];
        memcpy (client_random, client_hello + 11, 32);
        memset (client_hello + 11, '\0', 32);

        replay_lock ();
        if (have_client_random (client_random)) {
          replay_unlock ();
          vkprintf (1, "Receive again request with the same client random\n");
          RETURN_TLS_ERROR(info);
        }
        add_client_random (client_random);
        delete_old_client_randoms ();
        int oldest_cache_time = get_oldest_time ();
        replay_unlock ();

        unsigned char expected_random[32];
        int secret_id;
        for (secret_id = 0; secret_id < ext_secret_cnt; secret_id++) {
          sha256_hmac (ext_secret[secret_id], 16, client_hello, len, expected_random);
          if (CRYPTO_memcmp (expected_random, client_random, 28) == 0) {
            break;
          }
        }
        if (secret_id == ext_secret_cnt) {
          vkprintf (1, "Receive request with unmatched client random\n");
          RETURN_TLS_ERROR(info);
        }
        int timestamp = *(int *)(expected_random + 28) ^ *(int *)(client_random + 28);
        if (!is_allowed_timestamp (timestamp, oldest_cache_time)) {
          RETURN_TLS_ERROR(info);
        }

        D->extra_int2 = secret_id + 1;
        vkprintf (1, "TLS handshake matched secret [%s] from %s:%d\n", ext_secret_label[secret_id], show_remote_ip (C), c->remote_port);

        if (secret_over_limit (secret_id)) {
          per_secret_connections_rejected[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] at limit %d from %s:%d\n", ext_secret_label[secret_id], ext_secret_limit[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        unsigned char cipher_suite_id;
        if (tls_parse_client_hello_ciphers (client_hello, read_len, &cipher_suite_id) < 0) {
          vkprintf (1, "Can't find supported cipher suite\n");
          RETURN_TLS_ERROR(info);
        }

        assert (rwm_skip_data (&c->in, len) == len);
        c->flags |= C_IS_TLS;
        c->left_tls_packet_length = -1;

        int encrypted_size = get_domain_server_hello_encrypted_size (info);
        int response_size = 127 + 6 + 5 + encrypted_size;
        unsigned char *buffer = malloc (32 + response_size);
        assert (buffer != NULL);
        memcpy (buffer, client_random, 32);
        unsigned char *response_buffer = buffer + 32;
        memcpy (response_buffer, "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03", 11);
        memset (response_buffer + 11, '\0', 32);
        response_buffer[43] = '\x20';
        memcpy (response_buffer + 44, client_hello + 44, 32);
        memcpy (response_buffer + 76, "\x13\x01\x00\x00\x2e", 5);
        response_buffer[77] = cipher_suite_id;

        int pos = 81;
        int tls_server_extensions[3] = {0x33, 0x2b, -1};
        if (info->is_reversed_extension_order) {
          int t = tls_server_extensions[0];
          tls_server_extensions[0] = tls_server_extensions[1];
          tls_server_extensions[1] = t;
        }
        int i;
        for (i = 0; tls_server_extensions[i] != -1; i++) {
          if (tls_server_extensions[i] == 0x33) {
            assert (pos + 40 <= response_size);
            memcpy (response_buffer + pos, "\x00\x33\x00\x24\x00\x1d\x00\x20", 8);
            generate_public_key (response_buffer + pos + 8);
            pos += 40;
          } else if (tls_server_extensions[i] == 0x2b) {
            assert (pos + 5 <= response_size);
            memcpy (response_buffer + pos, "\x00\x2b\x00\x02\x03\x04", 6);
            pos += 6;
          } else {
            assert (0);
          }
        }
        assert (pos == 127);
        memcpy (response_buffer + 127, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9);
        pos += 9;
        response_buffer[pos++] = encrypted_size / 256;
        response_buffer[pos++] = encrypted_size % 256;
        assert (pos + encrypted_size == response_size);
        RAND_bytes (response_buffer + pos, encrypted_size);

        unsigned char server_random[32];
        sha256_hmac (ext_secret[secret_id], 16, buffer, 32 + response_size, server_random);
        memcpy (response_buffer + 11, server_random, 32);

        struct raw_message *m = calloc (sizeof (struct raw_message), 1);
        rwm_create (m, response_buffer, response_size);
        mpq_push_w (c->out_queue, m, 0);
        job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);

        free (buffer);
        return 11; // waiting for dummy ChangeCipherSpec and first packet
      }

      if (allow_only_tls && !(c->flags & C_IS_TLS)) {
        vkprintf (1, "Expected TLS-transport\n");
        RETURN_TLS_ERROR(default_domain_info);
      }

#if __ALLOW_UNOBFS__
      int tmp[2];
      assert (rwm_fetch_lookup (&c->in, &tmp, 8) == 8);
      if (!tmp[1] && !(c->flags & C_IS_TLS)) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "Long type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      if (len < 64) {
        assert (!(c->flags & C_IS_TLS));
#if __ALLOW_UNOBFS__
        vkprintf (1, "random 64-byte header: first 0x%08x 0x%08x, need %d more bytes to distinguish\n", tmp[0], tmp[1], 64 - len);
#else
        vkprintf (1, "\"random\" 64-byte header: have %d bytes, need %d more bytes to distinguish\n", len, 64 - len);
#endif
        return 64 - len;
      }

      unsigned char random_header[64];
      unsigned char k[48];
      assert (rwm_fetch_lookup (&c->in, random_header, 64) == 64);
        
      unsigned char random_header_sav[64];
      memcpy (random_header_sav, random_header, 64);
      
      struct aes_key_data key_data;
      
      int ok = 0;
      int secret_id;
      for (secret_id = 0; secret_id < 1 || secret_id < ext_secret_cnt; secret_id++) {
        if (ext_secret_cnt > 0) {
          memcpy (k, random_header + 8, 32);
          memcpy (k + 32, ext_secret[secret_id], 16);
          sha256 (k, 48, key_data.read_key);
        } else {
          memcpy (key_data.read_key, random_header + 8, 32);
        }
        memcpy (key_data.read_iv, random_header + 40, 16);

        int i;
        for (i = 0; i < 32; i++) {
          key_data.write_key[i] = random_header[55 - i];
        }
        for (i = 0; i < 16; i++) {
          key_data.write_iv[i] = random_header[23 - i];
        }

        if (ext_secret_cnt > 0) {
          memcpy (k, key_data.write_key, 32);
          sha256 (k, 48, key_data.write_key);
        }

        aes_crypto_ctr128_init (C, &key_data, sizeof (key_data));
        assert (c->crypto);
        struct aes_crypto *T = c->crypto;

        evp_crypt (T->read_aeskey, random_header, random_header, 64);
        unsigned tag = *(unsigned *)(random_header + 56);

        if (tag == 0xdddddddd || ((tag == 0xeeeeeeee || tag == 0xefefefef) && !ext_rand_pad_only)) {
          if (tag != 0xdddddddd && allow_only_tls) {
            vkprintf (1, "Expected random padding mode\n");
            RETURN_TLS_ERROR(default_domain_info);
          }
          assert (rwm_skip_data (&c->in, 64) == 64);
          rwm_union (&c->in_u, &c->in);
          rwm_init (&c->in, 0);
          // T->read_pos = 64;
          D->in_packet_num = 0;
          switch (tag) {
            case 0xeeeeeeee:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2;
              break;
            case 0xdddddddd:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2 | RPC_F_PAD;
              break;
            case 0xefefefef:
              D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE2;
              break;
          }
          assert (c->type->crypto_decrypt_input (C) >= 0);

          int target = *(short *)(random_header + 60);
          D->extra_int4 = target;
          D->extra_int2 = secret_id + 1;
          D->extra_int3 = (int)tag;  /* client transport tag for direct mode */
          vkprintf (1, "tcp opportunistic encryption mode detected, tag = %08x, target=%d, secret [%s]\n", tag, target, ext_secret_label[secret_id]);
          ok = 1;
          break;
        } else {
          aes_crypto_free (C);
          memcpy (random_header, random_header_sav, 64);
        }
      }

      if (ok) {
        /* Check per-secret connection limit (non-TLS; TLS checked during handshake) */
        if (!(c->flags & C_IS_TLS)) {
          int _sid = D->extra_int2;
          if (_sid > 0 && _sid <= 16 && secret_over_limit (_sid - 1)) {
            per_secret_connections_rejected[_sid - 1]++;
            vkprintf (1, "connection rejected: secret [%s] at limit %d from %s:%d\n", ext_secret_label[_sid - 1], ext_secret_limit[_sid - 1], show_remote_ip (C), c->remote_port);
            fail_connection (C, -1);
            return 0;
          }
        }

        /* Per-secret connection counter: increment here for all modes.
           Decrement: mtproto_ext_rpc_close (non-direct / direct failure)
           or tcp_direct_close (direct success). */
        {
          int _sid = D->extra_int2;
          if (_sid > 0 && _sid <= 16) {
            per_secret_connections[_sid - 1]++;
            per_secret_connections_created[_sid - 1]++;
          }
        }

        /* Activate DRS for TLS connections */
        if (c->flags & C_IS_TLS) {
          static int drs_types_checked;
          if (!drs_types_checked) {
            assert (check_conn_functions (&ct_tcp_rpc_ext_server_drs, 0) >= 0);
            assert (check_conn_functions (&ct_direct_client_drs, 0) >= 0);
            drs_types_checked = 1;
          }
          c->type = &ct_tcp_rpc_ext_server_drs;
          struct drs_state *drs = DRS_STATE (C);
          drs->record_index = 0;
          drs->total_records = 0;
          drs->last_record_time = precise_now;
          drs->delay_pending = 0;
          vkprintf (1, "DRS activated for TLS connection\n");
        }
        if (direct_mode) {
          return direct_connect_to_dc (C, D->extra_int4);
        }
        continue;
      }

      /* TLS connections have extra_int2 set from the TLS handshake phase.
         Clear it to prevent spurious decrement in mtproto_ext_rpc_close
         since we never incremented the per-secret counter. */
      if (c->flags & C_IS_TLS) {
        D->extra_int2 = 0;
      }
      if (ext_secret_cnt > 0) {
        vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
        return ((int)0xF0000000u);
      }

#if __ALLOW_UNOBFS__
      vkprintf (1, "short type with 64-byte header: first 0x%08x 0x%08x\n", tmp[0], tmp[1]);
      D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE1;
      D->in_packet_num = 0;

      assert (len >= 64);
      assert (rwm_skip_data (&c->in, 64) == 64);
      continue;
#else
      vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
      return ((int)0xF0000000u);
#endif
    }

    int packet_len_bytes = 4;
    if (D->flags & RPC_F_MEDIUM) {
      /* Transport error codes: DCs send a raw negative 4-byte int
         (e.g. -404, -429) in place of a normal packet length.
         Detect before QUICKACK masking destroys the sign. */
      if (packet_len < 0 && packet_len > -1000) {
        vkprintf (1, "transport error %d from %s:%d\n", packet_len, show_remote_ip (C), c->remote_port);
        transport_errors_received++;
        fail_connection (C, -1);
        return 0;
      }
      D->flags = (D->flags & ~RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
      packet_len &= ~RPC_F_QUICKACK;
      if (D->flags & RPC_F_QUICKACK) {
        quickack_packets_received++;
      }
    } else {
      /* compact mode */
      if (packet_len & 0x80) {
        D->flags |= RPC_F_QUICKACK;
        packet_len &= ~0x80;
        quickack_packets_received++;
      } else {
        D->flags &= ~RPC_F_QUICKACK;
      }
      if ((packet_len & 0xff) == 0x7f) {
        packet_len = ((unsigned) packet_len >> 8);
        if (packet_len < 0x7f) {
          vkprintf (1, "error while parsing compact packet: got length %d in overlong encoding\n", packet_len);
          fail_connection (C, -1);
          return 0;
        }
      } else {
        packet_len &= 0x7f;
        packet_len_bytes = 1;
      }
      packet_len <<= 2;
    }

    if (packet_len <= 0 || (packet_len & 0xc0000000) || (!(D->flags & RPC_F_PAD) && (packet_len & 3))) {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if ((packet_len > TCP_RPCS_FUNC(C)->max_packet_len && TCP_RPCS_FUNC(C)->max_packet_len > 0))  {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if (len < packet_len + packet_len_bytes) {
      return packet_len + packet_len_bytes - len;
    }

    assert (rwm_skip_data (&c->in, packet_len_bytes) == packet_len_bytes);
    
    struct raw_message msg;
    int packet_type;

    rwm_split_head (&msg, &c->in, packet_len);
    if (D->flags & RPC_F_PAD) {
      rwm_trunc (&msg, packet_len & -4);
    }

    assert (rwm_fetch_lookup (&msg, &packet_type, 4) == 4);

    if (D->in_packet_num < 0) {
      assert (D->in_packet_num == -3);
      D->in_packet_num = 0;
    }

    if (verbosity > 2) {
      kprintf ("received packet from connection %d (length %d, num %d, type %08x)\n", c->fd, packet_len, D->in_packet_num, packet_type);
      rwm_dump (&msg);
    }

    int res = -1;

    /* main case */
    c->last_response_time = precise_now;
    if (packet_type == RPC_PING) {
      res = tcp_rpcs_default_execute (C, packet_type, &msg);
    } else {
      res = TCP_RPCS_FUNC(C)->execute (C, packet_type, &msg);
    }
    if (res <= 0) {
      rwm_free (&msg);
    }

    D->in_packet_num++;
  }
  return NEED_MORE_BYTES;
#undef RETURN_TLS_ERROR
}

/*
 *
 *                END (EXTERNAL RPC SERVER)
 *
 */
