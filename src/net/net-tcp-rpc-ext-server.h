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

    Copyright 2016-2018 Telegram Messenger Inc                 
              2016-2018 Nikolai Durov
*/

#pragma once

#include <stdint.h>

#define __ALLOW_UNOBFS__ 0

#include "net/net-tcp-rpc-server.h"
#include "net/net-connections.h"

extern conn_type_t ct_tcp_rpc_ext_server;

int tcp_rpcs_compact_parse_execute (connection_job_t c);

#define EXT_SECRET_LABEL_MAX 32

void tcp_rpcs_set_ext_secret(unsigned char secret[16], const char *label,
                             int limit, long long quota, int max_ips, int64_t expires);
void tcp_rpcs_set_ext_rand_pad_only(int set);
const char *tcp_rpcs_get_ext_secret_label(int index);
int tcp_rpcs_get_ext_secret_limit(int index);
long long tcp_rpcs_get_ext_secret_quota(int index);
int tcp_rpcs_get_ext_secret_max_ips(int index);
int64_t tcp_rpcs_get_ext_secret_expires(int index);
int tcp_rpcs_get_ext_secret_count(void);

void tcp_rpcs_pin_ext_secrets (void);
int tcp_rpcs_reload_ext_secrets (const unsigned char secrets[][16],
                                const char labels[][EXT_SECRET_LABEL_MAX + 1],
                                const int *limits, const long long *quotas,
                                const int *max_ips_arr, const int64_t *expires_arr,
                                int count);

void tcp_rpcs_ip_track_disconnect (int secret_id, unsigned ip, const unsigned char *ipv6);

void tcp_rpc_add_proxy_domain (const char *domain);

void tcp_rpc_init_proxy_domains();

/* SOCKS5 upstream proxy */
int socks5_set_proxy (const char *url);
int socks5_is_enabled (void);

extern long long socks5_connects_attempted, socks5_connects_succeeded, socks5_connects_failed;
