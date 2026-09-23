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

    Copyright 2014-2018 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
              2016-2018 Nikolai Durov
    Copyright 2025 Teleproxy contributors
*/

#include "net/net-tls-parse.h"

#include <string.h>

#ifndef FUZZ_TARGET
#include "common/kprintf.h"
#else
static inline int kprintf (const char *format, ...) { (void)format; return 0; }
#endif

int tls_read_length (const unsigned char *data, int *pos) {
  *pos += 2;
  return data[*pos - 2] * 256 + data[*pos - 1];
}

int tls_check_server_hello (const unsigned char *response, int len,
                            const unsigned char *request_session_id,
                            int *is_reversed_extension_order,
                            int *encrypted_record_sizes,
                            int *encrypted_record_count) {
#define FAIL(error) {                                               \
    kprintf ("Failed to parse upstream TLS response: " error "\n"); \
    return 0;                                                       \
  }
#define CHECK_LENGTH(length)  \
  if (pos + (length) > len) { \
    FAIL("Too short");        \
  }
#define EXPECT_STR(pos, str, error)                          \
  if (memcmp (response + pos, str, sizeof (str) - 1) != 0) { \
    FAIL(error);                                             \
  }

  int pos = 0;
  CHECK_LENGTH(3);
  EXPECT_STR(0, "\x16\x03\x03", "Non-TLS response or TLS <= 1.1");
  pos += 3;
  CHECK_LENGTH(2);
  int server_hello_length = tls_read_length (response, &pos);
  if (server_hello_length <= 39) {
    FAIL("Receive too short ServerHello");
  }
  CHECK_LENGTH(server_hello_length);

  EXPECT_STR(5, "\x02\x00", "Non-TLS response 2");
  EXPECT_STR(9, "\x03\x03", "Non-TLS response 3");

  if (memcmp (response + 11, "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91"
                             "\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c", 32) == 0) {
    FAIL("TLS 1.3 servers returning HelloRetryRequest are not supprted");
  }
  if (response[43] == '\x00') {
    FAIL("TLS <= 1.2: empty session_id");
  }
  EXPECT_STR(43, "\x20", "Non-TLS response 4");
  if (server_hello_length <= 75) {
    FAIL("Receive too short server hello 2");
  }
  if (memcmp (response + 44, request_session_id, 32) != 0) {
    FAIL("TLS <= 1.2: expected mirrored session_id");
  }
  /* cipher (2) + compression (1); do not fold the extensions-length high byte
     into this check -- with an MLKEM key_share extensions exceed 255 bytes. */
  EXPECT_STR(76, "\x13", "TLS <= 1.2: expected a TLS 1.3 cipher");
  if (response[77] < 0x01 || response[77] > 0x03 || response[78] != 0x00) {
    FAIL("TLS <= 1.2: expected a TLS 1.3 cipher");
  }
  pos += 74;
  int extensions_length = tls_read_length (response, &pos);
  if (extensions_length + 76 != server_hello_length) {
    FAIL("Receive wrong extensions length");
  }
  int sum = 0;
  while (pos < 5 + server_hello_length - 4) {
    int extension_id = tls_read_length (response, &pos);
    if (extension_id != 0x33 && extension_id != 0x2b) {
      FAIL("Receive unexpected extension");
    }
    if (pos == 83) {
      *is_reversed_extension_order = (extension_id == 0x2b);
    }
    sum += extension_id;

    int extension_length = tls_read_length (response, &pos);
    if (pos + extension_length > 5 + server_hello_length) {
      FAIL("Receive wrong extension length");
    }
    /* key_share: 36 = x25519 (group 2 + len 2 + 32), 1124 = X25519MLKEM768
       (group 2 + len 2 + 1120) from an OpenSSL >= 3.5 backend. */
    if (extension_id == 0x2b ? extension_length != 2
                             : (extension_length != 36 && extension_length != 1124)) {
      FAIL("Unexpected extension length");
    }
    pos += extension_length;
  }
  if (sum != 0x33 + 0x2b) {
    FAIL("Receive duplicate extensions");
  }
  if (pos != 5 + server_hello_length) {
    FAIL("Receive wrong extensions list");
  }

  CHECK_LENGTH(6);
  EXPECT_STR(pos, "\x14\x03\x03\x00\x01\x01", "Expected dummy ChangeCipherSpec");
  pos += 6;

  *encrypted_record_count = 0;
  while (pos + 5 <= len && memcmp (response + pos, "\x17\x03\x03", 3) == 0) {
    pos += 3;
    int rec_len = tls_read_length (response, &pos);
    if (rec_len == 0 || pos + rec_len > len) {
      break;
    }
    if (*encrypted_record_count < MAX_ENCRYPTED_RECORDS) {
      encrypted_record_sizes[*encrypted_record_count] = rec_len;
    }
    (*encrypted_record_count)++;
    pos += rec_len;
  }
  if (*encrypted_record_count == 0) {
    FAIL("No encrypted application data records");
  }

#undef FAIL
#undef CHECK_LENGTH
#undef EXPECT_STR

  return 1;
}

int tls_parse_sni (const unsigned char *client_hello, int len,
                   char *out_domain, int max_domain_len) {
#define CHECK_LENGTH(length)  \
  if (pos + (length) > len) { \
    return -1;                \
  }

  int pos = 11 + 32 + 1 + 32;
  CHECK_LENGTH(2);
  int cipher_suites_length = tls_read_length (client_hello, &pos);
  CHECK_LENGTH(cipher_suites_length + 4);
  pos += cipher_suites_length + 4;
  while (1) {
    CHECK_LENGTH(4);
    int extension_id = tls_read_length (client_hello, &pos);
    int extension_length = tls_read_length (client_hello, &pos);
    CHECK_LENGTH(extension_length);

    if (extension_id == 0) {
      /* found SNI */
      CHECK_LENGTH(5);
      int inner_length = tls_read_length (client_hello, &pos);
      if (inner_length != extension_length - 2) {
        return -1;
      }
      if (client_hello[pos++] != 0) {
        return -1;
      }
      int domain_length = tls_read_length (client_hello, &pos);
      if (domain_length != extension_length - 5) {
        return -1;
      }
      int i;
      for (i = 0; i < domain_length; i++) {
        if (client_hello[pos + i] == 0) {
          return -1;
        }
      }
      if (domain_length >= max_domain_len || domain_length <= 0) {
        return -1;
      }
      memcpy (out_domain, client_hello + pos, domain_length);
      out_domain[domain_length] = '\0';
      return domain_length;
    }

    pos += extension_length;
  }

#undef CHECK_LENGTH
}

int tls_parse_client_hello_ciphers (const unsigned char *client_hello, int len,
                                    unsigned char *cipher_suite_id) {
  int pos = 76;
  if (pos + 2 > len) {
    return -1;
  }
  int cipher_suites_length = tls_read_length (client_hello, &pos);
  if (pos + cipher_suites_length > len) {
    return -1;
  }
  while (cipher_suites_length >= 2 &&
         (client_hello[pos] & 0x0F) == 0x0A &&
         (client_hello[pos + 1] & 0x0F) == 0x0A) {
    /* skip GREASE */
    cipher_suites_length -= 2;
    pos += 2;
  }
  if (cipher_suites_length <= 1 ||
      client_hello[pos] != 0x13 ||
      client_hello[pos + 1] < 0x01 ||
      client_hello[pos + 1] > 0x03) {
    return -1;
  }
  *cipher_suite_id = client_hello[pos + 1];
  return 0;
}

/* Returns 1 if the ClientHello key_share extension (0x33) carries an
   X25519MLKEM768 (0x11ec) entry, 0 otherwise / on parse failure.
   iOS/macOS Telegram and modern browsers send it; a real OpenSSL >= 3.5
   backend answers with the same group, so the fake-TLS front must too. */
int tls_client_hello_offers_mlkem (const unsigned char *client_hello, int len) {
  int pos = 11 + 32;
  if (pos + 1 > len) return 0;
  pos += 1 + client_hello[pos];              /* session_id_len + session_id */
  if (pos + 2 > len) return 0;
  int cs_len = tls_read_length (client_hello, &pos);
  pos += cs_len;
  if (pos + 1 > len) return 0;
  pos += 1 + client_hello[pos];              /* compression */
  if (pos + 2 > len) return 0;
  int ext_len = tls_read_length (client_hello, &pos);
  int ext_end = pos + ext_len;
  if (ext_end > len) return 0;
  while (pos + 4 <= ext_end) {
    int ext_id = tls_read_length (client_hello, &pos);
    int ext_size = tls_read_length (client_hello, &pos);
    if (pos + ext_size > ext_end) return 0;
    if (ext_id == 0x33) {
      int p = pos;
      if (p + 2 > pos + ext_size) return 0;
      int ks_len = tls_read_length (client_hello, &p);
      int ks_end = p + ks_len;
      if (ks_end > pos + ext_size) return 0;
      while (p + 4 <= ks_end) {
        int group = tls_read_length (client_hello, &p);
        int klen = tls_read_length (client_hello, &p);
        if (group == 0x11ec) return 1;
        p += klen;
      }
      return 0;
    }
    pos += ext_size;
  }
  return 0;
}
