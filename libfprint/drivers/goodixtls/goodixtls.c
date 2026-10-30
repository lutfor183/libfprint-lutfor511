// Goodix Tls driver for libfprint - Lutfor custom variant
// Custom driver for Goodix 27c6:5117 maintained by Lutfor <lutfor183.du@gmail.com>
// TLS PSK / device signature & key material reverse engineered by Lutfor via USB sniffing
// Renamed to avoid conflict with regular fprint driver (original driver id: goodixtls511)

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <natasha@natashaee.me>
// Copyright (C) 2026 Lutfor <lutfor183.du@gmail.com>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>

#include "drivers_api.h"
#include "fp-device.h"
#include "fpi-device.h"
#include "glibconfig.h"
#include "goodix.h"
#include "goodixtls.h"

#include <glib/gstdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define GOODIX_PSK_PATH   "/run/goodixtls/psk"
#define GOODIX_PSK_STAMP  "/run/goodixtls/psk.stamp"
#define GOODIX_PSK_SYNC   "/opt/lutfor-fprint/libexec/goodixtls-psk-sync"

/* Last-resort key: the PSK most recently recovered from this machine's
 * Windows Goodix_Cache.bin.  The live value is re-read from the Windows
 * cache at every open (see goodix_psk_get). */
static const guint8 goodix_default_psk[32] = {
  0x25, 0xB2, 0xF3, 0x94, 0xB9, 0xB9, 0x3C, 0xB5,
  0xB4, 0xF9, 0x1A, 0x6E, 0x54, 0x03, 0xF9, 0xEA,
  0x69, 0x93, 0x52, 0x12, 0x69, 0xE4, 0x43, 0x68,
  0x4D, 0xBF, 0x9D, 0x91, 0x0F, 0xBF, 0x43, 0xD4
};

static gboolean
parse_hex_psk (const gchar *hex, guint8 out[32])
{
  guint8 tmp[32];
  gsize i;

  if (!hex)
    return FALSE;
  while (g_ascii_isspace (*hex))
    hex++;
  if (strlen (hex) < 64)
    return FALSE;
  for (i = 0; i < 32; i++)
    {
      gint hi = g_ascii_xdigit_value (hex[i * 2]);
      gint lo = g_ascii_xdigit_value (hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return FALSE;
      tmp[i] = (guint8) ((hi << 4) | lo);
    }
  memcpy (out, tmp, 32);
  return TRUE;
}

static gchar *
unescape_mountpoint (gchar *mp)
{
  gchar *s = mp;
  gchar *out = g_malloc (strlen (mp) + 1);
  gchar *o = out;

  while (*s)
    {
      if (s[0] == '\\' && g_ascii_isdigit (s[1]) &&
          g_ascii_isdigit (s[2]) && g_ascii_isdigit (s[3]))
        {
          *o++ = (gchar) (((s[1] - '0') << 6) | ((s[2] - '0') << 3) | (s[3] - '0'));
          s += 4;
        }
      else
        *o++ = *s++;
    }
  *o = '\0';
  return out;
}

/* Find the newest <mount>/ProgramData/Goodix/Goodix_Cache.bin. */
static gchar *
goodix_find_windows_cache (glong *mtime_out)
{
  gchar *mounts = NULL;
  gchar **lines;
  gchar *best = NULL;
  glong best_mtime = 0;
  guint i;

  if (!g_file_get_contents ("/proc/mounts", &mounts, NULL, NULL))
    return NULL;

  lines = g_strsplit (mounts, "\n", -1);
  g_free (mounts);

  for (i = 0; lines[i]; i++)
    {
      gchar **f = g_strsplit_set (lines[i], " \t", 3);
      gchar *mp, *path;
      GStatBuf st;

      if (!f[0] || !f[1])
        {
          g_strfreev (f);
          continue;
        }
      mp = unescape_mountpoint (f[1]);
      path = g_build_filename (mp, "ProgramData", "Goodix", "Goodix_Cache.bin", NULL);
      if (g_stat (path, &st) == 0 && S_ISREG (st.st_mode))
        {
          if (st.st_mtime >= best_mtime)
            {
              best_mtime = st.st_mtime;
              g_free (best);
              best = g_strdup (path);
            }
        }
      g_free (path);
      g_free (mp);
      g_strfreev (f);
    }
  g_strfreev (lines);

  if (best && mtime_out)
    *mtime_out = best_mtime;
  return best;
}

static void
goodix_psk_maybe_sync (void)
{
  glong cache_mtime = 0;
  gchar *cache = goodix_find_windows_cache (&cache_mtime);
  gchar *stamp = NULL;
  gboolean fresh = FALSE;

  if (!cache)
    {
      fp_dbg ("No Windows Goodix cache found; using local/builtin PSK");
      return;
    }

  if (g_file_get_contents (GOODIX_PSK_STAMP, &stamp, NULL, NULL))
    {
      gchar **w = g_strsplit_set (stamp, " \n", 3);
      if (w[0] && w[1] && g_strcmp0 (w[0], cache) == 0 &&
          g_ascii_strtoll (w[1], NULL, 10) == cache_mtime &&
          g_file_test (GOODIX_PSK_PATH, G_FILE_TEST_EXISTS))
        fresh = TRUE;
      g_strfreev (w);
      g_free (stamp);
    }

  if (!fresh)
    {
      gchar *argv[] = { (gchar *) GOODIX_PSK_SYNC, cache, NULL };
      gint status = 0;
      gboolean ok;
      GError *spawn_err = NULL;

      ok = g_spawn_sync (NULL, argv, NULL,
                         G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                         NULL, NULL, NULL, NULL, &status, &spawn_err);
#if GLIB_CHECK_VERSION(2, 70, 0)
      if (ok)
        ok = g_spawn_check_wait_status (status, NULL);
#else
      if (ok)
        ok = g_spawn_check_exit_status (status, NULL);
#endif
      if (ok)
        fp_dbg ("PSK re-synced from %s", cache);
      else
        fp_warn ("PSK sync failed for %s (status %d): %s", cache, status,
                 spawn_err ? spawn_err->message : "exit nonzero");
      g_clear_error (&spawn_err);
    }

  g_free (cache);
}

/* Windows-like behaviour: follow the PSK in the Windows cache whenever it
 * changes; fall back to the last synced value, then to the builtin key. */
static void
goodix_psk_get (guint8 out[32])
{
  const gchar *env = g_getenv ("GOODIXTLS_PSK");
  gchar *txt = NULL;

  if (env && parse_hex_psk (env, out))
    {
      fp_dbg ("PSK from GOODIXTLS_PSK");
      return;
    }

  goodix_psk_maybe_sync ();

  if (g_file_get_contents (GOODIX_PSK_PATH, &txt, NULL, NULL))
    {
      gboolean ok = parse_hex_psk (txt, out);
      g_free (txt);
      if (ok)
        {
          fp_dbg ("PSK from Windows cache");
          return;
        }
    }

  memcpy (out, goodix_default_psk, 32);
  fp_dbg ("PSK builtin default");
}

GError *
err_from_ssl (void)
{
  unsigned long code = ERR_get_error ();
  const char *msg = ERR_reason_error_string (code);

  /* g_error_new: old malloc missed domain/NUL, crashed on NULL msg. */
  if (msg)
    return g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                        "TLS error: %s (code %lu)", msg, code);
  return g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                      "TLS error (code %lu)", code);
}

static unsigned int
tls_server_psk_server_callback (SSL           *ssl,
                                const char    *identity,
                                unsigned char *psk,
                                unsigned int   max_psk_len)
{
  const int len = 32;
  /* Driver TLS PSK / signature - reverse engineered by Lutfor (lutfor183.du@gmail.com)
   * Extracted from proprietary Goodix Windows driver USB traffic via reverse engineering.
   * Custom Lutfor driver key for 27c6:5117 - do not upstream without attribution. */
  guint8 actual_psk[32];

  goodix_psk_get (actual_psk);

  fp_dbg ("PSK WANTED %d", max_psk_len);
  if (len > max_psk_len)
    {
      fp_err ("max psk length (%d) too short (needs %d)", max_psk_len, len);
      return 0;
    }

  memcpy (psk, actual_psk, len);

  return len;
}

/* Cached SSL_CTX: static config, saves setup per verify. */
static SSL_CTX *cached_ctx = NULL;
static GMutex cached_ctx_lock;

__attribute__((destructor)) static void
cached_ctx_cleanup (void)
{
  if (cached_ctx)
    {
      SSL_CTX_free (cached_ctx);
      cached_ctx = NULL;
    }
}

static SSL_CTX *
tls_server_create_ctx (void)
{
  g_mutex_lock (&cached_ctx_lock);
  if (cached_ctx)
    {
      SSL_CTX_up_ref (cached_ctx);
      SSL_CTX *ctx = cached_ctx;
      g_mutex_unlock (&cached_ctx_lock);
      return ctx;
    }

  const SSL_METHOD *method = TLS_server_method ();
  SSL_CTX *ctx = SSL_CTX_new (method);

  if (ctx)
    {
      cached_ctx = ctx;
      SSL_CTX_up_ref (cached_ctx);
    }
  g_mutex_unlock (&cached_ctx_lock);

  return ctx;
}

static void
tls_server_config_ctx (SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto (ctx, 1);
  SSL_CTX_set_dh_auto (ctx, 1);
  SSL_CTX_set_cipher_list (ctx, "ALL");
  SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback (ctx, tls_server_psk_server_callback);
}

int
goodix_tls_client_write (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  /* Loop partial writes (old code dropped the tail). */
  guint16 done = 0;
  while (done < length)
    {
      ssize_t n = write (self->client_fd, data + done, length - done);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (n == 0)
        break;
      done += n;
    }
  return done;
}
int
goodix_tls_client_read (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  /* Poll 3s: bare blocking read wedged fprintd on stalls. */
  struct pollfd p = {.fd = self->client_fd, .events = POLLIN};
  int pr = poll (&p, 1, 3000);

  if (pr == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }
  if (pr < 0)
    return -1;
  if (!(p.revents & POLLIN))
    {
      errno = EIO;
      return -1;
    }
  return read (self->client_fd, data, length * sizeof (guint8));
}

int
goodix_tls_server_read (GoodixTlsServer *self, guint8 *data,
                        guint32 length, GError **error)
{
  int retr = SSL_read (self->ssl_layer, data, length * sizeof (guint8));

  if (retr <= 0)
    *error = err_from_ssl ();
  return retr;
}

static void
tls_config_ssl (SSL *ssl)
{
  SSL_set_min_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_max_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_psk_server_callback (ssl, tls_server_psk_server_callback);
  SSL_set_cipher_list (ssl, "ALL");
}

static void *
goodix_tls_init_serve (void *me)
{
  GoodixTlsServer *self = me;

  fp_dbg ("TLS server waiting to accept...");
  int retr = SSL_accept (self->ssl_layer);

  fp_dbg ("TLS server accept done");
  if (retr <= 0)
    {
      /* Key may have been reprovisioned by Windows: force a re-sync next open. */
      g_remove (GOODIX_PSK_STAMP);
      fp_err ("server ready failed: %s", ERR_reason_error_string (ERR_get_error ()));
    }
  else
    fp_dbg ("TLS connection ready");
  return NULL;
}

gboolean
goodix_tls_server_deinit (GoodixTlsServer *self, GError **error)
{
  /* NULL/-1 guards: double-deinit safe. */
  if (self->ssl_layer)
    {
      /* Wake serve thread before join (close-first hangs). */
      if (self->sock_fd >= 0)
        shutdown (self->sock_fd, SHUT_RDWR);
      if (self->client_fd >= 0)
        shutdown (self->client_fd, SHUT_RDWR);
      SSL_shutdown (self->ssl_layer);
      pthread_join (self->serve_thread, NULL);
      SSL_free (self->ssl_layer);
      self->ssl_layer = NULL;
    }

  if (self->client_fd >= 0)
    {
      close (self->client_fd);
      self->client_fd = -1;
    }
  if (self->sock_fd >= 0)
    {
      close (self->sock_fd);
      self->sock_fd = -1;
    }

  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  return TRUE;
}

gboolean
goodix_tls_server_init (GoodixTlsServer *self, GError **error)
{
  SSL_load_error_strings ();
  OpenSSL_add_ssl_algorithms ();
  SSL_library_init ();
  /* fds: -1 sentinel (0 is stdin). */
  self->sock_fd = -1;
  self->client_fd = -1;
  self->ssl_ctx = tls_server_create_ctx ();
  tls_server_config_ctx (self->ssl_ctx);

  int socks[2] = {0, 0};
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, socks) != 0)
    {
      g_set_error (error, G_FILE_ERROR, errno,
                   "failed to create socket pair: %s", strerror (errno));
      return FALSE;
    }
  self->sock_fd = socks[0];
  self->client_fd = socks[1];

  if (self->ssl_ctx == NULL)
    {
      fp_dbg ("Unable to create TLS server context\n");
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Unable to "
                                                                  "create TLS "
                                                                  "server "
                                                                  "context");
      return FALSE;
    }
  self->ssl_layer = SSL_new (self->ssl_ctx);
  /* SSL_new may fail: clean teardown, no crash. */
  if (!self->ssl_layer)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "failed to create TLS session");
      close (self->sock_fd);
      close (self->client_fd);
      self->sock_fd = -1;
      self->client_fd = -1;
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
      return FALSE;
    }
  tls_config_ssl (self->ssl_layer);
  SSL_set_fd (self->ssl_layer, self->sock_fd);

  pthread_create (&self->serve_thread, 0, goodix_tls_init_serve, self);

  return TRUE;
}
