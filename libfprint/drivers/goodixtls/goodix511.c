// Goodix Tls driver for libfprint - Lutfor custom variant
// Custom driver for Goodix 27c6:5117 maintained by Lutfor <lutfor183.du@gmail.com>
// Protocol, TLS PSK key and device signature reverse engineered by Lutfor
// Driver renamed from goodixtls511 -> lutfor511 to avoid conflict with regular fprint
// Milan engine integration: loads GoodixEngineAdapter.dll (AlgoChicago.dll) natively
// via in-process PE loader for Windows-identical matching.
// PE loader derived from the goodix-5e0a project by jitendradara12:
//   https://github.com/jitendradara12/goodix-5e0a
// AlgoChicago.dll analysis, driver integration and template storage by Lutfor.
// AlgoChicago.dll / GoodixEngineAdapter.dll are proprietary and not redistributed.

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
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110 USA

#include "drivers/goodixtls/goodix5xx.h"
#include "fp-device.h"
#include "fp-image-device.h"
#include "fp-image.h"
#include "fpi-assembling.h"
#include "fpi-context.h"
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "fpi-ssm.h"
#include "fp-print.h"
#include "fpi-print.h"
#include "glibconfig.h"
#include "gusb/gusb-device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix511.h"
#include "goodix_milan.h"

#define FP_COMPONENT "lutfor511"

#define GOODIX511_WIDTH 64
#define GOODIX511_HEIGHT 80
#define GOODIX511_SCAN_WIDTH 88
#define GOODIX511_FRAME_SIZE (GOODIX511_WIDTH * GOODIX511_HEIGHT)
// For every 4 pixels there are 6 bytes and there are 8 extra start bytes and 5
// extra end
#define GOODIX511_RAW_FRAME_SIZE \
  8 + (GOODIX511_HEIGHT * GOODIX511_SCAN_WIDTH) / 4 * 6 + 5
#define GOODIX511_CAP_FRAMES 1 // Number of frames we capture per swipe

typedef unsigned short Goodix511Pix;

struct _FpiDeviceGoodixTls511
{
  FpiDeviceGoodixTls parent;

  guint8            *otp;

  /* Milan engine state */
  guint8            *milan_template;
  guint              milan_template_len;
  guint16            *last_raw_frame;  /* last captured raw 16-bit frame (88x80) */
  gboolean            milan_enrolling;
  gboolean            milan_finish_pending; /* waiting for safe enroll completion */
  void               *milan_ctx;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls511, fpi_device_goodixtls511, FPI,
                      DEVICE_GOODIXTLS511, FpiDeviceGoodixTls5xx);

G_DEFINE_TYPE (FpiDeviceGoodixTls511, fpi_device_goodixtls511,
               FPI_TYPE_DEVICE_GOODIXTLS5XX);

// ---- ACTIVE SECTION START ----

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_ENABLE_CHIP,
  ACTIVATE_NOP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_RESET,
  ACTIVATE_SET_MCU_IDLE,
  ACTIVATE_READ_ODP,
  ACTIVATE_UPLOAD_MCU_CONFIG,
  ACTIVATE_SET_POWERDOWN_SCAN_FREQUENCY,
  ACTIVATE_NUM_STATES,
};

enum otp_write_states {
  OTP_WRITE_1,
  OTP_WRITE_2,
  OTP_WRITE_3,
  OTP_WRITE_4,

  OTP_WRITE_NUM,
};

static guint16 otp_write_addrs[] = {0x0220, 0x0236, 0x0238, 0x023a};

static void
otp_write_run (FpiSsm *ssm, FpDevice *dev)
{
  guint16 data;
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  guint8 *otp = self->otp;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OTP_WRITE_1:
      data = otp[46] << 4 | 8;
      break;

    case OTP_WRITE_2:
      data = otp[47];
      break;

    case OTP_WRITE_3:
      data = otp[48];
      break;

    case OTP_WRITE_4:
      data = otp[49];
      break;
    }

  goodix_send_write_sensor_register (
    dev, otp_write_addrs[fpi_ssm_get_cur_state (ssm)], data, goodixtls5xx_check_none,
    ssm);
  if (fpi_ssm_get_cur_state (ssm) == OTP_WRITE_NUM - 1)
    free (self->otp);
}

static void
read_otp_callback (FpDevice *dev, guint8 *data, guint16 len,
                   gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  if (len < 64)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (FP_DEVICE_ERROR,
                                             FP_DEVICE_ERROR_DATA_INVALID,
                                             "OTP is invalid (len: %d)", 64));
      return;
    }
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  self->otp = malloc (len);
  memcpy (self->otp, data, len);
  FpiSsm *otp_ssm = fpi_ssm_new (dev, otp_write_run, OTP_WRITE_NUM);
  fpi_ssm_start_subsm (ssm, otp_ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP:
      // Nop seems to clear the previous command buffer. But we are
      // unable to do so.
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_ENABLE_CHIP:
      goodix_send_enable_chip (dev, TRUE, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_NOP:
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      /* Skip static FW/PSK/OTP re-query when provisioned. */
      if (goodixtls5xx_is_provisioned (dev))
        fpi_ssm_next_state (ssm);
      else
        goodix_send_query_firmware_version (dev, goodixtls5xx_check_firmware_version, ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      if (goodixtls5xx_is_provisioned (dev))
        fpi_ssm_next_state (ssm);
      else
        goodix_send_preset_psk_read (dev, GOODIX_511_PSK_FLAGS, 0,
                                     goodixtls5xx_check_preset_psk_read, ssm);
      break;

    case ACTIVATE_RESET:
      goodix_send_reset (dev, TRUE, 5, goodixtls5xx_check_reset, ssm);
      break;

    case ACTIVATE_SET_MCU_IDLE:
      goodix_send_mcu_switch_to_idle_mode (dev, 5, goodixtls5xx_check_idle, ssm);
      break;

    case ACTIVATE_READ_ODP:
      if (goodixtls5xx_is_provisioned (dev))
        fpi_ssm_next_state (ssm);
      else
        goodix_send_read_otp (dev, read_otp_callback, ssm);
      break;

    case ACTIVATE_UPLOAD_MCU_CONFIG:
      goodix_send_upload_config_mcu (dev, goodix_511_config,
                                     sizeof (goodix_511_config), NULL,
                                     goodixtls5xx_check_config_upload, ssm);
      break;

    case ACTIVATE_SET_POWERDOWN_SCAN_FREQUENCY:
      /* 100: gentle idle polling (200 doubles wakeups). */
      goodix_send_set_powerdown_scan_frequency (
        dev, 100, goodixtls5xx_check_powerdown_scan_freq, ssm);
      break;
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  G_DEBUG_HERE ();
  if (!error)
    {
      goodixtls5xx_init_tls (dev);
      /* Initialize Milan matching engine */
      if (!goodix_milan_init (NULL))
        fp_warn ("Milan engine init failed - verify will use NBIS fallback");
      else
        fp_dbg ("Milan engine loaded: %s", goodix_milan_get_version ());
    }
  else
    {
      fp_err ("failed during activation: %s (code: %d)", error->message,
              error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
    }
}

// ---- ACTIVE SECTION END ----

// -----------------------------------------------------------------------------

// ---- SCAN SECTION START ----

const guint8 fdt_switch_state_mode[] = {
  0x01,
  0x80,
  0xaf,
  0x80,
  0xbf,
  0x80,
  0xa4,
  0x80,
  0xb8,
  0x80,
  0xa8,
  0x80,
  0xb7,
};


// ---- SCAN SECTION END ----

// ---- DEV SECTION START ----

static void
dev_activate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}


// ---- DEV SECTION END ----

static void
fpi_device_goodixtls511_init (FpiDeviceGoodixTls511 *self)
{
}
static GoodixTls5xxMcuConfig
get_mcu_config ()
{
  GoodixTls5xxMcuConfig cfg;

  cfg.free_fn = NULL;
  cfg.data = fdt_switch_state_mode;
  cfg.data_len = sizeof (fdt_switch_state_mode);
  return cfg;
}

/* Preprocess a raw 16-bit frame for Milan: 3x3 smooth - 11x11 background,
 * RMS normalize to 80, midpoint 128. Output: 64x80 8-bit. */
static uint8_t *
milan_preprocess_frame (const guint16 *raw_88x80)
{
  uint16_t smooth[GOODIX511_HEIGHT * GOODIX511_WIDTH];
  uint16_t bg[GOODIX511_HEIGHT * GOODIX511_WIDTH];
  int16_t diff[GOODIX511_HEIGHT * GOODIX511_WIDTH];
  int W = GOODIX511_WIDTH, H = GOODIX511_HEIGHT;
  int SW = GOODIX511_SCAN_WIDTH;

  /* Crop to 64x80 from 88x80 stride, then 3x3 blur */
  uint16_t cropped[H * W];
  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++)
      cropped[y * W + x] = raw_88x80[y * SW + x];

  /* 3x3 box blur */
  for (int y = 0; y < H; y++) {
    for (int x = 0; x < W; x++) {
      uint32_t sum = 0; int n = 0;
      for (int dy = -1; dy <= 1; dy++) {
        for (int dx = -1; dx <= 1; dx++) {
          int ny = y + dy, nx = x + dx;
          if (ny >= 0 && ny < H && nx >= 0 && nx < W) {
            sum += cropped[ny * W + nx]; n++;
          }
        }
      }
      smooth[y * W + x] = (uint16_t)(sum / n);
    }
  }

  /* 11x11 box blur (background) */
  int r = 5;
  for (int y = 0; y < H; y++) {
    for (int x = 0; x < W; x++) {
      uint32_t sum = 0; int n = 0;
      for (int dy = -r; dy <= r; dy++) {
        for (int dx = -r; dx <= r; dx++) {
          int ny = y + dy, nx = x + dx;
          if (ny >= 0 && ny < H && nx >= 0 && nx < W) {
            sum += cropped[ny * W + nx]; n++;
          }
        }
      }
      bg[y * W + x] = (uint16_t)(sum / n);
    }
  }

  /* diff = smooth - bg */
  for (int i = 0; i < H * W; i++)
    diff[i] = (int16_t)((int)smooth[i] - (int)bg[i]);

  /* RMS normalize */
  double mean = 0, sum_sq = 0;
  for (int i = 0; i < H * W; i++) mean += diff[i];
  mean /= H * W;
  for (int i = 0; i < H * W; i++) {
    double d = diff[i] - mean;
    sum_sq += d * d;
  }
  double rms = sqrt(sum_sq / (H * W));
  double scale = (rms > 0) ? 80.0 / rms : 1.0;

  uint8_t *out = malloc (W * H);
  for (int i = 0; i < H * W; i++) {
    int v = (int)(128 + (diff[i] - mean) * scale);
    if (v < 0) v = 0;
    if (v > 255) v = 255;
    out[i] = (uint8_t)v;
  }
  return out;
}

static FpImage *
crop_frame (guint8 * frame)
{
  FpImage * img = fp_image_new (GOODIX511_WIDTH, GOODIX511_HEIGHT);

  img->flags |= FPI_IMAGE_PARTIAL;
  /* Row memcpy: identical output, faster. */
  for (int y = 0; y != GOODIX511_HEIGHT; ++y)
    memcpy (img->data + y * GOODIX511_WIDTH,
            frame + y * GOODIX511_SCAN_WIDTH,
            GOODIX511_WIDTH);
  return img;
}

static void
goodix511_capture_raw_frame (FpDevice *dev,
                             const GoodixTls5xxPix *raw_frame,
                             guint16 frame_size)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  fp_dbg ("capture_raw_frame: action=%d, milan_ctx=%p, enrolling=%d",
          action, self->milan_ctx, self->milan_enrolling);

  if (self->milan_finish_pending)
    {
      /* Enrollment already finished; wait for the deferred completion. */
      return;
    }

  /* Save raw frame for verify matching */
  if (self->last_raw_frame)
    free (self->last_raw_frame);
  self->last_raw_frame = malloc (frame_size * sizeof (GoodixTls5xxPix));
  if (self->last_raw_frame)
    memcpy (self->last_raw_frame, raw_frame, frame_size * sizeof (GoodixTls5xxPix));

  /* Auto-detect enroll mode and feed frame to Milan engine */
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      if (!self->milan_ctx)
        {
          if (!goodix_milan_init (NULL))
            {
              fp_warn ("Milan engine not available for enroll");
              return;
            }
          int max_imgs = 12;
          self->milan_ctx = goodix_milan_enroll_start (&max_imgs);
          if (!self->milan_ctx)
            {
              fp_warn ("Milan enroll start failed");
              return;
            }
          fp_dbg ("Milan enroll started, max_imgs=%d", max_imgs);
        }
      uint8_t *frame_8 = milan_preprocess_frame (self->last_raw_frame);
      if (frame_8)
        {
          int count = 0, progress = 0;
          int r = goodix_milan_enroll_add_image (self->milan_ctx, frame_8,
                                                  GOODIX511_WIDTH, GOODIX511_HEIGHT,
                                                  &count, &progress);
          free (frame_8);
          fp_dbg ("Milan enroll add: r=%d count=%d progress=%d", r, count, progress);
          /* Commit when Milan reports complete */
          if (progress >= 100)
            {
              fp_dbg ("Milan enroll progress reached 100, committing template");
              uint8_t *blob = NULL;
              size_t blen = 0;
              int cr = goodix_milan_enroll_commit (self->milan_ctx, &blob, &blen);
              if (cr == 0 && blob)
                {
                  if (self->milan_template)
                    free (self->milan_template);
                  self->milan_template = blob;
                  self->milan_template_len = blen;
                  fp_warn ("Milan enroll complete: template %zu bytes", blen);

                  /* Store the packed template in the enroll print so that
                   * fprintd persists it and verify works across restarts. */
                  FpPrint *enroll_print = NULL;
                  FpiPrintType ptype = FPI_PRINT_UNDEFINED;
                  fpi_device_get_enroll_data (dev, &enroll_print);
                  if (enroll_print)
                    {
                      g_object_get (enroll_print, "fpi-type", &ptype, NULL);
                      if (ptype == FPI_PRINT_UNDEFINED)
                        {
                          GVariant *blob_variant = g_variant_new_fixed_array (
                            G_VARIANT_TYPE_BYTE, self->milan_template,
                            self->milan_template_len, 1);
                          fpi_print_set_type (enroll_print, FPI_PRINT_RAW);
                          g_object_set (enroll_print, "fpi-data", blob_variant, NULL);
                          self->milan_finish_pending = TRUE;
                        }
                    }
                }
              goodix_milan_enroll_finish (self->milan_ctx);
              self->milan_ctx = NULL;
              self->milan_enrolling = FALSE;
              goodixtls5xx_set_milan_enroll_mode (dev, FALSE);
            }
        }
    }
}

/* Custom verify match using Milan engine */
static FpiMatchResult
goodix511_verify_match (FpImageDevice *img_dev,
                        FpPrint       *template,
                        FpPrint       *print,
                        gint          score_threshold,
                        gint         *score)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);

  const guint8 *tpl = NULL;
  gsize tpl_len = 0;
  g_autoptr(GVariant) tpl_data = NULL;
  FpiPrintType ptype = FPI_PRINT_UNDEFINED;

  /* fprintd persists the Milan blob as RAW print data. */
  if (template)
    g_object_get (template, "fpi-type", &ptype, "fpi-data", &tpl_data, NULL);

  if (template)
    {
      /* Stored Milan prints are RAW; legacy SIGFM/NBIS prints cannot be
       * matched by the vendor engine. Fail closed instead of falling back
       * to an unrelated in-memory template. */
      if (ptype == FPI_PRINT_RAW && tpl_data)
        {
          gsize n = 0;
          const guint8 *p = g_variant_get_fixed_array (tpl_data, &n, 1);
          if (p && n > 0)
            {
              tpl = p;
              tpl_len = n;
            }
        }
      if (!tpl)
        return FPI_MATCH_FAIL;
    }
  else
    {
      tpl = self->milan_template;
      tpl_len = self->milan_template_len;
    }

  if (!tpl || tpl_len == 0)
    return FPI_MATCH_ERROR;

  /* Get raw 16-bit frame stored during capture */
  if (!self->last_raw_frame)
    return FPI_MATCH_FAIL;

  /* Preprocess for Milan */
  uint8_t *frame_8 = milan_preprocess_frame (self->last_raw_frame);
  if (!frame_8)
    return FPI_MATCH_FAIL;

  int match_score = 0;
  int matched = goodix_milan_verify_image (frame_8, GOODIX511_WIDTH,
                                           GOODIX511_HEIGHT,
                                           tpl, tpl_len,
                                           &match_score);
  free (frame_8);

  if (score)
    *score = match_score;

  return matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
}





static void
goodix511_enroll (FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  fp_dbg ("gx511_enroll called");

  if (!goodix_milan_init (NULL))
    {
      fpi_device_action_error (dev,
                               g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                                            "Milan engine not available"));
      return;
    }

  int max_imgs = 12;
  self->milan_ctx = goodix_milan_enroll_start (&max_imgs);
  if (!self->milan_ctx)
    {
      fpi_device_action_error (dev,
                               g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                                            "Milan enroll start failed"));
      return;
    }

  self->milan_enrolling = TRUE;
  goodixtls5xx_set_milan_enroll_mode (dev, TRUE);

  /* Activate device. capture_raw_frame will feed frames to Milan.
   * When Milan progress >= 100, goodix511_enroll_finish is called. */
  fpi_image_device_activate (img_dev);
}

static void
goodix511_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (img_dev);

  /* Milan has produced a template; finish the action at the normal
   * finger-off/idle point instead of starting another scan. */
  if (self->milan_finish_pending &&
      state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    {
      FpPrint *enroll_print = NULL;
      self->milan_finish_pending = FALSE;
      fpi_device_get_enroll_data (FP_DEVICE (img_dev), &enroll_print);
      if (enroll_print)
        fpi_image_device_enroll_complete_with_print (img_dev, enroll_print);
      else
        fpi_image_device_session_error (img_dev,
                                        g_error_new (FP_DEVICE_ERROR,
                                                     FP_DEVICE_ERROR_GENERAL,
                                                     "Enroll print missing at completion"));
      return;
    }

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    goodixtls5xx_scan_start (FPI_DEVICE_GOODIXTLS5XX (img_dev));
}

static void
fpi_device_goodixtls511_class_init (FpiDeviceGoodixTls511Class * class)
{
  FpiDeviceGoodixTlsClass * gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass * dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass * img_dev_class = FP_IMAGE_DEVICE_CLASS (class);
  FpiDeviceGoodixTls5xxClass * xx_cls = FPI_DEVICE_GOODIXTLS5XX_CLASS (class);

  xx_cls->get_mcu_cfg = get_mcu_config;
  xx_cls->process_frame = crop_frame;
  xx_cls->capture_raw_frame = goodix511_capture_raw_frame;
  xx_cls->scan_height = GOODIX511_HEIGHT;
  xx_cls->scan_width = GOODIX511_SCAN_WIDTH;
  xx_cls->psk = goodix_511_psk_0;
  xx_cls->psk_flags = GOODIX_511_PSK_FLAGS;
  xx_cls->psk_len = sizeof (goodix_511_psk_0);
  xx_cls->firmware_version = GOODIX_511_FIRMWARE_VERSION;
  xx_cls->reset_number = GOODIX_511_RESET_NUMBER;

  gx_class->interface = GOODIX_511_INTERFACE;
  gx_class->ep_in = GOODIX_511_EP_IN;
  gx_class->ep_out = GOODIX_511_EP_OUT;

  dev_class->id = "lutfor511";
  dev_class->full_name = "Lutfor Goodix 511 TLS Fingerprint Sensor (Reverse Engineered)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = 20;

  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  img_dev_class->score_threshold = 12;
  img_dev_class->img_width = GOODIX511_WIDTH;
  img_dev_class->img_height = GOODIX511_HEIGHT;
  img_dev_class->algorithm = FPI_DEVICE_ALGO_SIGFM;

  img_dev_class->activate = dev_activate;
  img_dev_class->change_state = goodix511_change_state;
  img_dev_class->match = goodix511_verify_match;

  /* Override enroll with Milan engine */
  dev_class->enroll = goodix511_enroll;

  fpi_device_class_auto_initialize_features (dev_class);
}

