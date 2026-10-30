/*
 * Goodix Milan Engine In-Process Loader and Bridge
 *
 * Loads GoodixEngineAdapter.dll in-process on Linux with %gs TEB and memfd W^X mapping.
 * Interfaces with Goodix's Milan biometric matching engine for enrollment and identification.
 *
 * Native PE-loader approach derived from the goodix-5e0a project by
 * jitendradara12 (https://github.com/jitendradara12/goodix-5e0a).
 * Adapted for the Goodix 27c6:5117 lutfor511 driver by Lutfor.
 *
 * Copyright (C) 2026 The libfprint Goodix 5e0a contributors
 * Integration changes Copyright (C) 2026 Lutfor <lutfor183.du@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <glib.h>

G_BEGIN_DECLS

/* Initialize the Milan engine from GoodixEngineAdapter.dll.
 * If dll_path is NULL, searches standard known locations.
 * Returns TRUE on success, FALSE on failure. */
gboolean goodix_milan_init (const char *dll_path);

/* Get engine version string (e.g. "Milan_v_3.02.00.20"). */
const char *goodix_milan_get_version (void);

/* Start enrollment context. Sets *max_images (e.g. 16).
 * Returns opaque enrollment context pointer or NULL on failure. */
void *goodix_milan_enroll_start (int *max_images);

/* Feed one 64x80 8-bit normalized grayscale impression to enrollment.
 * Updates *enrolled_count and *progress_pct.
 * Returns 0 on success, non-zero if impression was rejected (e.g. poor quality/duplicate). */
int goodix_milan_enroll_add_image (void *ctx,
                                   const uint8_t *pixels,
                                   int width,
                                   int height,
                                   int *enrolled_count,
                                   int *progress_pct);

/* Commit completed enrollment into a packed template buffer.
 * Caller owns and must free() *out_blob.
 * Returns 0 on success. */
int goodix_milan_enroll_commit (void *ctx,
                                uint8_t **out_blob,
                                size_t *out_len);

/* Free an active enrollment context. */
void goodix_milan_enroll_finish (void *ctx);

/* Verify a 64x80 8-bit normalized probe frame against a packed composite template.
 * Returns 1 on MATCH, 0 on NO MATCH or error.
 * If out_score is non-NULL, receives the engine match score (0-100). */
int goodix_milan_verify_image (const uint8_t *pixels,
                               int width,
                               int height,
                               const uint8_t *template_blob,
                               size_t template_len,
                               int *out_score);

/* Ticket 77: identify a 64x80 probe against an N-template gallery with ONE
 * identifyImage call (count=N), preserving the engine's native gallery
 * decision (same >0 score gate as verify). Returns 1 on MATCH with
 * *out_idx = gallery index and *out_score = engine score, 0 on NO MATCH
 * (*out_idx=-1) or error. Fail-closed: any unpack failure rejects without
 * matching, so a corrupt template can never false-accept. */
int goodix_milan_identify_image (const uint8_t *pixels,
                                 int width,
                                 int height,
                                 const uint8_t **template_blobs,
                                 const size_t *template_lens,
                                 int n_templates,
                                 int *out_idx,
                                 int *out_score);

/* Ticket 76: query Milan native frame quality for one 64x80 8-bit normalized
 * frame (the exact buffer verify consumes). Wraps the getQuality export,
 * which populates img quality/overlap plus a qout side-channel.
 * Outputs quality/overlap (0-255 each); returns the combined ranking proxy
 * (quality << 8 | overlap) so quality is primary and overlap breaks ties.
 * Returns 0 with outputs zeroed when the engine or export is unavailable or
 * the geometry is not 64x80 — callers break ties by residual range, then
 * active area. Missing quality alone does not reject a touch. */
guint goodix_milan_frame_quality (const uint8_t *pixels,
                                  int width,
                                  int height,
                                  guint *out_quality,
                                  guint *out_overlap);

G_END_DECLS
