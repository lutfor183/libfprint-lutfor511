# Milan Engine (Windows-identical matcher) for Goodix 27c6:5117

This document describes `lutfor12` / the current source tree: using Goodix's
own **Milan** biometric engine (`AlgoChicago.dll`, shipped on Windows as
`GoodixEngineAdapter.dll`) from Linux, instead of libfprint's NBIS/SIGFM
matcher. The goal is preprocess / enroll / identify behaviour identical to
Windows Hello on the same sensor.

Status: enroll, verify and identify (duplicate check) are implemented and
build cleanly. The vendor engine runs in-process with no Wine.

---

## 1. Components

| File | Role |
|------|------|
| `libfprint/drivers/goodixtls/goodix_milan.c` | Native PE loader + bridge for `GoodixEngineAdapter.dll` (`memfd_create`, W^X mapping, `%gs` TEB, MS-ABI calls, Win32 API shims) |
| `libfprint/drivers/goodixtls/goodix_milan.h` | Loader/bridge API: init, version, enroll, commit, verify, identify, quality |
| `libfprint/drivers/goodixtls/goodix511.c` | lutfor511 integration: frame preprocessing, enroll lifecycle, template storage, verify/identify hooks |
| `libfprint/fpi-image-device.c` / `.h` | Optional `match` vfunc (used by verify **and** identify) and deferred custom-enroll completion |
| `libfprint/fp-image-device-private.h` | `enroll_custom_print` state for deferred completion |
| `libfprint/drivers/goodixtls/goodix5xx.c` / `.h` | `capture_raw_frame` vfunc so the driver sees the 16-bit raw frame before squashing |

`goodix_milan.c` is adapted from the **goodix-5e0a** project by
**jitendradara12** (see Credits). The lutfor511-specific work is the raw-frame
preprocessing, composite template handling, FpPrint persistence and the
libfprint lifecycle integration.

---

## 2. Required proprietary DLL (not included)

The engine is Goodix proprietary code. It is **not** part of this repository.

Copy the Windows DLL to one of the paths searched by `goodix_milan_init()`
(for the packaged build the expected location is):

```bash
sudo install -m 0644 GoodixEngineAdapter.dll /opt/lutfor-fprint/lib/GoodixEngineAdapter.dll
```

or point the daemon at it explicitly:

```bash
# /etc/systemd/system/fprintd.service.d/lutfor.conf
[Service]
Environment=GOODIX_ENGINE_DLL_PATH=/opt/lutfor-fprint/lib/GoodixEngineAdapter.dll
```

The file is also accepted under names such as `GoodixEngineAdapter.dll` in
`/var/lib/fprint`, `/etc/goodix`, `/usr/lib/goodix`, `/usr/local/lib`, or the
path from `GOODIX_ENGINE_DLL_PATH`.

The load log line is:

```
5e0a: Milan biometric matching engine loaded successfully (Milan_v_3.02.00.x)
```

---

## 3. Data flow

### Capture
1. The TLS driver receives an 88x80 16-bit frame (`64` valid columns per row).
2. `capture_raw_frame` hands it to `goodix511_capture_raw_frame`, which keeps
   the last raw frame for verification.
3. `milan_preprocess_frame()` crops to 64x80, applies a 3x3 blur minus an
   11x11 background blur, then RMS-normalises contrast to midpoint 128. This
   is the buffer the Milan engine expects.

### Enroll
1. fprintd calls `enroll`; `goodix511_enroll` initialises the engine and
   `enrolStartEx` (max 12 images).
2. Every raw frame while the action is `ENROLL` is preprocessed and passed to
   `enrolAddImage`. The engine's internal quality gate decides when enough
   images were accepted (progress 100).
3. On progress 100 the driver calls `enrolFinish`/commit, producing a packed
   composite template (roughly 37-40 KiB) and stores it in the fprintd enroll
   print as **`FPI_PRINT_RAW`** (`fpi-data` byte array). This is what fprintd
   persists, so templates survive daemon restarts.
4. Completion is deferred: the driver sets `milan_finish_pending` and does
   **not** call `fpi_device_enroll_complete()` from the USB read callback.
   `goodix511_change_state` intercepts the next `AWAIT_FINGER_ON`, and
   `fpi_image_device_enroll_complete_with_print()` stores the result and
   deactivates. The normal `deactivate_complete -> maybe_complete_action`
   path completes the action. This mirrors upstream and avoids completing an
   action while the image device is still active (the previous SEGV).

### Verify / identify
1. libfprint's image-device code calls the class `match` vfunc
   (`goodix511_verify_match`) for **both** verify and identify when set.
2. The vfunc reads the Milan blob from the template print
   (`fpi-type == FPI_PRINT_RAW`, `fpi-data`), preprocesses the last raw probe
   frame, and calls `identifyImage`/`verify` in the vendor engine.
3. Identify before enrolling another finger uses the same vfunc, so RAW Milan
   prints participate correctly in fprintd's duplicate check.

### Legacy prints
Prints created before Milan (`FPI_PRINT_SIGFM`/`NBIS`) cannot be matched by the
vendor engine. The vfunc fails closed on non-RAW templates; re-enroll those
fingers after switching to the Milan build. Old prints can be removed with
`fprintd-delete "$USER"` or a fresh `/var/lib/fprint` database.

---

## 4. Build

```bash
meson setup build-lutfor-opt --prefix=/opt/lutfor-fprint \
  --libdir=/opt/lutfor-fprint/lib/x86_64-linux-gnu --buildtype=release \
  -Db_lto=true -Ddrivers=goodixtls511 -Dudev_rules=enabled \
  -Dintrospection=false -Dgtk-examples=false -Ddoc=false
ninja -C build-lutfor-opt
ninja -C build-lutfor-opt install     # /opt is owned by the user
systemctl restart fprintd
```

`meson.build` adds `goodix_milan.c` to the `goodixtls511` driver sources.

Requirements: x86-64 (the loader executes an x86-64 PE image), the proprietary
DLL above, and the normal libfprint build deps. The loader runs the DLL in the
fprintd process (no Wine, no sandbox); only load trusted DLLs.

---

## 5. Limitations / notes

- The engine and loader are x86-64 only.
- The vendor DLL is not sandboxed; it runs with fprintd's privileges.
- `score_threshold` and the NBIS/SIGFM algorithms are bypassed for Milan
  matching; the vendor engine makes the accept/reject decision.
- The engine quality gate can reject poor presses (`enrolAddImage` returns
  `0x83`); this is expected and matches the Windows behaviour.
- libfprint still runs SIGFM minutiae extraction on the image path; those
  results are ignored when the Milan `match` vfunc is used.
- Only the 27c6:5117 family (`GF_ST411SEC_APP_12118`) is supported by the
  lutfor511 integration.

---

## 6. Credits

This work builds on other people's work:

- **jitendradara12 / goodix-5e0a contributors** — native PE loader and
  Goodix engine bridge (`libfprint-driver/goodix_milan.c`), from
  <https://github.com/jitendradara12/goodix-5e0a>. The lutfor511 integration
  reuses that approach and adapts it to the 27c6:5117 sensor and libfprint's
  image-device lifecycle.
- **Alexander Meiler**, **Matthieu CHARETTE**, **Natasha England-Elbro** —
  original libfprint `goodixtls` driver (TLS protocol, MCU config, USB flow).
- **libfprint / fprintd** upstream (Benjamin Berg and contributors) — image
  device framework, print storage and the `match`-style plumbing.
- **Lutfor** <lutfor183.du@gmail.com> — DPAPI/`Goodix_Cache.bin` PSK recovery,
  REA decompilation of the Goodix engine and protocol, 27c6:5117 driver
  hardening, Milan integration and packaging.
- **Goodix** — the proprietary Milan engine (`AlgoChicago.dll` /
  `GoodixEngineAdapter.dll`). It is not redistributed here.

License of the source in this repository: LGPL-2.1-or-later, matching
libfprint and the adapted goodix-5e0a loader.
