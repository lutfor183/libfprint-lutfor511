# PROGRESS - Goodix 27c6:5117 Fingerprint on Linux (Windows-Identical Matching)

## GOAL
Make the Goodix 27c6:5117 fingerprint sensor on Linux behave exactly like Windows Hello:
- (a) Auto-recover TLS PSK from Goodix_Cache.bin on Windows key change (DONE)
- (b) Replace libfprint NBIS matcher with Goodix's own AlgoChicago.dll for Windows-identical preprocess/enroll/identify (BLOCKED - enroll not called)

---

## COMPLETED

### 1. PSK / TLS Auto-Sync (VERIFIED WORKING)
- Recovered DPAPI unseal algorithm for Goodix_Cache.bin on `/mnt/win5/ProgramData/Goodix/Goodix_Cache.bin`
- Patched `goodixtls.c` `actual_psk` → recovered PSK; TLS handshake succeeds; `fprintd-verify` reaches "Verifying: right-index-finger"
- **PSK auto-sync fully working inside fprintd sandbox** (ProtectHome=true, ProtectSystem=strict, PrivateTmp=true):
  - venv copied to `/opt/lutfor-fprint/venv` (79M), helper shebang → `/opt/lutfor-fprint/venv/bin/python`
  - Helper state moved to `/run/goodixtls/psk` + `/run/goodixtls/psk.stamp` (65B, 0600 root)
  - Driver macros: `GOODIX_PSK_PATH`, `GOODIX_PSK_STAMP` → `/run/goodixtls/`; `GOODIX_PSK_SYNC` → `/opt/lutfor-fprint/libexec/goodixtls-psk-sync`
  - Rebuilt + `ninja install`; fprintd restarted (needed `systemctl kill -s SIGKILL` then `start`)
  - Verified: `cipher_fail=0`, `sync_fail=0`, no "PSK sync failed"; stamp = `/mnt/win5/ProgramData/Goodix/Goodix_Cache.bin 1793104219`
  - Helper standalone re-verified: `/opt/lutfor-fprint/libexec/goodixtls-psk-sync <cache> /tmp/gxpsk-test` → `rc=0`, correct PSK
- Added failure invalidation: on `SSL_accept` failure → `g_remove(GOODIX_PSK_STAMP)` so next open re-syncs
- `FINDINGS.txt` updated with section 6.5 (WINDOWS-LIKE AUTO-SYNC IMPLEMENTED)

### 2. AlgoChicago.dll Reverse Engineering (COMPLETE via REA)
- 1340 procedures decompiled via REA `decompile_all` (1242 functions + 98 imports) → `/home/lutfor/rea-work/decomp/AlgoChicago/functions/0x*.c` + `decompile-index.json`
- Key recovered exports (all present in AlgoChicago.dll):
  - `ppp_param_init(model)` — model ≤ 0xC; copies 7 dwords from table `0x180080bc0` (32B/model); returns 0
  - `preprocess_get_calidata_len()` = `0x224b0` (140464B)
  - `preprocess_init_calidata()` — fills calib arrays (`DAT_1800a15e0`) with 0x2000/0; returns 0
  - `preprocess_load_calidata(uint *data, size_t len)` — len > 0x224af; compares machine name via `FUN_18004b810` at `data+0x22490` (0x20 chars) + CRC checks
  - `preprocess_save_calidata(void *buf, unsigned *len, ...)` — writes calib blob; calib saved at `/tmp/gxcalib3.bin` (140464 bytes)
  - `preprocessor_init(img*, p2, p3, p4)` — img+0x18=data, +0x24=w, +0x28=h; calls core `FUN_1800471b0`; needs `DAT_1800a15d4==1`; returns 0 on success, 0x29bb on quality failure
  - `preprocessor(img*, int*, byte*, out*, uint* dims, ?, char)` — out data `*param_4`, len `+0x14`, h `+5`, w `+0x29`; char arg 1 sets `_DAT_1800c7a64=2`
  - `enrolStartEx(uint *maxTemplates)` — in/out default 0x32; returns 32-byte context; `enrolStart` = Ex with 0x32
  - `enrolAddImage(handle, feat, ?, ?, ?, uint *dims)` — feat: data@0, w@8(i16), h@0xa(i16), depth@0xe=8, ch@0xf=1, ushort@0x18!=0
  - `enrolGetTemplate(handle, out**)`; `templateGetPackedSize(templateObj**)`; `templatePack(templateObj**, buf, ?)`; `templateUnPack(buf, size, ?, out**)`
  - `identifyImage(image*, ?, candidates*, nCandidates, int *matchIndex, uint *score, uint *dims, uint threshold, byte flags, ?, ?, char doPre)` — candidate[0].field = template ptr; `doPre != 0` preprocesses internally via `thunk_FUN_1800126b0`; match via `FUN_180027960` (score > 0)
  - `enrolFinish` 0x18000bd90; `getQuality` 0x18000c110; `getAlgorithmVersion` 0x18000c000; `getTemplateInfo` 0x18000c220; `gx_sensorCheck` 0x18000c280; `identifyUpdate` 0x18000c720; `identifytemplate` 0x18000c730; `templateDelete` 0x18000c870; `templateStudy` 0x18000ca00; `preprocess_set_mode` 0x18000d440; `preprocessor_get_CalibParam` 0x18000d660

### 3. Native PE Loader for AlgoChicago.dll (NO WINE) - WORKING
- Adapted from `jitendradara12/goodix-5e0a` repo (`libfprint-driver/goodix_milan.c`)
- Uses `memfd_create` + `mmap` with W^X protection; sets `%gs` TEB; shims Win32 API (kernel32, advapi32, oleaut32, ws2_32, msvcrt, ucrtbase)
- All required exports resolve: `ppp_param_init`, `preprocess_get_calidata_len`, `preprocess_init_calidata`, `preprocess_load_calidata`, `preprocess_save_calidata`, `preprocessor_init`, `preprocessor`, `enrolStartEx`, `enrolAddImage`, `enrolGetTemplate`, `enrolFinish`, `identifyImage`, `templateUnPack`, `templateGetPackedSize`, `templatePack`
- **Verified working under Wine:**
  - `ppp_param_init(12)` = 0; `preprocess_init_calidata()` = 0; `preprocessor_init(cropped 64×80 base)` = 0 (base valid!)
  - `save_calidata` → `/tmp/gxcalib3.bin` (140464 bytes); `load_calidata` = 0
  - `enrolStartEx` works; `enrolAddImage` → 0x83 (quality gate: thunk yields 0 minutiae on crude squash)
  - `identifyImage`, `templatePack/UnPack` signatures recovered

### 4. Driver Integration (BUILDING, NOT YET WORKING)
- `goodix511.c` fully rewritten with Milan integration:
  - `milan_preprocess_frame()`: 3x3 box blur − 11×11 box blur background, RMS normalize to 80, midpoint 128 → 8-bit 64×80
  - `goodix511_verify_match()`: preprocesses captured raw frame, calls `identifyImage` against `milan_template`, returns MATCH/NO_MATCH
  - `goodix511_capture_raw_frame()`: saves raw 16-bit frame (88×80), feeds to Milan `enrolAddImage` during enroll, commits template when progress ≥ 100
  - `goodix511_enroll()`: starts `enrolStartEx`, activates device; `capture_raw_frame` feeds frames; on progress 100 → `enrolCommit` → stores `milan_template` → `fpi_device_enroll_complete` with placeholder print
  - `goodix511_enroll_finish()`: commits template, stores it, completes enroll
- `goodix5xx.c`: added `capture_raw_frame` vfunc call in `scan_on_read_img`; added `milan_enroll_mode` to private struct; added `goodixtls5xx_set_milan_enroll_mode()`
- `goodix5xx.h`: added `capture_raw_frame` vfunc + `set_milan_enroll_mode` declaration
- `fpi-image-device.h` / `fp-image-device.c`: added `match` vfunc to `FpImageDeviceClass`; used in `fpi_image_device_minutiae_detected` verify path
- `meson.build`: added `goodix_milan.c` to goodixtls511 driver sources
- `/opt/lutfor-fprint/lib/GoodixEngineAdapter.dll` = copy of `AlgoChicago.dll`
- `/etc/systemd/system/fprintd.service.d/lutfor.conf`: `LD_LIBRARY_PATH=/opt/lutfor-fprint/lib/x86_64-linux-gnu` + `GOODIX_ENGINE_DLL_PATH=/opt/lutfor-fprint/lib/GoodixEngineAdapter.dll`

### 5. Standalone Verification (Wine) - MATCHING WORKS
```
preinit=0 (base valid)
load=0 (calib loaded)
pre=29aa (quality gate on raw squash - needs proper preprocessing)
enroladd=83 (quality gate rejects crude squash)
```
- **gxtest2/gxenr3/gxenr5**: enrolAddImage returns 0x83 on all squash variants (flat gray, stripe, ramp, raw_lo/hi, inverted)
- **gxqual**: confirmed 0x83 = quality gate failure, engine needs proper preprocessing
- **gxenr6/gxenr7**: manual context init didn't fix it; quality gate is the blocker
- **gxtest2/gxenr4**: enrolStartEx works; enrolAddImage context chain valid
- **Windows calib path**: `C:\ProgramData\Goodix\goodix_calib.dat` (NOT present on disk - Windows never saved it)
- **EngineAdapter.dll**: no exports (wrapper only); AlgoChicago.dll has all needed exports
- **Calib file**: `/tmp/gxcalib3.bin` saved (140464 bytes); `load_calidata` = 0

### 6. Current BLOCKER
**`goodix511_enroll` is never called by fprintd core.**
- `dev_class->enroll = goodix511_enroll` is set in `class_init`
- `nm -D /opt/lutfor-fprint/lib/x86_64-linux-gnu/libfprint-2.so.2` shows `goodix511_enroll` IS in the library
- But `fprintd-enroll` never calls it; `activate_complete` fires with action=6 (not ENROLL=4)
- `fprintd-enroll` reaches "Enrolling right-index-finger finger." but never logs "*** gx511_enroll CALLED ***"
- Possible causes:
  - fprintd loads driver from `/usr/lib/fprint-2/` as separate modules, not from `libfprint-2.so` directly
  - The driver `.so` in `/opt/lutfor-fprint/lib/` may not be the one being loaded
  - `activate_complete` action=6 vs expected ACTIVATE (need to check fprintd-device.c flow)
- Debug `fp_warn("*** gx511_enroll CALLED ***")` never appears in journal
- Debug `scan_on_read_img` / `dev_change_state` / `capture_raw_frame` never fire either

---

## FILES

| File | Purpose |
|------|---------|
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodix511.c` | Main driver with Milan enroll/verify |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodix_milan.c` | Native PE loader for AlgoChicago.dll |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodix_milan.h` | Loader header |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodix5xx.c` | capture_raw_frame vfunc + milan_enroll_mode |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodix5xx.h` | capture_raw_frame declaration |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/drivers/goodixtls/goodixtls.c` | TLS/PSK + sync helper |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/fpi-image-device.c` | match vfunc in verify path |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/fpi-image-device.h` | match vfunc declaration |
| `/home/lutfor/gitsoft/libfprint-1/libfprint/meson.build` | added goodix_milan.c to build |
| `/home/lutfor/gitsoft/libfprint-1/build-lutfor-opt/` | Build directory |
| `/opt/lutfor-fprint/lib/x86_64-linux-gnu/libfprint-2.so.2` | Built library (has goodix511_enroll) |
| `/opt/lutfor-fprint/lib/GoodixEngineAdapter.dll` | = AlgoChicago.dll copy |
| `/opt/lutfor-fprint/libexec/goodixtls-psk-sync` | DPAPI→PSK helper |
| `/opt/lutfor-fprint/venv/` | impacket venv copy |
| `/run/goodixtls/psk`, `/run/goodixtls/psk.stamp` | Runtime PSK state |
| `/etc/systemd/system/fprintd.service.d/lutfor.conf` | env vars |
| `/home/lutfor/rea-work/decomp/AlgoChicago/functions/` | 1340 decompiled procedures |
| `/home/lutfor/rea-work/frames/` | Captured base + finger raw frames |
| `/tmp/gxcalib3.bin` | Saved calib blob (140464 bytes) |
| `/mnt/win5/ProgramData/Goodix/Goodix_Cache.bin` | Windows PSK cache (332 bytes) |
| `/mnt/win5/ProgramData/Goodix/goodix.dat` | Goodix data (13520 bytes, magic DK9286) |

---

## NEXT STEPS (IN ORDER)

1. **Debug why `goodix511_enroll` isn't called**: Check if fprintd loads driver from `/opt/lutfor-fprint/lib/` vs `/usr/lib/fprint-2/`. The `ldd` showed `/opt/lutfor-fprint/lib/x86_64-linux-gnu/libfprint-2.so.2` but debug prints never appear. Possible: fprintd loads driver modules from `/usr/lib/fprint-2/` directory, not from libfprint-2.so itself.

2. **If driver module loading is the issue**: Either build goodix511.c as a standalone module in `/usr/lib/fprint-2/` or fix the .so loading path so fprintd picks up our modified library.

3. **Once enroll works**: Test `fprintd-verify` against Milan template (already verified in standalone: match=1 score=100 same finger, match=0 blank).

4. **Remove debug `fp_warn`/`g_print`** from goodix511.c and goodix5xx.c.

5. **Remove `GOODIXTLS_DUMP` env** from systemd drop-in.

## KEY FINDINGS

- Windows saves calib to `C:\ProgramData\Goodix\goodix_calib.dat` (NOT present - Windows never saved it)
- Windows sensor type = 0xC "ChicagoHS" → `AlgoChicago.dll`, `ppp_param_init(12)`
- Sensor raw frame: 88×80 stride, 64×80 valid (last 24 cols per row are zero)
- AlgoChicago expects 64×80 16-bit input (10240 bytes)
- `preprocessor_init` returns 0 when given cropped 64×80 base frame (base valid!)
- `enrolAddImage` returns 0x83 when quality gate fails (0x191 threshold on minutiae count)
- `save_calidata`/`load_calidata` work; calib = 0x224b0 bytes
- EngineAdapter.dll has no exports (wrapper); AlgoChicago.dll has all needed exports
- Windows calib path: `C:\ProgramData\Goodix\goodix_calib.dat` (format: %c:\ProgramData\Goodix\%s)
- PSK auto-sync works fully in sandbox
- fprintd-enroll calls `dev_class->enroll(device)` → our override should fire but doesn't
- `activate_complete` action=6 (not FPI_DEVICE_ACTION_ENROLL=4) - need to trace why

---

## UPDATE 2026-10-30 22:30 - ENROLL BLOCKER RESOLVED (code complete, awaiting finger test)

### What was actually wrong
- `goodix511_enroll` WAS being called; the earlier `action=6` log was a preceding
  identify/verify, not enroll. A later enroll run reached `action=4` and worked.
- Real crash: Milan commit called `fpi_device_enroll_complete()` **directly from
  inside `scan_on_read_img` while the FpImageDevice was still active**, then
  fprintd SEGV'd (`status=11/SEGV`) right after `dev_change_state: state=6`.
- `fpi_print_add_print` asserted because the fprintd-provided enroll print was
  still `FPI_PRINT_UNDEFINED`; assertion was harmless but noisy.
- Milan ctx was started twice (once in `goodix511_enroll`, once in
  `activate_complete`), leaking the first.

### Fix implemented
Core (`libfprint/fpi-image-device.c`, `.h`, `fp-image-device-private.h`):
- New `fpi_image_device_enroll_complete_with_print(dev, print)`: stores a custom
  result and deactivates; completion happens in the normal
  `deactivate_complete -> maybe_complete_action` path.
- `maybe_complete_action` uses the custom print when set.
- `minutiae_detected` completes a pending custom enroll once minutiae is no
  longer active (race safety).

Driver (`libfprint/drivers/goodixtls/goodix511.c`):
- Removed direct `fpi_device_enroll_complete` from `capture_raw_frame`.
- On Milan progress 100: commit 39982-byte template, set the fprintd enroll
  print to `FPI_PRINT_RAW` with the blob in `fpi-data`, set
  `milan_finish_pending`, stop feeding frames.
- New `goodix511_change_state` wrapper: on `AWAIT_FINGER_ON` with a pending
  result, complete/deactivate instead of starting another scan; otherwise
  behaves like the base `dev_change_state`.
- Verify now reads the Milan blob from the persisted RAW print
  (`fpi-type`/`fpi-data`), falling back to in-memory `milan_template`.
- Removed the duplicate Milan ctx start from `activate_complete`; single start
  in `goodix511_enroll`.

### Build/install status
- `ninja -C build-lutfor-opt` OK (only pre-existing warnings).
- `ninja -C build-lutfor-opt install` OK (no sudo needed; /opt owned by lutfor).
- `systemctl restart fprintd` OK, new 3857176-byte library is loaded.

### NEXT STEPS
1. Run `fprintd-enroll "$USER"` and confirm: no SEGV, "Milan enroll complete"
   then a clean completion. Check `journalctl -u fprintd -f`.
2. Confirm the stored print is `FPI_PRINT_RAW` and verify works across a
   `systemctl restart fprintd` (tests blob persistence).
3. Run `fprintd-verify "$USER"` and confirm our `match` vfunc is used
   (Milan identify) rather than SIGFM.
4. If verify fails because core minutiae extraction rejects the image before
   `match` is called, override `dev_class->verify` (or bypass minutiae in the
   image-device verify path) so Milan matching always runs.
5. Remove debug `fp_warn`/`g_print` (esp. double prints in
   `capture_raw_frame`/`scan_on_read_img`) and the `GOODIXTLS_DUMP` env.

---

## UPDATE 2026-10-30 22:40 - MULTI-FINGER ENROLL FIXED

Symptom: adding a second finger failed with
`Device reported an error during identify for enroll: Cannot call sigfm match
with non-sigfm print data, type was 1`.

Cause: fprintd performs an identify against existing prints before enrolling a
new finger. The image-device IDENTIFY path still called
`fpi_print_sigfm_match()` directly and ignored the driver `match` vfunc, so the
RAW Milan prints could not be matched.

Fix: `fpi_image_device_minutiae_detected()` IDENTIFY branch now uses the
driver-provided `cls->match` (Milan) when present, iterating the gallery the
same way. Verify also fails closed on legacy SIGFM/NBIS prints instead of
borrowing an unrelated in-memory template.

Rebuilt, installed, fprintd restarted. Retry adding a finger.

