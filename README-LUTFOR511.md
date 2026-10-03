# Lutfor Goodix 511 TLS driver for libfprint (`lutfor511`)

Custom libfprint build carrying a reverse-engineered driver for the
**Goodix 27c6:5117 / 27c6:5110** fingerprint reader
(GF_ST411SEC_APP_12118 firmware family).

Driver id is **`lutfor511`** (not `goodixtls511`), so it co-installs next to
the distribution libfprint without conflicts.

## What's custom vs upstream libfprint

- TLS PSK + MCU config for 27c6:5117/5110 (`goodix511.h`, `goodixtls.c`).
- Reliability hardening in `libfprint/drivers/goodixtls/`:
  frame validation, reassembly of coalesced USB packets, TLS record drain,
  read-error backoff, shutdown ordering, exact image-size checks.
- Responsiveness: calibration reuse (one capture per tap instead of two),
  skip static FW/PSK/OTP re-query after first activation, cached `SSL_CTX`,
  patient capture timeout. Powerdown scan frequency stays at the gentle
  default (`100`).
- PSK bytes, cipher suite (`ALL`), TLS 1.2 pinning and protocol bytes are
  untouched — provisioning behavior is identical to the working baseline.

See `git log` / `git diff` for the full change history.

## Install on Zorin OS / Ubuntu (fresh machine)

```bash
sudo dpkg -i libfprint-2-lutfor-opt_1.94.5-lutfor10_amd64.deb
sudo systemctl restart fprintd
fprintd-enroll "$USER"   # ~5-10 taps
fprintd-verify "$USER"   # tap to test
```

The package installs to `/opt/lutfor-fprint` (never touches system
libfprint), registers `ld.so`, installs a systemd override so `fprintd`
loads this build, and adds a udev rule with USB autosuspend `auto/2000` + `wakeup=disabled` + `persist=1`, plus a systemd sleep hook that stops `fprintd` pre-sleep and resets USB post-resume. Old `control=on` kept the sensor hot in hibernate — fixed in lutfor10.

`apt upgrade` of the distro `libfprint-2-2` is safe; just re-run
`sudo systemctl restart fprintd` if auth feels stale afterwards.

## Rebuild from source

```bash
meson setup build-snappy-opt --prefix=/opt/lutfor-fprint \
  --libdir=/opt/lutfor-fprint/lib/x86_64-linux-gnu --buildtype=release \
  -Db_lto=true -Ddrivers=goodixtls511 -Dudev_rules=enabled \
  -Dintrospection=false -Dgtk-examples=false -Ddoc=false
ninja -C build-snappy-opt
```

## Troubleshooting

- `Device was already claimed`: close Settings → Fingerprint, then retry.
  The GUI holds the device claim exclusively.
- `Command timed out: 0x00` at activation: known firmware quirk — NOP is
  fire-and-forget on 5117 (no ACK); the driver already handles this.
- Logs: `journalctl -u fprintd --since "10 min ago"`.
- Enroll each finger twice at different angles if multi-finger matching
  feels weak (matcher-side, `sigfm` threshold is fixed).

## Maintainer

Lutfor <lutfor183.du@gmail.com> — protocol/TLS key reverse engineering,
driver tuning and packaging.

## Peaceful multi-finger use (lutfor7 tuning)
- lutfor10: threshold `20` (was `28` in lutfor9): forgiving for tiny 64x80 press sensor, faster accept. Power: cool-sleep fix (auto/2000, no wakeup, sleep hook) — no more hot sensor in suspend/hibernate.
- Threshold history `28` (was `24`): stricter, less finger-to-finger false accept on 64x80 sensor. If taps reject too often, press firmer/centered, don't lower it first.
- Calibration `5 uses / 30s` (was `8 / 60s`): fresher baseline per finger, still 1 capture per tap. Fixes cross-finger bleed that caused 70/72 noisy 24B reports.
- Workflow: `rm -rf` stale DB once -> enroll right-index alone -> `fprintd-verify` until <1s -> then add 2nd finger at 2 angles. Never enroll same finger on Windows + Linux (template master = one OS only).
- `Device already claimed`: close Settings Fingerprint GUI, then `fprintd-enroll`. Keep autosuspend off via `99-goodix511-power.rules`.
