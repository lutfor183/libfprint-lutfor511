# libfprint-lutfor511

Custom Goodix **27c6:5117 / 27c6:5110** fingerprint driver for Linux, built
on top of [libfprint](https://fprint.freedesktop.org/).

Driver id: **`lutfor511`** — co-installs next to the distribution libfprint
without conflicts (installed to `/opt/lutfor-fprint`).

## Goal

Make the Goodix 27c6:5117 sensor on Linux behave like Windows Hello: same TLS
PSK provisioning, same calibrations, and — via the **Milan matcher** —
Goodix's own engine (`AlgoChicago.dll` / `GoodixEngineAdapter.dll`) loaded
natively for Windows-identical preprocess / enroll / identify.

## Install

Prebuilt co-installable Debian packages are in this repo:

```bash
sudo dpkg -i libfprint-2-lutfor-opt_1.94.5-lutfor12_amd64.deb   # when built
sudo systemctl restart fprintd
fprintd-enroll "$USER"
```

Or rebuild from source:

```bash
meson setup build-snappy-opt --prefix=/opt/lutfor-fprint   --libdir=/opt/lutfor-fprint/lib/x86_64-linux-gnu --buildtype=release   -Db_lto=true -Ddrivers=goodixtls511 -Dudev_rules=enabled   -Dintrospection=false -Dgtk-examples=false -Ddoc=false
ninja -C build-snappy-opt && sudo ninja -C build-snappy-opt install
sudo systemctl restart fprintd
```

See [`fix-snappy-coinstall.sh`](fix-snappy-coinstall.sh) for the co-installable
build (does not replace system `libfprint-2-2`).

## Milan matcher (`lutfor12`)

The current source tree adds Goodix's Milan engine as the matcher. This
requires the proprietary DLL (`AlgoChicago.dll`, shipped on Windows as
`GoodixEngineAdapter.dll`) — it is **not** included in this repo. Place it at
`/opt/lutfor-fprint/lib/GoodixEngineAdapter.dll` or set
`GOODIX_ENGINE_DLL_PATH`.

Full details: [`MILAN-ENGINE.md`](MILAN-ENGINE.md) — architecture, data flow,
requirements, limitations, and credits.

## Credits

- Native Goodix engine PE loader / bridge derived from
  **jitendradara12/goodix-5e0a**
  (<https://github.com/jitendradara12/goodix-5e0a>) by its contributors.
- Original `goodixtls` driver: **Alexander Meiler**, **Matthieu CHARETTE**,
  **Natasha England-Elbro**.
- **libfprint / fprintd** upstream (Benjamin Berg and contributors).
- **Lutfor** — PSK/DPAPI recovery, AlgoChicago.dll reverse engineering,
  27c6:5117 driver hardening, Milan integration and packaging.
- **Goodix** — proprietary Milan engine (`AlgoChicago.dll`), not redistributed.

Dev notes: [`PROGRESS.md`](PROGRESS.md).
