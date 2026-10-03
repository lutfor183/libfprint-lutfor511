#!/bin/bash
# fix-snappy-coinstall.sh - run IN /home/lutfor/gitsoft/libfprint-1
# Patches lutfor511 driver for snappy verify (like Windows) + rebuilds co-installable to /opt
# Does NOT replace system libfprint-2-2 (fixes conflict). Double-checked on 2026-09-15.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
BUILD="build-snappy-opt"
PREFIX="/opt/lutfor-fprint"
PKGNAME="libfprint-2-lutfor-opt"
VERSION="1.94.5-lutfor10"

echo "=== 1. Backup originals ==="
cp -n libfprint/drivers/goodixtls/goodix511.c libfprint/drivers/goodixtls/goodix511.c.bak-$(date +%F) || true
cp -n libfprint/drivers/goodixtls/goodix.c libfprint/drivers/goodixtls/goodix.c.bak-$(date +%F) || true

echo "=== 2. Apply snappy patch (idempotent) ==="
# goodix511.c:20 ->5 for reset/idle, 100->200 for powerdown scan freq (faster wake)
sed -i 's/goodix_send_reset (dev, TRUE, 20,/goodix_send_reset (dev, TRUE, 5,/g' libfprint/drivers/goodixtls/goodix511.c
sed -i 's/goodix_send_mcu_switch_to_idle_mode (dev, 20,/goodix_send_mcu_switch_to_idle_mode (dev, 5,/g' libfprint/drivers/goodixtls/goodix511.c
sed -i 's/goodix_send_set_powerdown_scan_frequency (/goodix_send_set_powerdown_scan_frequency (/g; s/dev, 100,/dev, 200,/g' libfprint/drivers/goodixtls/goodix511.c

# goodix.c: tls_successfully_established timeout 10 -> 5 (was always timing out)
sed -i 's/GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,/GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,/g' libfprint/drivers/goodixtls/goodix.c
# patch the specific 10ms timeout line (goodix.c:1053)
sed -i 's/TRUE,$/TRUE,/; s/10, FALSE, goodix_receive_none/5, FALSE, goodix_receive_none/' libfprint/drivers/goodixtls/goodix.c || true
# safer explicit:
grep -q "5, FALSE, goodix_receive_none" libfprint/drivers/goodixtls/goodix.c || sed -i 's/10, FALSE, goodix_receive_none/5, FALSE, goodix_receive_none/g' libfprint/drivers/goodixtls/goodix.c

echo "Patched. Diff:"
git diff --stat 2>/dev/null || diff -u libfprint/drivers/goodixtls/goodix511.c.bak-* libfprint/drivers/goodixtls/goodix511.c | head -n 80 || true
grep -n "goodix_send_reset\|goodix_send_mcu_switch_to_idle\|powerdown_scan_frequency\|TLS_SUCCESSFULLY" libfprint/drivers/goodixtls/goodix511.c libfprint/drivers/goodixtls/goodix.c | head -n 20

echo "=== 3. Clean old snappy build ==="
rm -rf "$BUILD"
meson setup "$BUILD" \
  --prefix="$PREFIX" \
  --libdir="$PREFIX/lib/x86_64-linux-gnu" \
  --buildtype=release \
  -Db_lto=true \
  -Dc_args="-O3 -march=native -DNDEBUG -flto" \
  -Dcpp_args="-O3 -march=native -DNDEBUG -flto" \
  -Db_ndebug=true \
  -Dstrip=true \
  -Ddrivers=goodixtls511 \
  -Dudev_rules=enabled \
  -Dintrospection=false \
  -Dgtk-examples=false \
  -Ddoc=false

echo "=== 4. Build (ninja) ==="
ninja -C "$BUILD" -j$(nproc)

echo "=== 5. Install to $PREFIX (co-installable, no conflict) ==="
sudo ninja -C "$BUILD" install

echo "=== 6. Fix conflict: ld.so + systemd override (already done for lutfor4, re-ensure) ==="
echo "$PREFIX/lib/x86_64-linux-gnu" | sudo tee /etc/ld.so.conf.d/lutfor-fprint.conf >/dev/null
sudo ldconfig
sudo mkdir -p /etc/systemd/system/fprintd.service.d
printf "[Service]\nEnvironment=LD_LIBRARY_PATH=%s/lib/x86_64-linux-gnu\n" "$PREFIX" | sudo tee /etc/systemd/system/fprintd.service.d/lutfor.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart fprintd || true

echo "=== 7. Verify co-install (must NOT have Conflicts/Replaces) ==="
echo "System lib still installed:"
dpkg -l | grep -E "libfprint-2-2|libfprint-2-tod" | head
echo "Custom lib:"
ls -lh "$PREFIX/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0"
ldd /usr/libexec/fprintd 2>&1 | grep -E "libfprint|not found"
echo "fprintd should show /opt/lutfor-fprint:"
ldd /usr/libexec/fprintd | grep libfprint || LD_LIBRARY_PATH="$PREFIX/lib/x86_64-linux-gnu" ldd /usr/libexec/fprintd | grep libfprint
systemctl cat fprintd | grep -A2 LD_LIBRARY_PATH || true

# optional deb with NO Conflicts/Replaces (for backup)
echo "=== 8. Optional: build deb without Conflicts (for dpkg -i reuse) ==="
rm -rf /tmp/pkg-$PKGNAME
DESTDIR=/tmp/pkg-$PKGNAME ninja -C "$BUILD" install
mkdir -p /tmp/pkg-$PKGNAME/DEBIAN
cat > /tmp/pkg-$PKGNAME/DEBIAN/control <<EOF
Package: $PKGNAME
Version: $VERSION
Section: libs
Priority: optional
Architecture: amd64
Maintainer: Lutfor <lutfor183.du@gmail.com>
Depends: libglib2.0-0, libgusb2, libssl3, libpixman-1-0, libgudev-1.0-0, libnss3
Description: libfprint Lutfor custom Goodix 27c6:5117 driver (co-installable /opt)
 Custom libfprint with reverse-engineered TLS PSK for Goodix 27c6:5117/5110
 Driver ID lutfor511. Installs to /opt/lutfor-fprint, does NOT conflict with
 libfprint-2-2 or fprintd. systemd override makes fprintd auto-use it.
 Survives apt upgrade/reinstall - just dpkg -i again if needed.
EOF
cat /tmp/pkg-$PKGNAME/DEBIAN/control
dpkg-deb --build /tmp/pkg-$PKGNAME "$ROOT/${PKGNAME}_${VERSION}_amd64.deb"
echo "Built $ROOT/${PKGNAME}_${VERSION}_amd64.deb (no Conflicts/Replaces)"
dpkg-deb -f "$ROOT/${PKGNAME}_${VERSION}_amd64.deb" Package Version Depends Conflicts Replaces 2>&1 | head

echo "=== 9. Power fix: cool sleep (auto + no wakeup, NOT on/-1) ==="
# lutfor10: old on/-1 kept sensor hot in sleep. Use auto/2000/disabled/persist=1 + sleep hook.
sudo cp heat-fix/99-goodix511-power.rules /etc/udev/rules.d/99-goodix511-power.rules
sudo cp heat-fix/goodix511-powersave /lib/systemd/system-sleep/goodix511-powersave
sudo chmod +x /lib/systemd/system-sleep/goodix511-powersave
sudo udevadm control --reload && sudo udevadm trigger || true

echo "=== 10. Self-test ==="
fprintd-list "$USER" 2>&1 | head -n 20 || true
timeout 8 bash -c 'time fprintd-verify 2>&1 || true' | head -n 40 || true
echo "=== Done. Verify snappy: time fprintd-verify (should be <1s after first touch) ==="
echo "If slow, check: journalctl -u fprintd -f and G_MESSAGES_DEBUG=all LIBFPRINT_DEBUG=1 fprintd-verify"
