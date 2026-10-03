#!/bin/bash
set -e
echo "[1/4] installing fixed udev rule..."
sudo cp 99-goodix511-power.rules /etc/udev/rules.d/99-goodix511-power.rules
echo "[2/4] installing sleep hook..."
sudo cp goodix511-powersave /lib/systemd/system-sleep/goodix511-powersave
sudo chmod +x /lib/systemd/system-sleep/goodix511-powersave
echo "[3/4] reloading udev + applying now..."
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 || true
for d in /sys/bus/usb/devices/*; do
  if [ -f "$d/idVendor" ] && [ "$(cat "$d/idVendor")" = "27c6" ] && [ "$(cat "$d/idProduct")" = "5117" ]; then
    echo "found $d, setting auto/2000/disabled/persist=1"
    echo auto | sudo tee "$d/power/control" >/dev/null || true
    echo 2000 | sudo tee "$d/power/autosuspend_delay_ms" >/dev/null || true
    echo disabled | sudo tee "$d/power/wakeup" >/dev/null || true
    echo 1 | sudo tee "$d/power/persist" >/dev/null || true
    cat "$d/power/control" "$d/power/runtime_status" || true
  fi
done
echo "[4/4] done. Test: sleep 5s idle -> runtime_status should go suspended, sensor cold."
echo "Then: systemctl suspend, resume, fprintd-verify should still work."
