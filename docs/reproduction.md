# Reproduction

All commands assume an x86_64 Linux host with the Wormhole plugged into one USB port. Bus numbers differ per host — confirm with `lsusb` first.

## 1. Enumerate

```sh
lsusb
lsusb -t
lsusb -v -d 0711:2211          # expect: 3 interfaces (1× Mass Storage, 2× HID)
for f in /sys/bus/usb/devices/*:1.*/bInterfaceClass; do
  echo "$f: $(cat $f)"
done
# expect: 08 (Mass Storage), 03 (HID), 03 (HID) — no 0E (Video)
```

If `lsusb -v` says `** UNAVAILABLE **` for HID report descriptors, read them from sysfs:

```sh
for n in /sys/class/hidraw/hidraw*/; do
  echo "== $n =="
  python3 -c "d=open('$n/device/report_descriptor','rb').read(); print(len(d), d.hex())"
done
```

## 2. SCSI identities

```sh
lsblk -o NAME,PATH,TRAN,SIZE,MOUNTPOINT /dev/srX
ls -l /sys/block/srX/device/{vendor,model,rev}
# expect: vendor j5create, model WormholeSwitch, rev 2.00

sg_inq /dev/sgX
sg_readcap /dev/sgX          # expect: Last LBA 1592, 2048 B
sg_readcap --16 /dev/sgX     # expect: Illegal Request / Invalid opcode on this firmware
sg_readcap /dev/sgX -H       # raw: 00 00 06 38 00 00 08 00
cat /sys/block/srX/size      # observe: 31744 (15.5 MiB) — vs 3.1 MiB above
```

Mount (automount handles it as `/media/$USER/WORMHOLE`):

```sh
sudo mkdir -p /tmp/wormhole_mnt
sudo mount -o ro /dev/srX /tmp/wormhole_mnt
ls -lR /tmp/wormhole_mnt
# verify hashes: see docs/iso-payload.md
```

## 3. HID identities

```sh
cat /proc/bus/input/devices | grep -A6 Wormhole
# expect: j5create WormholeSwitch, two entries (mouse + sysrq/kbd)
ls -l /dev/hidraw*
cat /sys/class/hidraw/<n>/device/input/*/name
```

## 4. USB capture (usbmon)

```sh
sudo modprobe usbmon
sudo tcpdump -D | grep usbmon     # list usbmonN interfaces
# Bus 3 in the log in docs/capture-log.md; adjust to your bus:
sudo tcpdump -i usbmon3 -w wormhole.pcap &
# in another terminal, interact:
sg_inq /dev/sgX
sg_readcap /dev/sgX
dd if=/dev/srX of=/tmp/out.bin bs=512 count=16
# stop:
sudo pkill tcpdump
capinfos wormhole.pcap
tcpdump -r wormhole.pcap -c 20 -v -X
```

CBW signature is `55 53 42 43` (`USBC`), CDB starts at byte 15. E.g. LOG SENSE is `4A 01 00 00 10 ...`, REQUEST SENSE is `03 00 00 00 12 00`, INQUIRY is `12 00 00 00 24 00`, READ CAPACITY(10) is `25 00 00 00 00 00`.

## 5. REA analysis (target-free)

Copy the ISO to a writable scratch dir (ISO mount is read-only and non-writable — `chmod -R u+w` after copy or copy to a new dir):

```sh
mkdir -p /tmp/wormhole && sudo cp -a /media/$USER/WORMHOLE/. /tmp/wormhole/
```

Then, via the `reverse-engineer-anything` skill:

- `inspect_pe_imports` / `inspect_pe_resources` / `inspect_pe_certificates` on `SKLoader.exe`
- Carve the DLL resource (offset 70520, size 104488 in that sample) and run `inspect_pe_imports` again
- `open_binary` on `GoBridgeDemon` (Mach-O) for deep analysis (requires aligned Ghidra)

Prerequisites to enable the blocked paths:

```sh
# tshark for REA pcap tools (Wireshark 4.x)
sudo apt install wireshark-common

# UPX for embedded DLL
sudo apt install upx-u

# Ghidra 12.1.x for REA deep analysis (REA 6.8.0 verifies 12.1.4)
# Install side-by-side, e.g. /opt/ghidra_12.1.4_PUBLIC, then point REA at it:
#   sudo ln -sfn /opt/ghidra_12.1.4_PUBLIC/ghidraRun /usr/local/bin/ghidra
# (REA discovers Ghidra via the `ghidra` launcher on PATH), or per-invocation:
#   GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC rea doctor --provider ghidra
# Verify: rea doctor --provider ghidra  # healthy, version 12.1.4
```

## 6. Second-machine bridge test

Plug the other end into a second PC, leave both ends connected, then:

1. Without running Wormhole software on either side: re-capture 30 s of idle usbmon — expect only kernel LOG SENSE / REQUEST SENSE pairs, 0 HID interrupts (as in `docs/capture-log.md`).
2. Run Wormhole/GoBridge on both sides (per ISO), move the mouse or drag a file, and capture again.
3. Compare: HID interrupt completions on the local `event*` device and Bulk/CSW/file-transfer traffic that appears only during the session.

Record what you see when you do this — the peer-to-peer data channel is internal, so local capture can only show its HID/SCSI *effects*.
