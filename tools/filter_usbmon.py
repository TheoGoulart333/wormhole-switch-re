#!/usr/bin/env python3
"""Keep only the usbmon records for chosen devices (sanitise a capture).

A `tcpdump -i usbmonN` capture records every device on that bus, so a raw
capture can hold other devices' traffic (input devices, other storage).
Raw captures stay out of the repo.  This writes a new classic pcap with the
same global header and only the records for the requested BUS:DEV pairs,
byte-for-byte and in original order.

    python3 tools/filter_usbmon.py RAW.pcap --device 3:15 -o OUT.pcap

Stdlib only.  Record and usbmon header decoding comes from wormhole_parse.py.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wormhole_parse as wp  # noqa: E402


def parse_bus_dev(text: str) -> tuple[int, int]:
    """Parse a decimal BUS:DEV pair such as '3:15'."""
    bus_s, sep, dev_s = text.partition(":")
    if not sep or not bus_s.isdigit() or not dev_s.isdigit():
        raise argparse.ArgumentTypeError("expected BUS:DEV such as 3:15, got %r" % text)
    return int(bus_s), int(dev_s)


def filter_pcap(src: str | Path, dst: str | Path, devices: set[tuple[int, int]]) -> dict:
    """Copy the records of `src` whose (bus, dev) is in `devices` into `dst`.

    Returns {'total': records read, 'kept': records written,
    'per_device': {'3:15': n, ...}}.  A truncated final record is dropped,
    as in wormhole_parse.read_pcap.
    """
    src, dst = Path(src), Path(dst)
    if src.resolve() == dst.resolve():
        raise ValueError("refusing to overwrite the source capture")
    data = src.read_bytes()
    if len(data) < 24:
        raise ValueError("file too short for a pcap global header")
    endian = wp._pcap_endian(data[:4])
    linktype = struct.unpack_from(endian + "IHHiiii", data, 0)[6]
    if linktype not in (wp.LINKTYPE_USB_LINUX_MMAPPED, wp.LINKTYPE_USB_LINUX_MMAPPED_LEGACY):
        raise ValueError("linktype %d is not usb-linux-mmap (220)" % linktype)

    out = bytearray(data[:24])
    total = 0
    per_device: dict[str, int] = {}
    off = 24
    while off + 16 <= len(data):
        _ts_sec, _ts_usec, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        end = off + 16 + incl
        if end > len(data):
            break  # truncated final record
        total += 1
        raw = data[off + 16:end]
        if len(raw) >= wp.HEADER_LEN:
            bus, dev = raw[12], raw[11]  # usbmon header: devnum at 11, busnum at 12
            if (bus, dev) in devices:
                out += data[off:end]
                key = "%d:%d" % (bus, dev)
                per_device[key] = per_device.get(key, 0) + 1
        off = end
    dst.write_bytes(bytes(out))
    return {"total": total, "kept": sum(per_device.values()), "per_device": per_device}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("pcap", help="raw usbmon pcap (linktype 220)")
    ap.add_argument("--device", metavar="BUS:DEV", action="append", required=True,
                    type=parse_bus_dev, help="device to keep, e.g. 3:15 (repeatable)")
    ap.add_argument("-o", "--output", required=True, metavar="OUT.pcap",
                    help="filtered pcap to write (must differ from PCAP)")
    args = ap.parse_args(argv)
    try:
        res = filter_pcap(args.pcap, args.output, set(args.device))
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    detail = ", ".join("%s: %d" % kv for kv in sorted(res["per_device"].items())) or "none"
    print("kept %d of %d records (%s) -> %s" % (res["kept"], res["total"], detail, args.output))
    if res["kept"] == 0:
        print("warning: no records matched; check BUS:DEV with `lsusb -t`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
