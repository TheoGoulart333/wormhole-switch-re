#!/usr/bin/env python3
"""Tests for tools/filter_usbmon.py.

Run from the repo root, stdlib only:

    python3 -m unittest tools.test_filter_usbmon -v
    # or
    python3 tools/test_filter_usbmon.py

Everything here is synthetic: the raw live captures are kept out of the repo.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import filter_usbmon as fu  # noqa: E402
import wormhole_parse as wp  # noqa: E402


def _record(bus: int, dev: int, payload: bytes = b"") -> bytes:
    """One usb-linux-mmap record: 64-byte usbmon header plus payload."""
    hdr = bytearray(wp.HEADER_LEN)
    hdr[8] = ord("C")
    hdr[9] = 1        # interrupt transfer
    hdr[10] = 0x83    # EP3 IN
    hdr[11] = dev
    hdr[12] = bus
    struct.pack_into("<II", hdr, 32, len(payload), len(payload))  # length, data_len
    return bytes(hdr) + payload


def _pcap(records: list[bytes], linktype: int = 220) -> bytes:
    out = bytearray(struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for i, rec in enumerate(records):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(rec), len(rec)) + rec
    return bytes(out)


class TestFilterPcap(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_keeps_only_requested_device_in_order(self):
        recs = [
            _record(3, 15, b"\x01\x02"),
            _record(3, 7, b"\x02" * 9),
            _record(3, 15, b"\x03"),
            _record(3, 14, b"USBC"),
            _record(1, 15, b"\x04"),  # same devnum on another bus: must not match
        ]
        dst = self.dir / "out.pcap"
        res = fu.filter_pcap(self._write("raw.pcap", _pcap(recs)), dst, {(3, 15)})
        self.assertEqual(res["total"], 5)
        self.assertEqual(res["kept"], 2)
        self.assertEqual(res["per_device"], {"3:15": 2})
        out = wp.read_pcap(dst)
        self.assertEqual([p.payload for p in out.packets], [b"\x01\x02", b"\x03"])
        self.assertTrue(all((p.bus, p.dev) == (3, 15) for p in out.packets))
        self.assertEqual(len(dst.read_bytes()), 24 + sum(16 + len(recs[i]) for i in (0, 2)))

    def test_multiple_devices_are_kept(self):
        recs = [_record(3, 15, b"a"), _record(3, 7, b"b"), _record(3, 14, b"c")]
        res = fu.filter_pcap(self._write("raw.pcap", _pcap(recs)), self.dir / "out.pcap",
                             {(3, 15), (3, 7)})
        self.assertEqual(res["per_device"], {"3:15": 1, "3:7": 1})

    def test_refuses_to_overwrite_source(self):
        src = self._write("raw.pcap", _pcap([_record(3, 15, b"x")]))
        before = src.read_bytes()
        with self.assertRaises(ValueError):
            fu.filter_pcap(src, src, {(3, 15)})
        self.assertEqual(src.read_bytes(), before)

    def test_rejects_other_linktype(self):
        src = self._write("eth.pcap", _pcap([b"\x00" * 64], linktype=1))
        with self.assertRaises(ValueError):
            fu.filter_pcap(src, self.dir / "out.pcap", {(3, 15)})

    def test_rejects_non_pcap(self):
        src = self._write("junk.bin", b"not a capture, just some text here")
        with self.assertRaises(ValueError):
            fu.filter_pcap(src, self.dir / "out.pcap", {(3, 15)})

    def test_truncated_final_record_is_dropped(self):
        cut = _pcap([_record(3, 15, b"ok")]) + struct.pack("<IIII", 1, 0, 200, 200) + b"\x00" * 10
        res = fu.filter_pcap(self._write("cut.pcap", cut), self.dir / "out.pcap", {(3, 15)})
        self.assertEqual((res["total"], res["kept"]), (1, 1))


class TestParseBusDev(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(fu.parse_bus_dev("3:15"), (3, 15))

    def test_invalid(self):
        for bad in ("3", "x:15", "3:", ":15", "3:-1"):
            with self.subTest(bad=bad), self.assertRaises(argparse.ArgumentTypeError):
                fu.parse_bus_dev(bad)


class TestMain(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "raw.pcap"
            src.write_bytes(_pcap([_record(1, 1, b"x")]))
            out = Path(d) / "out.pcap"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fu.main([str(src), "--device", "3:15", "-o", str(out)]), 1)
                self.assertEqual(fu.main([str(src), "--device", "1:1", "-o", str(out)]), 0)


if __name__ == "__main__":
    unittest.main()
