#!/usr/bin/env python3
"""Tests for tools/peer_rerun_send.py.  No hardware is touched.

Run from the repo root, stdlib only:

    python3 -m unittest tools.test_peer_rerun_send -v
    # or
    python3 tools/test_peer_rerun_send.py
"""

from __future__ import annotations

import ctypes
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import peer_rerun_send as prs  # noqa: E402
import wormhole_parse as wp  # noqa: E402

# label -> (HID type, payload) passed to wp.build_vendor_hid_cdb
FRAMES = {
    "M+1": ("3", bytes([0x00, 0x01])),
    "M-1": ("3", bytes([0x00, 0xFF])),
    "MZ": ("3", b""),
    "KZ": ("4", b""),
}


class TestCdbTable(unittest.TestCase):
    def test_sixteen_byte_frames_match_parser_builder(self):
        for label in prs.SIXTEEN:
            kind, payload = FRAMES[label]
            with self.subTest(label=label):
                want = wp.build_vendor_hid_cdb(kind, payload).hex()
                self.assertEqual(prs.CDB[label], want)
                self.assertEqual(len(prs.CDB[label]), 32)  # 16 bytes as hex

    def test_fifteen_byte_controls_drop_one_zero_before_footer(self):
        for short, full in (("short M+1", "M+1"), ("short M-1", "M-1")):
            with self.subTest(label=short):
                full_bytes = bytes.fromhex(prs.CDB[full])
                self.assertEqual(bytes.fromhex(prs.CDB[short]), full_bytes[:-3] + full_bytes[-2:])
                self.assertEqual(len(prs.CDB[short]), 30)  # 15 bytes as hex

    def test_plan_shape(self):
        self.assertEqual([p[0] for p in prs.PLAN], ["P1", "P2", "P3", "P4"])
        self.assertEqual([p[1] for p in prs.PLAN], ["sg_raw", "sgio", "sgio", "sgio"])
        self.assertEqual(prs.PLAN[2][2], 0.25)
        self.assertEqual(prs.FIFTEEN, ["short M+1", "short M-1"])


class TestSgIoHeader(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and struct.calcsize("P") == 8,
                         "64-bit Linux only")
    def test_struct_size_matches_kernel_header(self):
        self.assertEqual(ctypes.sizeof(prs.SgIoHdr), 88)


if __name__ == "__main__":
    unittest.main()
