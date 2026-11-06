#!/usr/bin/env python3
"""Tests for tools/wormhole_parse.py.

Run from the repo root, stdlib only:

    python3 -m unittest tools.test_wormhole_parse -v
    # or
    python3 tools/test_wormhole_parse.py

The integration tests run against the committed capture and assert
the counts/decodings documented in docs/capture-log.md.  If a count
changes, either the capture changed (update capinfos + docs) or the
parser regressed -- do not just update the expected value.
"""

from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wormhole_parse as wp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PCAP = REPO / "captures" / "wormhole_bus3_2026-11-06.pcap"


class TestCommittedCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = wp.read_pcap(PCAP)
        cls.summary = wp.summarise(cls.pcap)
        cls.txns = wp.parse_transactions(cls.pcap.packets)
        cls.wormhole = [t for t in cls.txns if t.bus == 3 and t.dev == 15]

    def test_packet_count_and_hash(self):
        self.assertEqual(len(self.pcap.packets), 2298)
        self.assertEqual(
            self.pcap.sha256,
            "fff7d587ab317d5fb2cb40c194347ba40ffb6aa4b7847fd4cba02e0eb3d1c97f")
        self.assertEqual(self.pcap.linktype, 220)
        self.assertAlmostEqual(self.pcap.duration, 29.032344, places=3)

    def test_wormhole_discovery_by_vid_pid(self):
        self.assertEqual(self.summary["wormhole_devices"], ["3:15"])
        info = self.summary["devices"]["3:15"]
        self.assertEqual(info["vid"], "0x0711")
        self.assertEqual(info["pid"], "0x2211")
        self.assertEqual(info["packets"], 250)
        self.assertEqual(info["by_xfer"].get("bulk"), 244)
        # HID interfaces idle: no interrupt packets for the Wormhole.
        self.assertEqual(info["by_xfer"].get("interrupt", 0), 0)

    def test_wormhole_enumeration_interfaces(self):
        devices = wp.discover_devices(self.pcap.packets)
        ifaces = devices[(3, 15)].interfaces
        self.assertEqual(len(ifaces), 3)
        self.assertEqual((ifaces[0]["class"], ifaces[0]["subclass"]), (0x08, 0x06))
        eps = [ep["address"] for iface in ifaces for ep in iface["endpoints"]]
        # Order in the descriptor: bulk IN/OUT, mouse EP3, keyboard EP4.
        self.assertEqual(eps, ["0x81", "0x02", "0x83", "0x84"])

    def test_wormhole_transaction_count_and_opcodes(self):
        self.assertEqual(len(self.wormhole), 42)
        hist = self.summary["devices"]["3:15"]["opcode_histogram"]
        self.assertEqual(hist, {
            "LOG SENSE": 16,
            "REQUEST SENSE": 16,
            "TEST UNIT READY": 4,
            "INQUIRY": 2,
            "READ CAPACITY(10)": 1,
            "READ TOC/PMA/ATIP": 2,
            "GET CONFIGURATION": 1,
        })
        csw = self.summary["devices"]["3:15"]["csw_status_histogram"]
        # Only the LOG SENSE probes fail.
        self.assertEqual(csw.get("CHECK CONDITION"), 16)

    def test_inquiry_decode(self):
        inq = [t for t in self.wormhole if t.opcode == 0x12]
        self.assertEqual(len(inq), 2)
        data = wp.decode_data(inq[0])
        self.assertEqual(data["pdt"], 5)
        self.assertEqual(data["vendor"], "j5create")
        self.assertEqual(data["product"], "WormholeSwitch")
        self.assertEqual(data["revision"], "2.00")
        self.assertEqual(data["version"], 0)

    def test_read_capacity_decode(self):
        rc = [t for t in self.wormhole if t.opcode == 0x25]
        self.assertEqual(len(rc), 1)
        data = wp.decode_data(rc[0])
        self.assertEqual(data["last_lba"], 1592)
        self.assertEqual(data["block_len"], 2048)
        self.assertEqual(data["capacity_bytes"], 1593 * 2048)

    def test_request_sense_decode(self):
        rs = [t for t in self.wormhole if t.opcode == 0x03]
        self.assertEqual(len(rs), 16)
        for t in rs:
            data = wp.decode_data(t)
            self.assertEqual(data["sense_key"], 5)
            self.assertEqual(data["sense_key_name"], "Illegal Request")
            self.assertEqual(data["asc"], "0x20")
            self.assertEqual(data["asc_name"],
                             "Invalid command operation code")

    def test_read_toc_and_get_config_are_cdrom_probes(self):
        # 0x43/0x46 are CD/DVD probes issued by the kernel after the
        # manual sg_inq/sg_readcap/dd, not READ(10) variants.
        toc = [t for t in self.wormhole if t.opcode == 0x43]
        cfg = [t for t in self.wormhole if t.opcode == 0x46]
        self.assertEqual(len(toc), 2)
        self.assertEqual(len(cfg), 1)
        self.assertEqual(toc[0].opcode_name, "READ TOC/PMA/ATIP")
        self.assertEqual(cfg[0].opcode_name, "GET CONFIGURATION")

    def test_interrupt_traffic_belongs_to_logitech_not_wormhole(self):
        summary = self.summary
        for key, dev in summary["devices"].items():
            if dev["is_wormhole"]:
                self.assertEqual(dev["by_xfer"].get("interrupt", 0), 0)
        # Bus 3 device 7 (Logitech 046d:c548) carries all interrupt traffic.
        logi = summary["devices"]["3:7"]
        self.assertGreater(logi["by_xfer"].get("interrupt", 0), 1000)

    def test_json_is_serialisable(self):
        first = self.pcap.first_ts or 0.0
        dicts = [wp.transaction_to_dict(t, first) for t in self.wormhole]
        blob = json.dumps(dicts, sort_keys=True)
        self.assertIn("WormholeSwitch", blob)
        self.assertEqual(len(dicts), 42)

    def test_no_orphan_csw_for_wormhole(self):
        for t in self.wormhole:
            self.assertIsNotNone(t.csw, "transaction %s missing CSW" % t.cbw.tag)


class TestUnitDecoders(unittest.TestCase):
    def test_parse_cbw(self):
        cdb = bytes.fromhex("120000002400")
        payload = b"USBC" + struct.pack("<II", 0x201, 36) + bytes([0x80, 0, 6]) + cdb
        payload = payload.ljust(31, b"\x00")
        cbw = wp.parse_cbw(payload)
        self.assertIsNotNone(cbw)
        assert cbw is not None
        self.assertEqual(cbw.tag, 0x201)
        self.assertEqual(cbw.cdb, cdb)
        self.assertEqual(cbw.flags, 0x80)

    def test_parse_csw(self):
        payload = b"USBS" + struct.pack("<II", 0x1F1, 0) + bytes([1])
        csw = wp.parse_csw(payload)
        self.assertIsNotNone(csw)
        assert csw is not None
        self.assertEqual(csw.status, 1)

    def test_parse_cbw_rejects_short_and_bad_sig(self):
        self.assertIsNone(wp.parse_cbw(b"USBC" + b"\x00" * 4))  # truncated echo
        self.assertIsNone(wp.parse_cbw(b"XXXX" + b"\x00" * 27))

    def test_decode_cdb_read10(self):
        cdb = bytes.fromhex("28000000000100000100")
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["name"], "READ(10)")
        self.assertEqual(out["lba"], 1)
        self.assertEqual(out["transfer_len_blocks"], 1)

    def test_decode_cdb_log_sense(self):
        out = wp.decode_cdb(bytes.fromhex("4a010000100000000800"))
        self.assertEqual(out["name"], "LOG SENSE")
        self.assertEqual(out["alloc_len"], 8)

    def test_decode_cdb_unknown_opcode(self):
        out = wp.decode_cdb(bytes([0xFF, 0, 0, 0, 0, 0]))
        self.assertEqual(out["name"], "UNKNOWN 0xFF")

    def test_parse_device_descriptor(self):
        payload = bytes.fromhex("120100020000004011071122000101020301")
        out = wp.parse_device_descriptor(payload)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["vid"], 0x0711)
        self.assertEqual(out["pid"], 0x2211)

    def test_parse_config_descriptor_endpoints(self):
        # Full Wormhole config descriptor from the capture (82 bytes).
        payload = bytes.fromhex(
            "0902520003010060050904000002080650000705810200020007050202000200"
            "09040100010301020009210001000122340007058303080001090402000103"
            "01010009210001000122430007058403080004")
        out = wp.parse_config_descriptor(payload)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["total_length"], 0x52)
        self.assertEqual(out["num_interfaces"], 3)
        eps = [ep["address"] for i in out["interfaces"] for ep in i["endpoints"]]
        self.assertEqual(eps, ["0x81", "0x02", "0x83", "0x84"])

    def test_read_pcap_rejects_non_pcap(self):
        with self.assertRaises(ValueError):
            wp.read_pcap(REPO / "README.md")

    def test_read_pcap_missing_file(self):
        with self.assertRaises(OSError):
            wp.read_pcap(REPO / "captures" / "does-not-exist.pcap")


if __name__ == "__main__":
    unittest.main(verbosity=2)
