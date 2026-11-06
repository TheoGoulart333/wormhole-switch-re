#!/usr/bin/env python3
"""Parse a Linux usbmon pcap (linktype 220, usb-linux-mmap) for the
J5Create WormholeSwitch (VID 0711:PID 2211) and other USB devices on the bus.

Stdlib only -- no tshark, pyshark or scapy required.  The committed sample
``captures/wormhole_bus3_2026-11-06.pcap`` is the reference input.

What it does
------------
* Reads a classic pcap (not pcapng), decodes the 64-byte usb-linux-mmap
  header of every packet.
* Discovers devices from USB control enumeration (GET_DESCRIPTOR) by
  VID:PID, so it never relies on a hard-coded Bus:Device number, which
  changes on every replug and differs between the two cable ends.
* Pairs SCSI Bulk-Only CBW -> data -> CSW transactions per device and
  decodes the CDB, the data phase (INQUIRY / READ CAPACITY(10) /
  REQUEST SENSE / READ TOC / GET CONFIGURATION) and the CSW status.
* Summarises control / bulk / interrupt traffic per device, which is
  how "the Wormhole HID interfaces are idle" can be verified.

usb-linux-mmap header (64 bytes, little-endian, offsets verified
against ``captures/wormhole_bus3_2026-11-06.pcap`` and tshark 4.4.19)
-------------------------------------------------------------------
    0  u64  URB id
    8  u8   type           'S' submit / 'C' complete
    9  u8   xfer_type      1 interrupt, 2 control, 3 bulk
   10  u8   endpoint       high bit = IN, low bits = EP number
   11  u8   device number
   12  u8   bus number
   13  u8   reserved (observed 0)
   14  u8   flag_setup     '\\0' setup packet present, '-' not relevant
   15  u8   flag_data      '\\0' data present, '<' submit/no-data,
                          '>' complete/no-data
   16  i32  ts_sec
   20  i32  reserved (observed 0)
   24  i32  ts_usec
   28  i32  status         0 on complete, -115 (-EINPROGRESS) on submit
   32  u32  length         URB transfer length
   36  u32  data_len       bytes of payload after the 64-byte header
   40  8B   setup packet   only when flag_setup == '\\0'
   48  u32  interval       interrupt polling interval
   52  u32  start_frame
   56  u32  transfer_flags
   60  u32  num_iso_descs
   64  ...  payload (data_len bytes)

Bulk-Only framing inside bulk payloads
---------------------------------------
    CBW (31 B): 'USBC' u32 tag, u32 data_len, u8 flags (0x80 = IN),
                u8 LUN, u8 CDB length, CDB bytes
    CSW (13 B): 'USBS' u32 tag, u32 residue, u8 status
                (0 good, 1 CHECK CONDITION, 2 phase error)

A CBW *complete* packet in usbmon carries only the first 8 bytes of
the CBW; only SUBMIT packets carry the full 31 bytes.  This parser
therefore creates a transaction only on a SUBMIT CBW and ignores the
truncated COMPLETE echo -- counting both would double-count and
previously led to a truncated-payload index error.

Usage
-----
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --json
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --device 14
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --all --no-transactions

Exit codes: 0 success, 1 usage/IO error, 2 unsupported file format.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

# pcap LINKTYPE_USB_LINUX_MMAPPED.  Wireshark reports this as
# encapsulation 115 (usb-linux-mmap); the on-disk pcap linktype field
# is 220.  195 is the legacy DLT_USB_LINUX_MMAPPED with the same
# 64-byte header layout in practice, so it is accepted too.
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USB_LINUX_MMAPPED_LEGACY = 195
HEADER_LEN = 64
WORMHOLE_VID = 0x0711
WORMHOLE_PID = 0x2211

XFER_NAMES = {1: "interrupt", 2: "control", 3: "bulk"}
CSW_STATUS_NAMES = {0: "good", 1: "CHECK CONDITION", 2: "phase error"}

# SCSI opcodes observed from / relevant to this device.  Unknown opcodes
# are reported as UNKNOWN 0xNN rather than dropped.
SCSI_OPCODES = {
    0x00: "TEST UNIT READY",
    0x03: "REQUEST SENSE",
    0x04: "FORMAT UNIT",
    0x12: "INQUIRY",
    0x1C: "RECEIVE DIAGNOSTIC RESULTS",
    0x25: "READ CAPACITY(10)",
    0x28: "READ(10)",
    0x2A: "WRITE(10)",
    0x43: "READ TOC/PMA/ATIP",
    0x46: "GET CONFIGURATION",
    0x4A: "LOG SENSE",
    0x5A: "MODE SENSE(10)",
    0x9E: "READ CAPACITY(16)",
    0xA0: "RECEIVE DIAGNOSTIC",
    0xA3: "REPORT LUNs",
}
SENSE_KEYS = {
    0: "No Sense", 1: "Recovered Error", 2: "Not Ready", 3: "Medium Error",
    4: "Hardware Error", 5: "Illegal Request", 6: "Unit Attention",
    7: "Data Protect", 8: "Checksum Error", 9: "Copy Abort",
    10: "Aborted Command", 11: "Volume Overflow", 12: "Miscompare",
    13: "User Initiated Abort",
}
ASC_NAMES = {
    0x0000: "No additional sense information",
    0x2000: "Invalid command operation code",
    0x2400: "Invalid field in CDB",
    0x3000: "Incompatible medium installed",
    0x0400: "Not ready",
    0x3A00: "Medium not present",
}


# --------------------------------------------------------------------------
# pcap + usbmon decoding
# --------------------------------------------------------------------------

@dataclass
class UrbPacket:
    frame: int
    ts: float                      # seconds, from the pcap record header
    urb_id: int
    kind: str                      # 'S' or 'C'
    xfer: int
    endpoint: int                  # raw, e.g. 0x81 = EP1 IN
    dev: int
    bus: int
    flag_setup: int
    flag_data: int
    status: int
    length: int
    data_len: int
    setup: bytes | None
    interval: int
    transfer_flags: int
    payload: bytes

    @property
    def direction(self) -> str:
        return "IN" if self.endpoint & 0x80 else "OUT"

    @property
    def ep_num(self) -> int:
        return self.endpoint & 0x0F


@dataclass
class PcapData:
    path: str
    sha256: str
    linktype: int
    packets: list[UrbPacket]
    duration: float
    first_ts: float | None


def _pcap_endian(magic: bytes) -> str:
    if magic == bytes.fromhex("d4c3b2a1"):
        return "<"
    if magic == bytes.fromhex("a1b2c3d4"):
        return ">"
    if magic == bytes.fromhex("4d3cb2a1"):
        return "<"  # nanosecond variant, timestamps still usec-scaled below
    if magic == bytes.fromhex("a1b23c4d"):
        return ">"
    raise ValueError(
        "not a classic pcap (magic %s); pcapng is not supported -- "
        "re-capture with tcpdump -w file.pcap" % magic.hex()
    )


def decode_usbmon_header(raw: bytes) -> dict:
    """Decode one 64-byte usb-linux-mmap header + payload."""
    if len(raw) < HEADER_LEN:
        raise ValueError("packet shorter than 64-byte usbmon header")
    hdr = raw[:HEADER_LEN]
    (urb_id,) = struct.unpack_from("<Q", hdr, 0)
    kind = chr(hdr[8])
    xfer, endpoint, dev, bus = hdr[9], hdr[10], hdr[11], hdr[12]
    flag_setup, flag_data = hdr[14], hdr[15]
    _ts_sec, _reserved, _ts_usec = struct.unpack_from("<iii", hdr, 16)
    (status,) = struct.unpack_from("<i", hdr, 28)
    length, data_len = struct.unpack_from("<II", hdr, 32)
    setup = hdr[40:48] if flag_setup == 0 else None
    (interval,) = struct.unpack_from("<I", hdr, 48)
    (transfer_flags,) = struct.unpack_from("<I", hdr, 56)
    payload = raw[HEADER_LEN:HEADER_LEN + data_len]
    return {
        "urb_id": urb_id, "kind": kind, "xfer": xfer, "endpoint": endpoint,
        "dev": dev, "bus": bus, "flag_setup": flag_setup,
        "flag_data": flag_data, "status": status, "length": length,
        "data_len": data_len, "setup": setup, "interval": interval,
        "transfer_flags": transfer_flags, "payload": payload,
    }


def read_pcap(path: str | Path) -> PcapData:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("file too short for a pcap global header")
    endian = _pcap_endian(data[:4])
    _magic, _vmaj, _vmin, _zone, _sig, _snap, linktype = struct.unpack_from(
        endian + "IHHiiii", data, 0)
    if linktype not in (LINKTYPE_USB_LINUX_MMAPPED, LINKTYPE_USB_LINUX_MMAPPED_LEGACY):
        raise ValueError(
            "linktype %d, expected 220 (usb-linux-mmap, Wireshark "
            "encapsulation 115); this parser only handles "
            "`tcpdump -i usbmonN` captures" % linktype)
    packets: list[UrbPacket] = []
    off, frame = 24, 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + incl > len(data):
            break  # truncated final record
        raw = data[off:off + incl]
        off += incl
        frame += 1
        if len(raw) < HEADER_LEN:
            continue
        d = decode_usbmon_header(raw)
        packets.append(UrbPacket(
            frame=frame, ts=ts_sec + ts_usec / 1e6, **d))
    first = packets[0].ts if packets else None
    last = packets[-1].ts if packets else None
    duration = (last - first) if first is not None and last is not None else 0.0
    return PcapData(
        path=str(path), sha256=hashlib.sha256(data).hexdigest(),
        linktype=linktype, packets=packets, duration=duration, first_ts=first)


# --------------------------------------------------------------------------
# USB descriptor decoding (control enumeration)
# --------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    bus: int
    dev: int
    vid: int | None = None
    pid: int | None = None
    bcd_device: int | None = None
    device_descriptor: bytes | None = None
    config_descriptors: list[bytes] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)

    @property
    def key(self) -> tuple[int, int]:
        return (self.bus, self.dev)


def parse_device_descriptor(payload: bytes) -> dict | None:
    if len(payload) < 18 or payload[0] != 18 or payload[1] != 1:
        return None
    vid, pid, bcd = struct.unpack_from("<HHH", payload, 8)
    return {"vid": vid, "pid": pid, "bcd_device": bcd,
            "usb_version": struct.unpack_from("<H", payload, 2)[0],
            "b_max_packet0": payload[7], "i_manufacturer": payload[14],
            "i_product": payload[15], "i_serial": payload[16]}


def parse_config_descriptor(payload: bytes) -> dict | None:
    if len(payload) < 9 or payload[0] < 9 or payload[1] != 2:
        return None
    total, num_if = struct.unpack_from("<HB", payload, 2)
    ifaces: list[dict] = []
    off = 9
    while off + 2 <= len(payload):
        blen, btype = payload[off], payload[off + 1]
        if blen < 2 or off + blen > len(payload):
            break
        if btype == 4 and blen >= 9:  # INTERFACE
            ifaces.append({
                "number": payload[off + 2], "alt": payload[off + 3],
                "num_endpoints": payload[off + 4],
                "class": payload[off + 5], "subclass": payload[off + 6],
                "protocol": payload[off + 7], "endpoints": []})
        elif btype == 5 and blen >= 7 and ifaces:  # ENDPOINT
            addr = payload[off + 2]
            ifaces[-1]["endpoints"].append({
                "address": "0x%02x" % addr,
                "direction": "IN" if addr & 0x80 else "OUT",
                "attributes": payload[off + 3],
                "max_packet": struct.unpack_from("<H", payload, off + 4)[0]})
        off += blen
    return {"total_length": total, "num_interfaces": num_if,
            "bm_attributes": payload[7], "max_power_units": payload[8],
            "interfaces": ifaces}


def discover_devices(packets: list[UrbPacket]) -> dict[tuple[int, int], DeviceInfo]:
    devices: dict[tuple[int, int], DeviceInfo] = {}
    pending_setup: dict[tuple[int, int, int], bytes] = {}
    for p in packets:
        key = (p.bus, p.dev)
        devices.setdefault(key, DeviceInfo(bus=p.bus, dev=p.dev))
        if p.xfer != 2:  # control only
            continue
        if p.kind == "S" and p.setup is not None:
            pending_setup[(p.bus, p.dev, p.urb_id)] = p.setup
        elif p.kind == "C" and p.payload:
            setup = pending_setup.pop((p.bus, p.dev, p.urb_id), None)
            if setup is None or len(setup) < 8:
                continue
            _bm, b_req, w_val, _w_idx, w_len = struct.unpack("<BBHHH", setup)
            if b_req != 6:  # GET_DESCRIPTOR
                continue
            dtype = (w_val >> 8) & 0xFF
            dev_info = devices[key]
            if dtype == 1 and w_len >= 18:
                parsed = parse_device_descriptor(p.payload)
                if parsed:
                    dev_info.vid = parsed["vid"]
                    dev_info.pid = parsed["pid"]
                    dev_info.bcd_device = parsed["bcd_device"]
                    dev_info.device_descriptor = p.payload
            elif dtype == 2 and w_len > 9:
                parsed = parse_config_descriptor(p.payload)
                if parsed:
                    dev_info.config_descriptors.append(p.payload)
                    dev_info.interfaces = parsed["interfaces"]
    return devices


# --------------------------------------------------------------------------
# SCSI Bulk-Only decoding
# --------------------------------------------------------------------------

@dataclass
class CbW:
    tag: int
    data_len: int
    flags: int
    lun: int
    cdb: bytes
    frame: int
    ts: float


@dataclass
class CsW:
    tag: int
    residue: int
    status: int
    frame: int
    ts: float


@dataclass
class Transaction:
    bus: int
    dev: int
    cbw: CbW
    data: bytes = b""
    csw: CsW | None = None

    @property
    def opcode(self) -> int:
        return self.cbw.cdb[0] if self.cbw.cdb else 0

    @property
    def opcode_name(self) -> str:
        return SCSI_OPCODES.get(self.opcode, "UNKNOWN 0x%02X" % self.opcode)


def parse_cbw(payload: bytes) -> CbW | None:
    if len(payload) < 31 or payload[:4] != b"USBC":
        return None
    tag, data_len = struct.unpack_from("<II", payload, 4)
    flags, lun, cdb_len = payload[12], payload[13], payload[14]
    cdb = payload[15:15 + cdb_len] if cdb_len else b""
    return CbW(tag=tag, data_len=data_len, flags=flags, lun=lun,
               cdb=cdb, frame=0, ts=0.0)  # frame/ts filled by caller


def parse_csw(payload: bytes) -> CsW | None:
    if len(payload) < 13 or payload[:4] != b"USBS":
        return None
    tag, residue = struct.unpack_from("<II", payload, 4)
    return CsW(tag=tag, residue=residue, status=payload[12], frame=0, ts=0.0)


def parse_transactions(packets: list[UrbPacket]) -> list[Transaction]:
    """Pair CBW (SUBMIT) -> data (COMPLETE) -> CSW (COMPLETE) per device.

    Bulk-Only is strictly sequential per device, so one pending
    transaction per (bus, dev) is sufficient and interleaved devices
    do not cross-pair.
    """
    txns: list[Transaction] = []
    pending: dict[tuple[int, int], Transaction] = {}
    for p in packets:
        if p.xfer != 3 or not p.payload:
            continue
        if p.payload[:4] == b"USBC":
            if p.kind != "S":
                continue  # truncated 8-byte COMPLETE echo, not a new CBW
            cbw = parse_cbw(p.payload)
            if cbw is None:
                continue
            cbw.frame, cbw.ts = p.frame, p.ts
            txn = Transaction(bus=p.bus, dev=p.dev, cbw=cbw)
            pending[(p.bus, p.dev)] = txn
            txns.append(txn)
        elif p.payload[:4] == b"USBS":
            if p.kind != "C":
                continue
            csw = parse_csw(p.payload)
            if csw is None:
                continue
            csw.frame, csw.ts = p.frame, p.ts
            txn = pending.pop((p.bus, p.dev), None)
            if txn is not None:
                txn.csw = csw
            # Orphan CSW (no pending CBW seen): still surface it.
            else:
                txn = Transaction(bus=p.bus, dev=p.dev,
                                  cbw=CbW(0, 0, 0, 0, b"", p.frame, p.ts))
                txn.csw = csw
                txns.append(txn)
        elif p.kind == "C":
            txn = pending.get((p.bus, p.dev))
            if txn is not None:
                txn.data += p.payload
    return txns


def decode_cdb(cdb: bytes) -> dict:
    """Decode common CDB fields per opcode. Unknown fields stay raw."""
    if not cdb:
        return {}
    op = cdb[0]
    out: dict = {"opcode": "0x%02X" % op,
                 "name": SCSI_OPCODES.get(op, "UNKNOWN 0x%02X" % op),
                 "cdb_hex": cdb.hex()}
    if op == 0x03 and len(cdb) >= 6:                      # REQUEST SENSE
        out["alloc_len"] = cdb[4]
    elif op == 0x12 and len(cdb) >= 6:                    # INQUIRY
        out["evpd"] = bool(cdb[1] & 0x01)
        out["page_code"] = cdb[2] if out["evpd"] else None
        out["alloc_len"] = struct.unpack_from(">H", cdb, 3)[0]
    elif op == 0x25 and len(cdb) >= 10:                   # READ CAPACITY(10)
        pass
    elif op in (0x28, 0x2A) and len(cdb) >= 10:           # READ/WRITE(10)
        out["lba"] = struct.unpack_from(">I", cdb, 2)[0]
        out["transfer_len_blocks"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x43 and len(cdb) >= 10:                   # READ TOC/PMA/ATIP
        out["format"] = cdb[1] & 0x0F
        out["track/session"] = cdb[6]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x46 and len(cdb) >= 10:                   # GET CONFIGURATION
        out["starting_feature"] = struct.unpack_from(">H", cdb, 2)[0]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x4A and len(cdb) >= 10:                   # LOG SENSE
        out["page_code"] = cdb[2]
        out["subpage_code"] = cdb[3]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x9E and len(cdb) >= 16:                   # READ CAPACITY(16)
        out["service_action"] = cdb[10] & 0x1F
    return out


def _ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def decode_data(txn: Transaction) -> dict:
    """Decode the data phase. Returns {} when there is no data."""
    data = txn.data
    if not data:
        return {}
    op = txn.opcode
    out: dict = {"len": len(data), "hex": data.hex(), "ascii": _ascii(data)}
    if op == 0x12 and len(data) >= 36:                    # INQUIRY (standard)
        out.update({
            "pdt": data[0] & 0x1F,
            "rmb": bool(data[1] & 0x80),
            "version": data[2],
            "response_format": data[3] & 0x0F,
            "additional_length": data[4],
            "vendor": data[8:16].decode("ascii", "replace").strip(),
            "product": data[16:32].decode("ascii", "replace").strip(),
            "revision": data[32:36].decode("ascii", "replace").strip(),
        })
        if len(data) > 36:
            out["trailing_ascii"] = _ascii(data[36:])
    elif op == 0x25 and len(data) >= 8:                   # READ CAPACITY(10)
        last_lba, block_len = struct.unpack_from(">II", data, 0)
        out.update({"last_lba": last_lba, "block_len": block_len,
                    "capacity_bytes": (last_lba + 1) * block_len})
    elif op == 0x03 and len(data) >= 18:                  # REQUEST SENSE
        key = data[2] & 0x0F
        asc = struct.unpack_from(">H", data, 12)[0]
        out.update({
            "response_code": data[0] & 0x7F,
            "sense_key": key,
            "sense_key_name": SENSE_KEYS.get(key, "unknown"),
            "asc": "0x%02X" % (asc >> 8),
            "ascq": "0x%02X" % (asc & 0xFF),
            "asc_name": ASC_NAMES.get(asc, "unknown"),
        })
    elif op == 0x43 and len(data) >= 4:                   # READ TOC
        out.update({"toc_data_len": struct.unpack_from(">H", data, 0)[0],
                    "first_track": data[2], "last_track": data[3]})
    return out


def transaction_to_dict(txn: Transaction, first_ts: float) -> dict:
    csw = txn.csw
    status = csw.status if csw else None
    return {
        "bus": txn.bus, "dev": txn.dev,
        "cbw_frame": txn.cbw.frame,
        "t_offset_s": round(txn.cbw.ts - first_ts, 6) if first_ts else None,
        "tag": "0x%x" % txn.cbw.tag,
        "lun": txn.cbw.lun,
        "direction": "IN" if txn.cbw.flags & 0x80 else "OUT",
        "cbw_data_len": txn.cbw.data_len,
       **decode_cdb(txn.cbw.cdb),
        "data": decode_data(txn),
        "csw_frame": csw.frame if csw else None,
        "csw_status": status,
        "csw_status_name": CSW_STATUS_NAMES.get(status, "unknown") if status is not None else None,
        "csw_residue": csw.residue if csw else None,
    }


# --------------------------------------------------------------------------
# Summaries
# --------------------------------------------------------------------------

def summarise(pcap: PcapData) -> dict:
    devices = discover_devices(pcap.packets)
    txns = parse_transactions(pcap.packets)
    per_device: dict[str, dict] = {}
    for key, info in sorted(devices.items()):
        bus, dev = key
        pkts = [p for p in pcap.packets if p.bus == bus and p.dev == dev]
        xfer_counts = collections.Counter(XFER_NAMES.get(p.xfer, str(p.xfer)) for p in pkts)
        ep_counts = collections.Counter(
            "EP%d %s" % (p.ep_num, p.direction) for p in pkts)
        dev_txns = [t for t in txns if t.bus == bus and t.dev == dev]
        opcode_hist = collections.Counter(t.opcode_name for t in dev_txns)
        csw_hist = collections.Counter(
            CSW_STATUS_NAMES.get(t.csw.status, "unknown")
            for t in dev_txns if t.csw is not None)
        per_device["%d:%d" % (bus, dev)] = {
            "vid": ("0x%04x" % info.vid) if info.vid is not None else None,
            "pid": ("0x%04x" % info.pid) if info.pid is not None else None,
            "is_wormhole": info.vid == WORMHOLE_VID and info.pid == WORMHOLE_PID,
            "packets": len(pkts),
            "by_xfer": dict(xfer_counts),
            "by_endpoint": dict(sorted(ep_counts.items())),
            "interfaces": info.interfaces,
            "scsi_transactions": len(dev_txns),
            "opcode_histogram": dict(opcode_hist),
            "csw_status_histogram": dict(csw_hist),
        }
    wormholes = [k for k, v in per_device.items() if v["is_wormhole"]]
    return {
        "file": pcap.path, "sha256": pcap.sha256, "linktype": pcap.linktype,
        "packets": len(pcap.packets), "duration_s": round(pcap.duration, 6),
        "first_ts": pcap.first_ts,
        "devices": per_device,
        "wormhole_devices": wormholes,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _fmt_device_table(summary: dict) -> list[str]:
    lines = ["Devices (Bus:Dev  VID:PID  packets  control/bulk/interrupt  SCSI txns)"]
    for key, d in sorted(summary["devices"].items()):
        vidpid = "%s:%s" % (d["vid"], d["pid"]) if d["vid"] else "unknown"
        mark = "  <-- WormholeSwitch" if d["is_wormhole"] else ""
        lines.append("  %s  %s  %d  %s  %d%s" % (
            key, vidpid, d["packets"],
            "/".join(str(d["by_xfer"].get(k, 0)) for k in ("control", "bulk", "interrupt")),
            d["scsi_transactions"], mark))
    return lines


def _fmt_interfaces(interfaces: list[dict]) -> list[str]:
    lines = []
    for iface in interfaces:
        lines.append("    If %d: class 0x%02x/0x%02x/0x%02x" % (
            iface["number"], iface["class"], iface["subclass"], iface["protocol"]))
        for ep in iface["endpoints"]:
            lines.append("      EP %s %s attr 0x%02x maxpkt %d" % (
                ep["address"], ep["direction"], ep["attributes"], ep["max_packet"]))
    return lines


def _fmt_txn(t: dict) -> str:
    data = t.get("data") or {}
    extra = ""
    if "vendor" in data:
        extra = " %r/%r rev %r PDT=%d" % (data["vendor"], data["product"],
                                          data["revision"], data["pdt"])
    elif "last_lba" in data:
        extra = " last_LBA=%d block=%d capacity=%d B" % (
            data["last_lba"], data["block_len"], data["capacity_bytes"])
    elif "sense_key_name" in data:
        extra = " key=%d (%s) ASC=%s/%s (%s)" % (
            data["sense_key"], data["sense_key_name"], data["asc"],
            data["ascq"], data["asc_name"])
    elif data.get("len"):
        extra = " data[%d]=%s" % (data["len"], data["hex"][:64])
    return "  f%-5d t=%8.3fs tag=%-8s %-28s CDB=%-24s dir=%s len=%-4d CSW=%s%s" % (
        t["cbw_frame"], t["t_offset_s"] or 0, t["tag"], t["name"],
        t.get("cdb_hex", ""), t["direction"], t["cbw_data_len"],
        t["csw_status_name"], extra)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("pcap", help="usbmon pcap (linktype 220)")
    ap.add_argument("--device", metavar="BUS:DEV",
                    help="only summarise this device, e.g. 3:15 (default: "
                         "WormholeSwitch if found, else all devices)")
    ap.add_argument("--all", action="store_true",
                    help="show transactions for every device, not just Wormhole")
    ap.add_argument("--no-transactions", action="store_true",
                    help="summary only, no per-transaction list")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    try:
        pcap = read_pcap(args.pcap)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1 if isinstance(e, OSError) else 2

    summary = summarise(pcap)
    first_ts = summary["first_ts"] or 0.0
    txns = parse_transactions(pcap.packets)

    # Decide which devices get a transaction listing.
    want: set[tuple[int, int]] | None
    if args.device:
        try:
            bus_s, dev_s = args.device.split(":")
            want = {(int(bus_s), int(dev_s))}
        except ValueError:
            print("error: --device must be BUS:DEV", file=sys.stderr)
            return 1
    elif args.all:
        want = None  # all
    elif summary["wormhole_devices"]:
        want = {(int(k.split(":")[0]), int(k.split(":")[1])) for k in summary["wormhole_devices"]}
    else:
        want = None
    shown = [t for t in txns if want is None or (t.bus, t.dev) in want]
    txn_dicts = [transaction_to_dict(t, first_ts) for t in sorted(shown, key=lambda t: t.cbw.frame)]

    if args.json:
        out = dict(summary)
        out["transactions"] = txn_dicts
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    print("File: %s" % summary["file"])
    print("SHA-256: %s" % summary["sha256"])
    print("Packets: %d  duration: %.3fs  linktype: %d (usb-linux-mmap)" % (
        summary["packets"], summary["duration_s"], summary["linktype"]))
    print()
    print("\n".join(_fmt_device_table(summary)))

    # Enumeration detail for the focused device(s).
    devices = discover_devices(pcap.packets)
    focus: set[tuple[int, int]] = want if want is not None else {(t.bus, t.dev) for t in shown}
    for key in sorted(focus):
        info = devices.get(key)
        if info and info.interfaces:
            print("\nEnumeration %d:%d:" % key)
            print("\n".join(_fmt_interfaces(info.interfaces)))

    if not args.no_transactions:
        print("\nSCSI Bulk-Only transactions (%d):" % len(txn_dicts))
        for t in txn_dicts:
            print(_fmt_txn(t))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
