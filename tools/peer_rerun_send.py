#!/usr/bin/env python3
"""Peer-side send driver for the peer->local re-run (wormhole-switch-re, 2026-11-06).

Sends vendor 0xD9 CDBs to the Wormhole's SCSI generic node and writes one JSON
line per send.  Payloads are chosen so the other machine sees no keystrokes:
mouse +1 and -1 px (net zero), an idle mouse report, an all-zero keyboard
report (no key pressed), and two 15-byte control frames (+1/-1, expected to be
rejected).

Phases, in send order:
  P1  sg_raw -C 1, 16-byte CDBs, 2.0 s gap     (command-line path)
  P2  SG_IO ioctl, 16-byte CDBs, 2.0 s gap     (sg_raw not involved)
  P3  SG_IO ioctl, 16-byte CDBs, 0.25 s gap    (rapid: timing-guard test)
  P4  SG_IO ioctl, 15-byte controls, 2.0 s gap (framing control)

usage: peer_rerun_send.py /dev/sgN LOG.jsonl
"""

import ctypes
import fcntl
import json
import os
import subprocess
import sys
import time

SG_IO = 0x2285            # linux/scsi/sg.h
SG_DXFER_NONE = -1
SENSE_LEN = 32


class SgIoHdr(ctypes.Structure):
    """struct sg_io_hdr from linux/scsi/sg.h (88 bytes on x86-64)."""
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


assert ctypes.sizeof(SgIoHdr) == 88, ctypes.sizeof(SgIoHdr)

# Generated with tools/wormhole_parse.py build_vendor_hid_cdb and checked for length.
CDB = {
    "M+1": "d9330001000000000000000000004f54",
    "M-1": "d93300ff000000000000000000004f54",
    "MZ": "d9330000000000000000000000004f54",
    "KZ": "d9340000000000000000000000004f54",
    "short M+1": "d93300010000000000000000004f54",
    "short M-1": "d93300ff0000000000000000004f54",
}
SIXTEEN = ["M+1", "M-1", "MZ", "KZ"]
FIFTEEN = ["short M+1", "short M-1"]

PLAN = [
    ("P1", "sg_raw", 2.0, SIXTEEN),
    ("P2", "sgio", 2.0, SIXTEEN),
    ("P3", "sgio", 0.25, SIXTEEN),
    ("P4", "sgio", 2.0, FIFTEEN),
]


def send_sg_raw(dev, cdb_hex):
    args = ["sg_raw", "-C", "1", dev] + [cdb_hex[i:i + 2] for i in range(0, len(cdb_hex), 2)]
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return {"rc": p.returncode, "out": p.stdout.strip()[-300:], "err": p.stderr.strip()[-300:]}


def send_sgio(fd, cdb_hex):
    cdb = bytes.fromhex(cdb_hex)
    cmd = (ctypes.c_ubyte * len(cdb))(*cdb)
    sense = (ctypes.c_ubyte * SENSE_LEN)()
    hdr = SgIoHdr()
    hdr.interface_id = ord("S")
    hdr.dxfer_direction = SG_DXFER_NONE
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = SENSE_LEN
    hdr.cmdp = ctypes.cast(cmd, ctypes.c_void_p)
    hdr.sbp = ctypes.cast(sense, ctypes.c_void_p)
    hdr.timeout = 5000
    fcntl.ioctl(fd, SG_IO, hdr)
    return {
        "status": hdr.status,
        "host_status": hdr.host_status,
        "driver_status": hdr.driver_status,
        "sense": bytes(sense[:hdr.sb_len_wr]).hex(),
        "duration_ms": hdr.duration,
    }


def main(argv):
    dev, log_path = argv[1], argv[2]
    fd = os.open(dev, os.O_RDWR)
    seq = 0
    try:
        with open(log_path, "a") as log:
            for phase, path, gap, labels in PLAN:
                for label in labels:
                    seq += 1
                    cdb_hex = CDB[label]
                    t = time.time()
                    try:
                        if path == "sg_raw":
                            res = send_sg_raw(dev, cdb_hex)
                        else:
                            res = send_sgio(fd, cdb_hex)
                    except (OSError, subprocess.SubprocessError) as exc:
                        res = {"error": repr(exc)}
                    row = {"seq": seq, "phase": phase, "path": path, "label": label,
                           "cdb": cdb_hex, "cdb_len": len(cdb_hex) // 2, "t": round(t, 6), **res}
                    line = json.dumps(row)
                    log.write(line + "\n")
                    log.flush()
                    print(line, flush=True)
                    time.sleep(gap)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main(sys.argv)
