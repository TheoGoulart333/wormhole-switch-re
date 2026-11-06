# wormhole-switch-re

Reverse-engineering research, notes, and captures for the **J5Create Wormhole** USB A↔A bridge cable (Magic Control Technology **WormholeSwitch**, VID `0711` / PID `2211`).

This is a community documentation project. It is **not affiliated with, sponsored by, or endorsed by** J5Create, KaiJet Technology, or Magic Control Technology Corp. Original firmware and host-software binaries are copyrighted and are **not** vendored here — only hashes, descriptors, and analysis are published.

## What this device is

The Wormhole is a USB A-to-A cable whose middle contains a microcontroller that presents as a compound USB device to each host it is plugged into:

- a **fake CD-ROM** (SCSI Bulk-Only) carrying Windows/macOS host software, and
- **two boot-class HID interfaces** (mouse + keyboard) that allow input injection from the peer machine.

When both ends are plugged into two PCs, each PC runs the bundled *Wormhole* / *GoBridge* software (see `docs/iso-payload.md`). The local USB enumeration is identical regardless of whether the peer is connected — the peer link is internal to the cable.

```
        ┌──────────── J5Create Wormhole cable ────────────┐
  PC A ─┴─ USB A ─[ microcontroller ]─ USB A ─┴─ PC B
                     │
                     ├─ If 0: Mass Storage 08/06/50 (Bulk-Only) → /dev/srX, /dev/sgY
                     ├─ If 1: HID Boot Mouse 03/01/02 (EP3)
                     └─ If 2: HID Boot Keyboard 03/01/01 (EP4)
```

## Protocol summary (observed)

| Layer | Detail |
|---|---|
| USB | USB 2.00, High-Speed 480M, self-powered, MaxPower 10mA, malformed `bmAttributes 0x60` (missing must-be-set bit 7). |
| SCSI (If 0) | Standard Bulk-Only, Bulk-Only CBW (`USBC`) / CSW (`USBS`). INQUIRY returns PDT=5 (cd/dvd), version `0x00` (no conformance claimed), vendor `j5create`, product `WormholeSwitch`, rev `2.00`. Minimal command set: `TEST UNIT READY`, `INQUIRY`, `REQUEST SENSE`, `READ CAPACITY(10)`, `READ(10)`. `LOG SENSE (0x4A)` and `READ CAPACITY(16) (0x9E)` return CHECK CONDITION / INVALID OPCODE. |
| Capacity anomaly | `READ CAPACITY(10)` returns last LBA 1592 / 2048 B blocks (3.1 MiB), but Linux exposes `/dev/srX` as 31744×512 B (15.5 MiB) and mounts a 15.5 MiB ISO9660 volume labelled `WORMHOLE`. The reported capacity and the block-device size do not match. |
| HID (If 1/2) | Boot Mouse (52 B report descriptor) and Boot Keyboard (67 B). Appear as `hidraw*` + input events. Idle until peer software injects reports — see `docs/transport.md`. |
| ISO payload | `autorun.inf` → `SKLoader.exe` (embedded UPX DLL resource) + `Deployment/GSDD.lst`/`GSDD.zz`, macOS `Wormhole.app` → `WormholeShell` → `Wormhole.tgz` → `GoBridgeDemon` + `KMKeyMouse`/`KMClipboard`/`OTiTransfer`. See `docs/iso-payload.md` and `docs/pe-analysis.md`. |

See [`docs/capture-log.md`](docs/capture-log.md) for a sample usbmon capture and CBW/CSW breakdown.

## Repository layout

```
.
├── README.md                     # this file
├── LICENSE                       # MIT (for documentation code/scripts)
├── .gitignore                    # excludes firmware blobs, pcaps > policy, etc.
├── docs/
│   ├── transport.md              # USB descriptors, SCSI, HID identities
│   ├── iso-payload.md            # ISO contents, manifests, macOS bundle map
│   ├── pe-analysis.md            # REA PE imports/resources/certs for SKLoader.exe + embedded DLL
│   ├── mac-gobridge.md           # GoBridgeDemon + OTiTransfer function-level analysis (HID CDB packets)
│   ├── capture-log.md            # usbmon methodology + CBW/CSW pattern + capacity anomaly
│   ├── methodology.md            # REA device-protocol workflow used
│   └── reproduction.md           # commands to re-dump this device yourself
├── captures/
│   ├── wormhole_bus3_2026-11-06.pcap
│   └── wormhole_bus3_capinfos.txt
└── tools/
    ├── wormhole_parse.py         # stdlib-only usbmon pcap parser (CBW/CSW/SCSI)
    └── test_wormhole_parse.py    # unittest suite for the parser
```

## Reproduce the basics

```sh
lsusb -v -d 0711:2211
sg_inq /dev/sgX
sg_readcap /dev/sgX          # note: --16 fails on this firmware
sg_readcap --10 /dev/sgX
lsblk -o NAME,PATH,TRAN,SIZE /dev/srX
sudo modprobe usbmon
sudo tcpdump -i usbmon3 -w wormhole.pcap   # Bus 3 = wormhole bus on this host; adjust
```

See `docs/reproduction.md` for endpoints, `/sys` paths, and REA commands.

## Parse a capture

`tools/wormhole_parse.py` is stdlib-only (no tshark/pyshark/scapy) and
reproduces the counts in `docs/capture-log.md` from the committed pcap.
It discovers the Wormhole by VID:PID during control enumeration, so it
does not depend on a Bus:Device number from a previous plug:

```sh
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --json
python3 -m unittest tools.test_wormhole_parse
```

## Tooling notes (this host)

- `reverse-engineer-anything` skill v49, `references/device-protocol-analysis.md` followed (identify transport → capture traffic → reconstruct CBW/CDB → map host binaries).
- `inspect_pe_imports` / `inspect_pe_resources` / `inspect_pe_certificates` worked (target-free).
- Deep analysis unblocked: Ghidra **12.1.4** installed side-by-side at `/opt/ghidra_12.1.4_PUBLIC` (12.2 untouched), `/usr/local/bin/ghidra` symlink repointed to 12.1.4 so REA 6.8.0 accepts it. `rea doctor --provider ghidra` healthy; SKLoader (988 functions), unpacked OTiArchive DLL (1,849), and GoBridgeDemon (1,204) all decompile. See `docs/pe-analysis.md` *Tooling*.
- `inspect_pcap_client` now passes: `tshark`/`capinfos` 4.4.19 at `/usr/bin/`. (The repo parser in `tools/` remains stdlib-only and does not need them.)
- `upx` 4.2.4 (`/usr/bin/upx`) installed — embedded DLL unpacked 104,488 → 310,312 B; real imports (380) and exports (12 `OTI_*`/`ArchiveTree*`) recovered. See `docs/pe-analysis.md`.

## License

Documentation and scripts in this repository are MIT. Original J5Create/KaiJet firmware and software binaries are not included and remain copyrighted by their respective owners.

## Acknowledgements

Thanks to Magic Control Technology Corp. for the hardware that prompted this study, and to the REA (`reverse-engineer-anything`) toolchain for the PE and capture-analysis workflow.
