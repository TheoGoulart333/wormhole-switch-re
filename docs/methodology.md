# Methodology

Followed `reverse-engineer-anything` v49 → `references/device-protocol-analysis.md` ("SCSI/USB device protocol reverse engineering (IronKey pattern)").

## Workflow

1. **Identify transport** — `lsusb` + `lsusb -t` + `/sys/bus/usb/devices` + `lsusb -v -d 0711:2211`. Established Bulk-Only mass storage + two boot HID interfaces. No video class (no USB camera on this host — 0x0E absent, no `/dev/video*`).
2. **Map kernel bindings** — `usb-storage`, `usbhid`, `/sys/block/srX`, `/dev/sgY`, `hidraw*`, `/proc/bus/input/devices`. Established `/dev/srX` (removable CD-ROM), `sgX`, `event*` input handlers.
3. **Capture traffic** — Linux `usbmon` + `tcpdump -i usbmon3` (bus 3). CBW (`USBC`) / CSW (`USBS`) reconstructed by hex dump; DATA IN decoded as SCSI sense / inquiry / capacity.
4. **Reconstruct command protocol** — SCSI opcode histogram + CDB decoding; LOG SENSE rejection and capacity anomaly documented as observed behaviour, not inferred firmware design.
5. **Map host binaries (REA)** —
   - Windows PE suite: `inspect_pe_imports` → `inspect_pe_resources` → `inspect_pe_certificates` on `SKLoader.exe` (dependency graph, embedded DLL, Authenticode chain). Then carved resource payload and re-ran `inspect_pe_imports` on the UPX stub.
   - Mac bundle: `open_binary` on `GoBridgeDemon`, fallback ELF strings for Mach-O symlinks (`@executable_path/../Frameworks/...`).
6. **Close / retain** — `close_binary` after `open_binary`. Evidence IDs are cited in `docs/pe-analysis.md`.

## IronKey-pattern notes applied

- The PE's `KERNEL32` imports (`CreateProcessA`, `ShellExecuteA`, `FindResource`/`LoadResource`) were the tell that the **loader is the protocol entry point**, mirroring the IronKey `ikpkcs11.dll` lesson: reverse the loader/embedded DLL first, not the wire.
- SCSI vendor-opcode hunting (IronKey 0x20) does **not** apply here — this device uses *standard* opcodes minimally (INQUIRY, TEST UNIT, REQUEST SENSE, READ CAPACITY, READ). No vendor CDBs were observed in the capture.
- Linux ELF fallback was not needed (no ELF target in the ISO).

## Tool / provider gaps

| Desired | Status | Remediation |
|---------|--------|-------------|
| Deep disassembly (`binary_overview`, `list_procedures`, `analyze_function`) | Blocked — Ghidra 12.2 (`/opt/ghidra_12.2_PUBLIC`) vs REA requires 12.1.x verified 12.1.4 (`unsupported_version`) | Install Ghidra 12.1.4 or update REA for 12.2 line |
| `tshark` REA pcap (`inspect_pcap_capture`, `inspect_packet_capture`) | Blocked — `tshark` binary not on PATH (GUI 4.4.19 + `capinfos` only) | `sudo apt install wireshark-common` or set `REA_TSHARK_COMMAND` to a tshark 4.x absolute path |
| UPX decompression | Not attempted — `upx` not installed | `sudo apt install upx-u` then `upx -d` on the carved DLL (in a VM) and re-run REA imports |
| `inspect_macho` | Unavailable on Linux (macOS-only) | Use `open_binary` (Ghidra) or macOS host |
| Live peer traffic | Not captured — second machine connected but no Wormhole session driven | Run GoBridge on both ends, move mouse/files, re-capture `usbmon3` |

## Preservation

- Original firmware/host blobs are **not** in this repo (copyrighted). Hashes are recorded in `docs/iso-payload.md` and `docs/pe-analysis.md`.
- Pcap retained in `captures/` (195 kB, sanitized — USB only, no network identifiers).
- Scratch working directory: `~/.hermes/cache/scratch/wormhole/` (not tracked). REA paths in evidence IDs point there.

## What remains unknown

- `GSDD.zz` / `GSDD.lst` container format (encryption/compression) and their role in SKLoader deployment.
- Embedded DLL's true imports/exports and protocol role (UPX-packed).
- Bridge peer-to-peer data channel between the two cable ends (internal to the microcontroller, not enumerated from one host).
- Why kernel block size (15.5 MiB) disagrees with `READ CAPACITY(10)` (3.1 MiB) — requires pre-plug kernel log or firmware dump to resolve.
