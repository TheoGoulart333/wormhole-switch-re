# PE analysis: SKLoader.exe + embedded DLL

Tooling: `reverse-engineer-anything` skill v49.

- `inspect_pe_imports` on `SKLoader.exe` → `ev_07329fb9b606a2dffe0bf64dab8fc5e1a053b0393bddbd24d479a14241626fca`
- `inspect_pe_resources` on `SKLoader.exe` → `ev_6a73d90a3edee6195a19b687c0eb84a5be2b0ddec17c3b961c38fa8706e9e90a`
- `inspect_pe_certificates` on `SKLoader.exe` → `ev_442fc03a72f711ac630f37683084e8b506f83545b1309075e7464dac0f95c191`
- `inspect_pe_imports` on extracted embedded DLL → `ev_579fef7e2940f9aaa3ad2727ac9fcb3df7cdfa5b48a0beb5ef125777d48ea077`

Hashes (original blobs are not in this repo):

```
SKLoader.exe            db88b211c78e28eab1561baf2af3e4a2592299be326c6af2f557107d68630af8
Embedded DLL resource   acc30445201b26e86cb1f8c8bce85914edb907020e70d91bfb31824563d1e2d5 (104488 B, offset 70520 in SKLoader)
GSDD.lst                0ba5766dea8b66f8f49c42df2246144f9110d7e2c9e3f58e35c85812aed7cf93
GSDD.zz                 897f80733e41fb2d89d32a671ed3ea5a821d95739a7ab0784b0fd4c5d7b1b259
WormholeShell           179be25a0f11a16def7b9612ea5c3981dfb59616446dbdd8705eafb1fb28b5ce
GoBridgeDemon           152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68
```

## SKLoader.exe

- PE32 i386, 200392 B, 4 sections (`file`).
- Imphash (pefile) `be27a3513dcc60a4715f8432543394cf`, import directory RVA 62432 size 120, **no delay imports**.
- Coverage: 5 DLLs, 225 imports.

| DLL | Functions (sample) |
|-----|-------------------|
| `MFC42.DLL` | 150+ ordinal imports (MFC app) |
| `MSVCRT.dll` | `memset`, `malloc`, `strlen`, `_mbs*`, `atoi`, `atol` |
| `KERNEL32.dll` | `CloseHandle`, `CreateFileA`, `CreateProcessA`, `GetModuleFileNameA`, `GetLogicalDrives`, `GetDriveTypeA`, `MoveFileA`, `FindResourceA`/`LoadResource`, `Sleep` |
| `USER32.dll` | `EnableWindow`, `GetSystemMetrics`, `SendMessageA` |
| `SHELL32.dll` | `SHGetSpecialFolderPathA`, `ShellExecuteA` |

No `DeviceIoControl`, no `SetupDi*`, no `CreateFile` on `\\.\`-style device paths (beyond generic `CreateFileA`), no WinUSB. This is not a USB protocol driver — it is a deployment loader that enumerates drives, extracts resources, and spawns processes via `CreateProcessA`/`ShellExecuteA`.

## Resources (15 entries)

- Type **`DLL`** name **129** lang 1028, payload RVA 70520, offset 70520, size 104488, SHA-256 `acc3044520...` — MZ blob.
- 9 `RT_ICON` images (IDs 1-9), `RT_DIALOG` IDs 100/102, `RT_STRING` ID 7, `RT_GROUP_ICON`, `RT_VERSION` ID 1. Icons match J5Create branding visually.

The DLL resource is the payload: SKLoader extracts it at runtime (typical for KaiJet loaders). It was carved to `embedded_DLL_129.bin` for analysis (not tracked).

## Embedded DLL (UPX)

- `file`: `PE32 executable for MS Windows 4.00 (DLL), Intel i386, UPX compressed, 3 sections`
- Sections: `UPX0` (vsize 0x83000), `UPX1` (vsize 0x17000, raw 0x16400), `.rsrc` (0x02000). `UPX!` signature at offset ~992.
- REA imports: 9 DLLs, 13 functions total — UPX stub only:

```
KERNEL32: LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree
ADVAPI32: RegCloseKey
COMCTL32: _TrackMouseEvent
GDI32: BitBlt
MFC42 ordinal 4407
MSVCRT: atoi
RPCRT4: UuidCreate
SHELL32: ShellExecuteA
USER32: GetDC
```

Imphash `59908120d5bcb424b73bcd6a2bf054b1` reflects the stub, not the real code. Real imports/exports are hidden until decompression. `upx` is not installed on this host, so decompression and deeper REA analysis of the original code were not performed. The signed embedded DLLs under `GSDD` are expected to be the main Wormhole transfer logic, but that remains **unknown** from static stubs alone.

## Authenticode (SKLoader.exe)

- One `WIN_CERTIFICATE` at file offset 192512, length 7880, type 2 (PKCS#7), payload SHA-256 `9b92dc2b...`.
- Digest OID `1.3.14.3.2.26` (SHA1), signer RSA.
- Leaf subject:
  ```
  countryName=TW, organizationName=Magic Control Technology Corp.,
  organizationalUnitName=Digital ID Class 3 - Microsoft Software Validation v2,
  organizationalUnitName=GM' Secretary, commonName=Magic Control Technology Corp.
  serial_hex=1af6a29f359edb48a50633d3dae59d75
  not_before 120724000000Z / not_after 150725235959Z
  ```
- Chain: VeriSign Class 3 Code Signing 2010 CA (2010-2020) → VeriSign Class 3 Public Primary G5 (2006-2036) → Symantec timestamping G2/G4 (2022).
- REA does not verify signatures or chain validity — fields are structural only.

## Mac GoBridgeDemon (REA `open_binary`)

`open_binary` on `GoBridgeDemon` returned:

```
format: mach-o-universal, kind: executable,
sha256: 152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68,
architecture: x86
```

`binary_overview` then failed: **provider unavailable**, `unsupported_version` — installed Ghidra 12.2 at `/opt/ghidra_12.2_PUBLIC` vs REA requiring 12.1.x (verified 12.1.4). Deep disassembly is blocked until Ghidra is aligned. `inspect_macho` (Mach-O export inspection) is macOS-only (`unsupported_host`), so Mach-O analysis on Linux relies on `open_binary` + deep provider.

Session was closed with `close_binary`.
