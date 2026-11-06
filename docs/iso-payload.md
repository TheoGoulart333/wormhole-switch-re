# ISO payload: WORMHOLE volume

Volume label `WORMHOLE`, ISO9660, 16252928 B (15.5 MiB block-device size), mounted read-only at `/tmp/wormhole_mnt` (first plug) and `/media/rich/Wormhole` (second plug). Contents identical between plugs.

```
autorun.inf                         73 B    2013-10-31
SKLoader.exe                    200392 B    2013-10-23
Deployment/
  Config/LoaderMenifest.xml        313 B    2013-10-31
  GSDD.lst                       12663 B    2013-10-23
  GSDD.zz                    1407767 B    2013-10-23
Wormhole.app/
  Contents/
    Info.plist                    1357 B
    PkgInfo                          8 B
    MacOS/WormholeShell          52468 B    Mach-O universal (i386 + ppc_7400)
    Resources/
      icon_01.icns               69864 B
      Wormhole.tgz             1387029 B    gzip, 2013-10-31 → 4085760 B
      English.lproj/MainMenu.nib 33637 B
```

File output:

```
autorun.inf: Microsoft Windows Autorun file
SKLoader.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections
GSDD.lst: data
GSDD.zz: data
LoaderMenifest.xml: XML 1.0, UTF-8 (with BOM), CRLF
WormholeShell: Mach-O universal binary with 2 architectures
Wormhole.tgz: gzip compressed data, from Unix, original size 4085760
```

## autorun.inf

```
[autorun]
open=SKLoader.exe
icon=SKLoader.exe
ISOVersion=1.0.1107.56
```

Classic AutoRun loader — deprecated by modern Windows, but the intended bootstrap on plug-in.

## Manifest: KaiJet / Wormhole1107

`Deployment/Config/LoaderMenifest.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<gsmanifest version="1.0">
    <loader uuid="{1D2DF83A-32C9-4b01-9033-32E1F35337B1}" version="1.0.1325.32" oemversion="1.0.1107.56">
    <options>
        <OEMInfo CompanyID="KaiJet" ProductName="Wormhole1107"></OEMInfo>
    </options>
    </loader>
</gsmanifest>
```

Loader version `1.0.1325.32`, OEM product `Wormhole1107`, ISO version `1.0.1107.56`.

`Wormhole.app/Contents/Info.plist` (shell bundle):

```
CFBundleExecutable = WormholeShell
CFBundleIdentifier = com.KaiJet.WormholeShell
Archive            = Wormhole.tgz
Destination        = ~/Library
Demon Bundle Identifier = com.KaiJet.GoBridgeDemon
UI Bundle Identifier    = com.KaiJet.Wormhole
LSMinimumSystemVersion  = 10.5
LSUIElement = true
NSHumanReadableCopyright = Copyright © 2011 j5 create c/o KaiJet Technology
CFBundleShortVersionString = 1.0.1107.56
```

## SKLoader.exe (Windows)

- SHA-256 `db88b211c78e28eab1561baf2af3e4a2592299be326c6af2f557107d68630af8`
- PE analysis in `docs/pe-analysis.md`: MFC app, drops an embedded UPX DLL resource and spawns it. No USB imports (no `DeviceIoControl`) — it is a deployment loader, not a USB driver.
- Signed by Magic Control Technology Corp. (TW).

## Deployment/GSDD.*

- `GSDD.lst` — SHA-256 `0ba5766dea8b66f8f49c42df2246144f9110d7e2c9e3f58e35c85812aed7cf93`, 12663 B. Header bytes are high-entropy — no `MZ`, `PK`, `ELF`, or Mach-O magic in the first scan. Likely an encrypted/compressed manifest/table for SKLoader to consume.
- `GSDD.zz` — SHA-256 `897f80733e41fb2d89d32a671ed3ea5a821d95739a7ab0784b0fd4c5d7b1b259`, 1407767 B. First bytes `4F 54 02 1D...`, contains `MZ` at offset 10376 (20 MZ hits overall). No `PK`/`ELF`. Unknown container — likely a KaiJet deployment archive (hot-and-warm compression + encryption) that SKLoader unpacks under Windows. Dynamic analysis under Wine is the suggested next step; do **not** redistribute the original blobs (copyrighted).

## macOS WormholeShell → Wormhole.tgz

`WormholeShell` (SHA-256 `179be25a0f11a16def7b9612ea5c3981dfb59616446dbdd8705eafb1fb28b5ce`) strings include:

```
/usr/bin/tar
Try: /usr/bin/tar -xzf '%@' -C '%@'
Archive
Destination
Uninstall App
Preferences
removeLoginItem
extractMacKMLinkExes
```

It extracts `Wormhole.tgz` into the destination (`~/Library` per plist). Extracted tree (`mac_extract/`):

```
Wormhole.app/Contents/MacOS/Wormhole
Wormhole.app/Contents/PlugIns/DownloadUpdateTool.app/.../DownloadUpdateTool
Wormhole.app/Contents/PlugIns/GoBridgeDemon.app/Contents/MacOS/GoBridgeDemon
  (Mach-O universal i386+ppc_7400, SHA-256 152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68)
Wormhole.app/Contents/PlugIns/GoBridgeDemon.app/Contents/Frameworks/
  KMClipboard.dylib
  KMKeyMouse.dylib
  FileChgEvent.dylib
  OTiTransfer.framework/Versions/A/OTiTransfer
```

`GoBridgeDemon` links `@executable_path/../Frameworks/KMClipboard.dylib`, `../Frameworks/KMKeyMouse.dylib`, `../Frameworks/OTiTransfer.framework/Versions/A/OTiTransfer` and Carbon/Cocoa/CoreServices/CoreFoundation. Strings show the KVM/clipboard role:

```
flagsChanged: / keyDown: / keyUp:
myCGMOuseEventCallback type=-2
Demon send CGEvent to local
myCGKeyboardEventCallback type=-2
Hide cursor..... / Unhide cursor...... %d
CGEvent keyboard tap disabled!! enable again!!
CGEvent keyboard tap enabled!!! / CGEvent mouse tap enabled!!! / CGEvent gesture tap enabled!!!
Demon getScreenInfo
GodDamnDaemon / GBDaemon is alive
Create keyboard event tap failed!! / Create mouse event tap failed!!
isAccessOn
GoBridge Demon terminated!!!
```

`KMKeyMouse` links `IOKit.framework` — consistent with HID bridge control. `KMClipboard` implies cross-machine clipboard sync. `OTiTransfer` + `FileChgEvent` suggest the file-drag path (chunking, change events).

Full bundle inventory from `tar -tzf Wormhole.tgz` is preserved in the working notes; extracting it does not imply any additional firmware — it is host software.
