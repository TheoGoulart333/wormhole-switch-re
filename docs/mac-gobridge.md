# Mac GoBridgeDemon + OTiTransfer: function-level analysis

Tooling: Ghidra 12.1.4 via REA 6.8.0 (see `docs/pe-analysis.md` *Tooling*).
Binaries are scratch extracts from the ISO (not tracked):

```
GoBridgeDemon  152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68
               mach-o-universal i386+ppc, 669K, 1204 procedures, 4423 strings
OTiTransfer    b7d7157eeeb00b6cc9fd53b25b54d6e700e1008b558ee0de47762a7bc4314e45
               mach-o-universal i386+ppc dylib, 138K, 297 procedures, 578 strings
```

Evidence (`binary_overview`):
- GoBridgeDemon → `ev_26ed15872d2e8057e62b56f5b5aa5f30087694ab0948d13ec10b987d18ce79a8`
- OTiTransfer → `ev_bd407798648d872299c964442aa6a6eccea40094ded9b770dcb230eaa4da8580`

## GoBridgeDemon `_main` (0x2b2f)

Pseudocode → `ev_1c86876877ea1bb1a960277d78f1771095680f28f81ac3cbe32d1f7a895bdad1`
(analyze parent `ev_edb7c7a3f228403bea854ad1341adf6d8df308959559c2ff28007a9060a04a5b`).

Startup, in order:

1. `NSAutoreleasePool`, `NSApplicationLoad`, `NSLock` → `g_sendDataLock`,
   `THMFileManager` → `g_serverObject`.
2. `NSConnection`: root object = `THMFileManager`, name **`GodDamnDaemon`**
   (CFString `cf_GodDamnDaemon`), `enableMultipleThreads`. The Wormhole
   app talks to the daemon over this distributed-object connection.
3. `NSDistributedNotificationCenter` posts **`GBDaemonisalive`** with the
   bundle identifier.
4. `CGEventTapCreate` ×2 (both `kCGHeadInsertEventTap`, added to the
   run loop via `CFMachPortCreateRunLoopSource`):
   - Gesture (only if `Gestalt('sysv') > 0x106f`):
     `CGEventTapCreate(kCGSessionEventTap, …, mask 0xe01c0000, _myCGGestureEventCallback)`
     — failure logs `Create gesture event tap failed: %@`.
   - Mouse/HID: `CGEventTapCreate(kCGHIDEventTap, …, mask 0x4000fe, _myCGMOuseEventCallback)`
     — failure logs `Create mouse event tap failed: %@`.
   - `myCGKeyboardEventCallback` (0x26f9) also exists as a symbol; keyboard
     events ride the same tap/handler path (see below).
5. `CFRunLoopTimer` (~0.5 s tolerance) firing `_checkEnableAccess` — polls
   accessibility permission (`isAccessOn`) so taps can be (re)installed.
6. `_createWindow()` (shield window), `_RunApplicationEventLoop()`,
   teardown, log `GoBridgeDemon terminated: %@`.

## Event flow: tap → consume-or-forward

`myCGMOuseEventCallback` (0x2499), pseudocode → `ev_4fd6b3aa5b06a29fa0a82f8add7c6736a22a251aa42f5137f56115c5655f0ad0`
(analyze parent `ev_d6455fdcefbf254151f471bc9ce444ce145950240e4491e331a955d4f4b2dc4c`):

- Tap disabled (`type == -2`) → log and return `NULL` (swallow).
- Else `[g_serverObject handleSystemEvent:event]` — `THMFileManager_handleSystemEvent:`
  (0x20f7e, pseudocode → `ev_8fc7fbbac2d2f3a6538938909532952749fd180bfc4767bb24bfde47c6b92d6d`)
  is a thin synchronized forwarder:
  `CGEventGetType(event)` → `[[self+0xec handleCarbonEvent:withEvent:]` — the
  `KMLink` delegate object (`KMKeyMouse.dylib`) — returning its status.
- Status meanings (from the callback's branches):
  - `0` — local: return the event (deliver locally). If a remote session was
    active, un-hide the cursor (`NSCursor unhide` × N), `orderOut` the shield
    window, clear state.
  - `≠0`, was inactive — remote session starting: activate the app, show the
    shield window at `(0,0)` (`makeKeyAndOrderFront`), hide the cursor
    (`NSCursor hide`, re-hide after 0.5 s, log `Hide cursor: %d`), set state.
  - `3` — log `Daemon send CGEvent to local`, return the event locally.
  - Otherwise (cursor hidden, remote) — return `NULL`: **the event is
    swallowed locally** and has been forwarded by `handleCarbonEvent` /
    `post*HIDEventToRemote` instead.
- `CGEvent` string search: 18 hits in the inventory
  (parent `ev_cc40a1395fa7d1533f1ebf8d8c20fc05c5e56891723acb6b4ff5a914f4a20bbb`).

## HID forwarding (GoBridgeDemon side)

- `-[THMFileManager postMouseHIDEventToRemote:]` (0x22fdb, pseudocode →
  `ev_430caf6959d56af2cb191ed70fe9f3a9a8950ac652d7dd34b973080549265d84`):
  builds a HID packet buffer from the event payload (scroll-direction byte
  handling at `self+0xf8`), then `OTi_SendHIDPacket(1, packet)` if the
  enable flag at `self+0x51` is set. Type `1` = mouse.
- `-[THMFileManager postKeyboardHIDEventToRemote:]` (0x1bcaa, pseudocode →
  `ev_2c947c33d7cfd85a908e8ea0822b1ec913de5767a7f88d76c0c70a0b59afdc1c`):
  pass-through — `OTi_SendHIDPacket(packet)` when enabled.
  `postMultimediaHIDEventToRemote:` (0x1bccb) is the third variant.
- Reverse direction: `postMouseHIDEventToLocal:` (0x22f5a) reconstructs and
  posts CGEvents locally on the receiving side.
- `OTi_SendHIDPacket` is imported from
  `@executable_path/../Frameworks/OTiTransfer.framework/Versions/A/OTiTransfer`.

## File-transfer command surface (ObjC selectors)

`search_procedures THMGB` → `ev_328058d67f415c92dd17a98fff1ef8a9f630b754f91809d378bd2bd4601fec69`.
The daemon implements a command protocol over `THMGBServer` /
`THMGBClient` (`THMGBCommandHandler`, `THMGBError`):

- **Server** (`THMGBServer(ServerCommandHandler)`): `handleLogin`,
  `handleLogout`, `handleUploadFileData`, `handleUploadMultipleFile`,
  `handleUploadMultipleFilesConfirm`, `handleUploadMultipleFileAbort`,
  `handleUploadMultipleFilesWithZeroLength`, `handleDownloadMultipleFile`,
  `handleDownloadMultipleFileAbort`, `handleRenameFile`, `handleDeleteFile`,
  `handleMakeNewDirectory`, `handleRemoveDirectory`, `handleGetDirectoryInfo`,
  `handleChangeFileAttribute`, `handleExtraXMLPacket`,
  `_NotifyUPipeMesssageUpToAppThread:` (spelling as in binary),
  `handleCommand:` dispatcher.
- **Client** (`THMGBClient(ClientCommandHandler)`): `handleUploadMultipleFileConfirmation`,
  `handleDownloadFileZero`, `handleDownloadFileData`, `handleDirectoryInfo`,
  `handleDomainFolders:`, `handleUploadMultiFileError`,
  `handleUploadDownloadFinish:`, `handleTransferFailed:`, `handleDriveInfo:`,
  `handleRequestResponse:`, `handleCommand:`.
- `THMFileManager` (~200 methods) implements sessions/queues
  (`uploadSessionWithID:`, `downloadSessionWithID:`, `rxQueues`, `txQueue`
  counters), remote XML (`sendXml:`, `receiveSwitchToRemoteXML:`),
  hotkey switching (`onHotkeySwitch:`, `isSwitchToRemote`,
  `SendSwitchToRemoteCmd:andX:andY:andW:andH:`), clipboard
  (`buildClipboardFileData:`, `handleDownloadClipboardFile:to:`),
  wallpaper/misc-info sync, and UDP-pipe notifications
  (`postUPipeMessageToRemote:`, `upNotifyUpipeMessage:`).

No `socket` strings in the inventory; local app↔daemon traffic is the
`NSConnection` (`GodDamnDaemon`) + `UPipe` notifications. Peer traffic
does not go through sockets in this binary — see OTiTransfer below.

## OTiTransfer: the USB transport

`OTiTransporter` (C++, ~70 methods): `FindAllDevices`, `OTiMatching`,
`AuthoringDevicesMatching`, `findUsbInterface`, `setDeviceService`,
`MountMedia`/`UnmountMedia`, `SendSCSICommandSendData` /
`SendSCSICommandReceiveData`, `sendHIDPacket`, `GetData`/`PutData`,
`RunLoopFunction`/`ReceiveData`/`SendData`, `processReceiveState` /
`processTransferState`, `GetSideType` / `GetFunctionType` / `GetDeviceMode`
(cable side A/B), `NorDetectBound` / `NandDetectBound`,
`ReadNorInitTable` / `ReadNanInitTable`, `GetFlashType`, `IsSamsungDevice`,
`Is5000Device`, `CheckLicense`, `VerifyMPStatus`, `USBRestart`,
`ObtainExclusive`/`ReleaseExclusive`, sense→result mapping in
`SendSCSICommandSendData`.

### Device matching

`OTiTransporter::FindAllDevices` (0x2e86, pseudocode →
`ev_c39c2d84102fca11d4b5b0e6e764da1f77d3b483749835e9958a165df3984207`,
analyze parent `ev_0b8407674d4d67262505eddcebf5ffabf9595e997b4401bd860321bad139e7ec`):
`IOMasterPort` → `AuthoringDevicesMatching()` →
`IOServiceGetMatchingServices`, iterate, `CheckParents`, read
`IORegistryEntryCreateCFProperties`, filter on
`DeviceCharacteristics`. Results carry `Device_Product_ID` =
`OTiTransporter::productID` (0xb9bc) and `Device_Vender_ID` =
`OTiTransporter::vendorID` (0xb9c0) globals — zero in the file image
(`read_bytes` → `ev_47939154302f9e01277339997cb1fcf4ef4f75f85bd31797461bcd4f1e3932c5`),
set at runtime from the framework `Info.plist` via
`CopyValueFromInfoPlistForKey`:

```xml
<key>idVendor</key><integer>1809</integer>   <!-- 0x0711 -->
<key>idProduct</key><integer>8721</integer>  <!-- 0x2211 -->
```

So macOS matches the cable by the same VID:PID as Linux (`0711:2211`);
`IOUSB` string search: GoBridgeDemon 0 hits, OTiTransfer 2 hits;
`0711` 0 hits in both (IDs are plist integers, not strings).

### HID wire format — the peer link

`OTi_SendHIDPacket(type, packet)` (0x24b9, pseudocode →
`ev_a634aa7fba791d81bb673dd26715943e5a632687030beac5ade86f6f9e1d2cc2`,
analyze parent `ev_093143d729c79d17d55e54ef481b6aeb2adb011efcda28e6130d0fbde14a236f`):

- Null packet or no transporter → return `-2`.
- < 10 s since USB restart (`USBRestart` timestamp at transporter+0x4c) →
  log `send HID ignored because of USB restart: %@`, return 0.
- Else `CFDataCreate(packet, 14)` → `OTiTransporter::sendHIDPacket(type, data)`.

`OTiTransporter::sendHIDPacket` (0x4654, pseudocode →
`ev_06ae4453f902070991bca6fad7197fd59ad2a735330eb693f8f31362d694a11c`,
analyze parent `ev_9e1ee833e176f37bc8cecbe4de834159c5ee329bdd233d28ca13a20c4724689a`):

```
u8 packet[16] = {
  0xD9,                 // magic
  '3' | '4' | '6',      // type: 1=mouse → '3', 2=keyboard → '4', 3=multimedia → '6'
  payload[12],          // first 12 bytes of the 14-byte CFData packet
  'O', 'T'              // trailing signature (stack locals local_22/local_21)
}
if type == 3: NSLog("key HID: %02x …", payload[0..7])
SendSCSICommandSendData(this, packet, 0x10, NULL, &result, &otiResult, …)
return otiResult == 0
```

The 16-byte buffer **is the SCSI CDB**: `SendSCSICommandSendData`
(0x3f4a, pseudocode → `ev_ceec34182f5720d6cc032984cecfdfb39a646a3ff248eb69eb532a37c5993908`,
analyze parent `ev_36407fbbd9da1ea1555610bc1f2fe79aadfca8b62b4c525eb6f604596d3451b7`)
takes `(CDB, CDB_len=0x10, CFData* data, …)`, builds an `SCSITask`
(vtable: set-CDB `+0x20`, optional data-write `+0x2c`, `ExecuteTaskSync`
2000 ms `+0x30`, status `+0x40`, service response `+0x48`), and maps
sense `(key<<16 | ASC<<8 | ASCQ)` to OTi result codes
(e.g. `0x98200→0x82`, `0x62800→8`, `0x23a00→5`, `0x52000/0x72700→6`),
logging `SenseKey(byte2)=%d byte12=%d byte13=%d`, `otiResult %x`, and
`cdb: 0x%02x …` (first 8 CDB bytes).

In other words: **host→cable traffic is a vendor SCSI command whose
16-byte CDB is the packet** (`D9 <type> <12 payload> O T`). The cable
microcontroller forwards it to the peer end; the peer's OTiTransfer
`RunLoopFunction`/`ReceiveData`/`processReceiveState` collects packets
(`GetData`/`PutData`, Tx/Rx queues) and GoBridgeDemon replays them as
CGEvents. This is why the idle Linux capture shows only standard kernel
CDBs (INQUIRY / LOG SENSE / …): vendor CDBs only appear when the
Wormhole software actively sends HID/file data. File-transfer packets
use the same `SendSCSICommand*` plumbing with a data phase
(`CFData` at `+0x2c`); their packet magic still needs a live
capture to confirm.

## Unknowns (narrowed)

- File/clipboard packet magic and framing beyond the HID `D9` format —
  needs a live peer-active usbmon capture (see `docs/reproduction.md` §6).
  `tools/wormhole_parse.py` will need a vendor-CDB decoder for it.
- `handleCarbonEvent:withEvent:` lives in `KMKeyMouse.dylib`
  (`KMLink` delegate) — not analyzed yet.
- Cable-side forwarding (how the microcontroller routes CDB packets to
  the peer end) is not in host binaries; needs firmware or two-end capture.
