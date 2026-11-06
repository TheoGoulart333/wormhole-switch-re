# Live peer-active capture (2026-11-06)

Bidirectional `0xD9` HID injection between the two ends of the same cable,
captured simultaneously on both hosts.

- Local host: Wormhole at Bus 3 Dev 15, serial `C6629C6563582530`, `/dev/sg1` (was `/dev/sg2` before re-enum), `usbmon3`
- Peer host: Wormhole at Bus 1 Dev 6, serial `C6629C6563582531`, `/dev/sg9`, `usbmon1` (the second machine; its name and address are left out)

## Files

Published (local-host file filtered to the Wormhole; see [Sanitisation](#sanitisation)):

| File | Packets | Duration | SHA-256 |
|---|---|---|---|
| `captures/wormhole_bus3_live3_2026-11-06.pcap` (local host, Wormhole only) | 464 | 69.6 s | `02919837a7b06eab2978d33f460c10db9b6e6aa8d2139f806c4871ba16f6d70a` |
| `captures/wormhole_bus1_live_2026-11-06.pcap` (peer host, unfiltered) | 524 | 68.7 s | `3ed782f7a36e368dc8003d2eb641754716b125f368166669fc927162d7401ffa` |

Capinfos: `captures/wormhole_bus3_live3_capinfos.txt`, `captures/wormhole_bus1_live_capinfos.txt`.

The peer capture's bus holds only the Wormhole and its root hub, so it needed no filtering.

Raw source of the published local file (not published): 4598 packets, 70.0 s, SHA-256 `119ba9cf0fac3085e4c9b2b19cce87ff2f00bb1cadc071fe1f48af55ed147143`.

Earlier local-only runs (not published; no peer capture exists for either):

| Run | Raw packets | Duration | Raw SHA-256 | Wormhole (3:15) content |
|---|---|---|---|---|
| `bus3_live` (15:25) | 1924 | 48.5 s | `ea60b58a45f2434e7dbda359b4b5cc5fd20d3f7317c3bb770ce434c169d80c8f` | 183 SCSI commands; no `0xD9` CDBs; no HID reports |
| `bus3_live2` (15:35) | 6202 | 70.0 s | `285d8271f60d2b2ded321814a1464b4a689d105e40f5a4c5d8a75ced22a52590` | No `0xD9` CDBs; one EP3 mouse report `x=+60` at raw frame 849 |

## Sanitisation

A `tcpdump -i usbmonN` capture records every device on that bus. Besides the Wormhole, the raw live3 capture held:

- Logitech receiver `046d:c548` (3:7): 1,639 interrupt reports, all 9-byte report-ID-2 frames, with no report-ID-1 (keyboard) frames. The byte layout looks like pointer movement, not typing.
- IronKey S200 `1953:0202` (3:14): 138 SCSI commands, all TEST UNIT READY, REQUEST SENSE or `0x4A`.

Neither belongs in a public repo, so the published bus-3 file keeps only the Wormhole's packets:

```sh
python3 tools/filter_usbmon.py RAW.pcap --device 3:15 -o captures/OUT.pcap
```

Checked against the raw file: the 464 Wormhole packets, the 79 SCSI transactions and the 1 HID report are identical. `tools/test_filter_usbmon.py` covers the filter itself.

Not changed here: `captures/wormhole_bus3_2026-11-06.pcap` (committed in `e15d291`) also holds 1,688 packets from the Logitech receiver and 342 from the IronKey. Removing them from history needs a rewrite and force-push, so that is an open decision.

## Injection sequence

All CDBs built with `tools/wormhole_parse.py:build_vendor_hid_cdb` (`D9 '3'/'4' <12 payload> OT`),
sent with `sg_raw -C 1 /dev/sgX <bytes>` (space-separated, `--cmd-file` is not supported in this sg3-utils build).
Mouse payload = boot-mouse `buttons/X/Y/wheel` in bytes 0–3; keyboard = boot-keyboard `mods/reserved/keys…` in bytes 0–7 (HID usage `0x04='a'`, `0x05='b'`, `0x06='c'`).

| # | From | Packet | sg_raw result |
|---|------|--------|---------------|
| 1 | local | mouse `X=+10` `000a…` | Good |
| 2 | local | mouse `X=+20` `0014…` | Good |
| 3 | local | mouse `X=+30` `001e…` | Good |
| 4 | local | click down `01…` / up `00…` | Good ×2 |
| 5–6 | local | kbd `'a'` press/release `000004…` / `000000…` | Good ×2 |
| 7 | peer | mouse `X=+40` `0028…` | **CHECK CONDITION**, sense key 9, `ASC=0xFF/0xFF` |
| 8 | peer | mouse `X=+50` `0032…` | CHECK CONDITION (same sense) |
| 9 | peer | mouse `X=+60` `003c…` | **Good** |
| 10–11 | peer | click down/up | CHECK CONDITION ×2 |
| 12–13 | peer | kbd `'b'` press/release | CHECK CONDITION ×2 |
| 14–15 | local | kbd `'c'` press/release | Good ×2 |
| 16 | peer | wheel `00000001…` | CHECK CONDITION |

## Results (parser: `tools/wormhole_parse.py --hid`)

### Local → peer: clean forwarding

- 9 local CDBs decoded as valid 16-byte `D9` (`footer_ok=True, framing=True`), all `CSW=good`.
- Peer capture shows **9/9 HID reports received, 1:1 with the local send**:
  `EP3 mouse x=+10 / +20 / +30`, click `L=True` then `L=False`,
  `EP4 keyboard keys=[0x4]` then idle, `keys=[0x6]` then idle.
- Between injections, the only Wormhole commands are `0x4A` and `REQUEST SENSE`, in pairs every 2.02 s, on both hosts.

### Peer → local: mostly rejected / truncated

- Peer capture shows 8 `0xD9` CDBs on the wire, but **7 of 8 arrive as 15-byte CDBs** (`d93300280000000000000000004f54` = 15 B, missing one `00` before `OT`; parser `footer_ok=None, framing=False`). Each returns `CSW=CHECK CONDITION`, and the follow-up `REQUEST SENSE` reports `key 9 (Copy Abort), ASC=0xFF/0xFF`. That is the firmware's vendor sense; the parser's "Copy Abort" label is an alias, not a real SPC abort.
- Only `mouse60` arrives as a proper 16-byte CDB (`d933003c000000000000000000004f54`, `footer_ok=True`) with `CSW=good`. It is the only peer packet forwarded: the local host logs **one Wormhole HID report, EP3 mouse `x=+60`**, at raw frame 617.
- Hypothesis: the peer host's `sg_raw` (0.4.42) with `-C 1` still truncates or mis-frames some sends, or the peer firmware accepts `0xD9` only in some states. The one success in the middle of the sequence rules out a simple "peer end never accepts" explanation. Needs a re-run isolating the peer send path (e.g. `-C 1` vs default heuristic, CDB generation via Python SG_IO ioctl instead of sg_raw, and spacing sends past the USB-restart guard).

Note on counts: the raw local capture has 1,640 HID reports. 1,639 come from the Logitech receiver (3:7) and 1 from the Wormhole; the published file keeps only the Wormhole's one.

## What this closes / leaves open (`docs/methodology.md`)

- **Closed:** host→cable `0xD9` forwarding to the peer HID interfaces works with no GoBridge/Wormhole software running. `payload[0..3]` → boot-mouse EP3, `payload[0..7]` → boot-keyboard EP4, verified byte-for-byte.
- **Open:** the peer→local asymmetry above. The `bus3_live2` run adds one more peer→local report, EP3 `x=+60` at raw frame 849, in a run where this host sent no `0xD9` CDBs. Its peer side was not captured, so the sender is not established.
- **Open:** no live UPipe/file/clipboard traffic yet (`candidate UPipe: 0` on every capture), so the capacity-anomaly and `GSDD.zz` container questions are unchanged.
- **Open:** the committed `captures/wormhole_bus3_2026-11-06.pcap` holds other devices' traffic (see Sanitisation).
- **Next run:** the peer-send re-run described above. Not run yet.
