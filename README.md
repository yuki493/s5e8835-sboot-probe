# s5e8835 S-Boot Probe

**Static resolver probe for Samsung Exynos 1380 (`s5e8835`) S-Boot/LK — SVE-2026-3546 / CVE-2026-21155.**

> **STATIC ONLY.** This repository contains no USB code, no flashing code, no fuse
> code, and no device-write path. Nothing here talks to a phone. The tools read a
> local `sboot.bin` and print addresses. That is the whole attack surface.

---

## Why this exists

The public SVE-2026-3546 proof of concept targets **s5e8825 only**. It resolves the
s5e8825 LK image, builds a loader for its memory layout, and ends in a one-way
Secure Boot KEY2 fuse. Owners of the newer **Exynos 1380 / s5e8835** devices —
Galaxy Tab S9 FE, Galaxy A26 5G, Galaxy A35 5G, Galaxy A54 5G — had no documented
answer to the first question: *does the resolver even understand this LK?*

This repository answers that question statically. It documents the s5e8835 LK
layout, the two resolver changes needed to make `parallel()` and `input_map()`
recognize it, and the exact heuristics that still fail. The result was validated
against four independent `sboot.bin` images spanning 2025-08 to 2026-10.

No hardware was used. No device was unlocked. No fuse was burned.

---

## What it does

- Locates the LK sub-image inside a raw `sboot.bin` by scanning for the BSS
  descriptor triple, then validates the candidate with `resolve.image_map()`.
- Derives the LK load base, end address, and BSS range **from the image**, rather
  than hardcoding them per build.
- Runs the nine upstream resolver heuristics and prints a PASS/FAIL table.
- Dumps the `compressed_download_init` instruction window and the MOVZ/MOVK
  constants that `input_map()` sees, so a failing build can be diagnosed without
  a disassembler.
- Ships the exact `resolve.py` patch needed for the s5e8835 slot-register layout
  while preserving the s5e8825 behavior.

## What it explicitly does not do

- It does **not** connect to a device, enumerate USB, or open a serial port.
- It does **not** flash, erase, unlock, or write anything.
- It does **not** burn, plan, or simulate a fuse. There is no dry run.
- It does **not** build or run a loader payload.
- It does **not** redistribute Samsung firmware or the upstream `resolve.py`.
- It does **not** claim that the exploit chain is portable end-to-end. Only the
  static resolver stage is covered here.

---

## Device coverage

All four images are `sboot.bin` extracted from official BL packages. The table is
the complete dataset behind the findings.

| Device | Model | Build | SPL | sboot.bin sha256 | LK slice | Base | BSS |
|---|---|---|---|---|---|---|---|
| Galaxy Tab S9 FE (Wi-Fi) | SM-X510 | X510XXSGEZI3 | 2026-09-05 | `a8abc835e5b7337fd6ed6009abe74bde18882d8807841ae6d48e62eebf44f267` | `0xf1000` | `0xf4800000` | `0xf4c3d000..0xf507a908` |
| Galaxy A26 5G | SM-A266B | A266BXXS4AYGA | 2025-08-01 | `79f169c9ecc03f604add536c5d3eb3c1a097ecabb7d4c3986ad20387bcd481c4` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5105df8` |
| Galaxy A35 5G | SM-A356E | A356EXXSBDZH1 | Oct 2026 | `797fcba92b90e6ceadd55ffa6adaea64793c4a378c0dca26efc8ce9f89e37484` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5079908` |
| Galaxy A54 5G | SM-A546E | A546EXXUNGZJ5 | Oct 2026 | `cb386232b2b32fc55fb3af7c676e54fb4fb43080e4d2adb1391edd8fdf5d9dc9` | `0xf1000` | `0xf4800000` | `0xf4c44000..0xf5087270` |

**All four:** `end = 0xf6000000`.

Download-mode buffers are identical across the family:

```text
PAR_BASE = 0xce800000   PAR_SIZE = 0x7e00000   PAR_SLOT = 0x1e00000
IN_BASE  = 0x890010000  IN_SIZE  = 0x8000000  IN_SLOT  = 0x2000000
```

The BSS range differs on every build. That is expected: it is linker output, not a
protocol constant. `image_map()` recovers it from the descriptor at the head of the
LK slice, so it must never be hardcoded.

---

## Findings

### 1. LK layout is stable across four devices

Every image places the LK sub-image at file offset **`0xf1000`** and maps it at
**`0xf4800000`**, ending at **`0xf6000000`**. The BSS descriptor sits at
`0xf1030` (file offset), immediately inside the slice.

The whole `sboot.bin` is `0x800000` bytes. The first `0xf1000` bytes are EPBL and
other pre-LK blobs; the `s5e8835` string at file offset `0x5e43` lives there, not
in LK. Additional marker copies appear inside LK on some builds:

| Device | `s5e8835` marker file offsets |
|---|---|
| SM-X510 | `0x5e43` |
| SM-A266B | `0x5e43`, `0x26e42b`, `0x4f125f` |
| SM-A356E | `0x5e43`, `0x26ee28`, `0x4f125f` |
| SM-A546E | `0x5e43`, `0x276bf0`, `0x4f125f` |

### 2. The download buffers match s5e8825 exactly

Both `parallel_download_init` and `compressed_download_init` materialize the same
buffer geometry as the s5e8825 ground truth. On the X510 the functions resolve at:

```text
parallel_download_init   @ 0xf4863d64
compressed_download_init @ 0xf4863fb0
```

The patch changes only *how the slot register is recognized*, not the buffer
values. After the patch both rows return the exact s5e8825 values on every
s5e8835 build tested.

### 3. The slot register moved from `w9` to `w10`

The upstream resolver was written against s5e8825, where the per-slot size is
loaded into **`w9`**:

```text
mov  w9, #0x1e00000      ; PAR_SLOT (or #0x2000000 for IN_SLOT)
```

On s5e8835 LK, the same constant is loaded into **`w10`**, while `w9` carries the
`0x40` stride/count value:

```text
mov  w10, #0x2000000     ; slot size
mov  w9,  #0x40          ; slot count / stride constant
```

The upstream predicates `slot[2:] != (9, 0, 0x52800000)` therefore reject the real
slot on s5e8835 and the resolvers return an empty candidate list. The patch accepts
`w9` **or** `w10`.

### 4. The s5e8825 ordering guard

Simply accepting `w10` everywhere is not safe. The two SoCs schedule the base,
total-size, and slot-size MOVZs in a different order:

- **s5e8825 (`w9`):** the 64-bit base pair is emitted **before** the size loads.
  Upstream's `base_offset >= min(total[0], slot[0])` rejection is part of the
  original filter.
- **s5e8835 (`w10`):** the base pair can be emitted **after** the slot load, so the
  same rejection discards the valid candidate.

The final patch applies the ordering rejection only when the slot register is
`w9`. That is the whole reason the A53 regression stays green.

### 5. The A53 regression

An intermediate revision accepted `w10` without the conditional. On the s5e8825
A53 image that admitted a spurious candidate and the regression line no longer
reproduced. The final `slot[2] == 9` guard restores the ground truth:

```text
base=0xf8800000 in=0x890010000 pack=0x894110000 code=0x896010100 out=0xc5000000 write=0xf8f03de8 cb=0xf8f04008 walk=0x33f03de8
```

Any future resolver change must reproduce that line before it is considered
portable.

### 6. Block wrappers

`blk_bread` and `blk_bwrite` resolve by symbol XREF and non-PAC prologue on two
builds:

| Device | `blk_bread` | `blk_bwrite` |
|---|---|---|
| SM-X510 | `0xf4846b58` | `0xf4846d54` |
| SM-A266B | `0xf4845fb8` | `0xf48461b4` |

Both wrappers use the classic non-PAC prologue:

```text
fd7b bda9 f657 01a9 f44f 02a9 fd03 0091
```

A35/A54 wrapper addresses were not captured in the tester report. The rows are
expected to pass there as well, but this repository does not claim an address it
did not observe.

### 7. Five heuristics still fail

On the X510 and A26 after the patch, the nine-row probe is **4 PASS / 5 FAIL**:

| Row | Failure signature |
|---|---|
| `compressed output block` | `RuntimeError: compressed output: []` |
| `Odin setter/reply` | `RuntimeError: Odin setter: []` |
| `screen printf/cursor` | `IndexError: list index out of range` |
| `em_crypto_sha256` | `RuntimeError: SHA-256 XREF not found` |
| `blk shift` | `RuntimeError: block shift` |

These are heuristic-shape failures, not evidence that the functions are absent:

- The s5e8835 LK is **PAC-built**. `screen_fns()` and `sha256_fn()` match fixed
  non-PAC prologues, so they cannot find the new function starts.
- `comp_output()` and `send_info()` encode s5e8825 instruction scheduling and
  callback layouts; the s5e8835 variants have not been mapped yet.
- `blk shift` depends on the `blk_bread` call sites and follows the same PAC /
  scheduling difference.

The two block wrappers that do pass are explicitly non-PAC, which corroborates the
PAC explanation rather than contradicting it.

---

## Quick start

### 1. Clone the upstream project

```bash
git clone https://github.com/Gabriel2392/SVE-2026-3546.git
cd SVE-2026-3546
```

### 2. Apply the patch

```bash
git apply /path/to/s5e8835-sboot-probe/resolve.patch
# or: patch -p1 < /path/to/s5e8835-sboot-probe/resolve.patch
```

Verify both hunks:

```bash
grep -c "slot\[2:\] not in" resolve.py   # 2
grep -c "slot\[2\] == 9" resolve.py      # 1
```

### 3. Point the tools at the patched resolver

Either export the repository path (the tools prepend it to `sys.path`):

```bash
export SVE_REPO="$PWD"
```

Or copy the tools next to `resolve.py`:

```bash
cp /path/to/s5e8835-sboot-probe/tools/find_lk.py .
cp /path/to/s5e8835-sboot-probe/tools/input_diag.py .
```

The import is deliberately defensive:

```python
import os, sys
sys.path.insert(0, os.environ.get("SVE_REPO", os.getcwd()))
import resolve
```

### 4. Obtain the BL child for your device

Download the official BL package for your exact model and build (for example
`BL_X510XXSGEZI3_..._MULTI_CERT.tar.md5`). Use the vendor/FUS source appropriate
for your region. **Do not commit or redistribute the firmware.**

### 5. Unpack the image

```bash
unzip BL_*.zip                 # if the download is zipped
tar -xf BL_*.tar.md5           # tar with an appended MD5
lz4 -d sboot.bin.lz4 sboot.bin # only if the member is lz4-compressed
```

### 6. Run the probe

```bash
python3 find_lk.py sboot.bin
```

### 7. Diagnose `input_map()` if needed

```bash
python3 input_diag.py sboot.bin
```

`input_diag.py` is self-contained: it does not import `find_lk`. It prints the
`compressed_download_init` window, MOVZ/MOVK pairs, MOVZ constants, and the patched
`input_map()` result.

---

## Reading the output

`find_lk.py` prints nine rows. A `FAIL` means the upstream heuristic did not match
this build; it does not mean the firmware is corrupt or the device is unsupported.

| # | Row | What it resolves | Healthy s5e8835 result |
|---|---|---|---|
| 1 | `parallel_download_init` | PAR buffer base/size/slot | `(0xce800000, 0x7e00000, 0x1e00000)` |
| 2 | `compressed_download_init` | IN buffer base/size/slot | `(0x890010000, 0x8000000, 0x2000000)` |
| 3 | `compressed output block` | Output accumulator base and block size | currently `compressed output: []` |
| 4 | `Odin setter/reply` | Odin callback setter, reply buffer, default send | currently `Odin setter: []` |
| 5 | `screen printf/cursor` | Screen printf, cursor getter, display update | currently `IndexError` |
| 6 | `blk_bread` | `blk_bread` wrapper address | `0xf4846b58` on X510 |
| 7 | `blk_bwrite` | `blk_bwrite` wrapper address | `0xf4846d54` on X510 |
| 8 | `em_crypto_sha256` | SHA-256 wrapper and call count | currently `SHA-256 XREF not found` |
| 9 | `blk shift` | Block-size shift from `blk_bread` call sites | currently `block shift` |

Rows 1, 2, 6, and 7 are the structural rows. They are the ones that must pass
before any loader layout can be derived. Rows 3–5, 8, and 9 are the remaining port
work.

---

## The patch

```diff
diff --git a/resolve.py b/resolve.py
index 0ca6493..a8b947a 100755
--- a/resolve.py
+++ b/resolve.py
@@ -153,10 +153,10 @@ def parallel(data):
                 if total[2:] != (2, 0, 0x52800000):
                     continue
                 for slot in items:
-                    if slot[2:] != (9, 0, 0x52800000):
+                    if slot[2:] not in ((9, 0, 0x52800000), (10, 0, 0x52800000)):
                         continue
                     span = max(base[0], total[0], slot[0]) - min(base[0], total[0], slot[0])
-                    if (span <= 0x20 and slot[1] and total[1] // slot[1] >= 2 and
+                    if (span <= 0x20 and slot[1] and 2 <= total[1] // slot[1] <= 64 and
                             total[1] >= slot[1] * (total[1] // slot[1])):
                         candidates.append((base[1], total[1], slot[1]))
     candidates = sorted(set(candidates))
@@ -283,9 +283,9 @@ def input_map(data):
                 if total[2:] != (2, 0, 0x52800000):
                     continue
                 for slot in items:
-                    if slot[2:] != (9, 0, 0x52800000):
+                    if slot[2:] not in ((9, 0, 0x52800000), (10, 0, 0x52800000)):
                         continue
-                    if base_offset >= min(total[0], slot[0]):
+                    if slot[2] == 9 and base_offset >= min(total[0], slot[0]):
                         continue
                     if max(base_offset, total[0], slot[0]) - min(base_offset, total[0], slot[0]) > 0x24:
                         continue
```

The first hunk teaches both resolvers that the slot size may live in `w10`; it
also bounds the total/slot ratio to `2..64`, which prevents a wide `w10` search
from inventing implausible candidates. The second hunk is the s5e8825 compatibility
guard: the base-before-size rejection is applied **only** when the slot register is
`w9`. s5e8825 needs that rejection; s5e8835 emits the base after the slot and must
skip it. Without the `slot[2] == 9` condition the patch breaks the A53; with it,
both families resolve correctly.

---

## Porting notes

### Add another s5e8835 device

1. Extract `sboot.bin` from the matching BL package and record the SHA-256.
2. Run `find_lk.py` unpatched first. If `parallel_download_init` and
   `compressed_download_init` fail with an empty candidate list, the build uses the
   `w10` layout and needs this patch. If they pass, it still uses the `w9` layout;
   record that, because it is a useful counterexample.
3. After patching, confirm both structural rows return the family constants:
   `0xce800000/0x7e00000/0x1e00000` and `0x890010000/0x8000000/0x2000000`.
4. Compare the BSS range but do not expect it to match. `image_map()` must derive it.
5. Capture the block-wrapper addresses and the five failure signatures. A build that
   passes a row the X510 fails is more valuable than one that matches it.

### Add another s5e8825 device

Run the patch and verify the A53 ground truth still reproduces. The ordering guard
must keep `input_map()` on the original candidate. Then run the probe and compare
against the known s5e8825 values; a change here means the patch is too permissive,
not that the device is special.

### What to compare

- LK slice offset, load base, end address.
- BSS descriptor range and the derived `image_map()` result.
- PAR/IN triplets (base, size, slot).
- Slot register (`w9` vs `w10`) and the relative order of base/total/slot MOVZs.
- Block-wrapper addresses and prologue bytes (PAC vs non-PAC).
- The nine row statuses, especially which rows newly pass.

### A53 ground truth

```text
base=0xf8800000 in=0x890010000 pack=0x894110000 code=0x896010100 out=0xc5000000 write=0xf8f03de8 cb=0xf8f04008 walk=0x33f03de8
```

Treat this as a regression test, not a suggestion. If a resolver change moves any
of these values, the change is not ready.

---

## Remaining work

- **`comp_output`** — locate the s5e8835 output accumulator and block size. The
  current pattern is s5e8825-specific.
- **`send_info`** — locate the Odin callback setter, reply buffer, and default send
  path. This is the other correctness-critical row.
- **`screen`** — make `screen_fns()` PAC-tolerant, or stub the cosmetic progress
  output for a first port.
- **`sha256`** — the X510 wrapper is reported at `0xf48645ec`, calling
  `0xf48bea04`; the prologue matcher needs to accept the PAC form.
- **`blk shift`** — follows from the `blk_bread` call sites; can be pinned for a
  first port once the wrapper is stable.
- **PAC prologues** — the general fix behind `screen` and `sha256`: match
  `pacibsp`/`autibsp`-style prologues instead of fixed non-PAC sequences.
- **November-2026+ BL diff** — the highest-value next artifact. The September and
  October builds still share the layout; a November SMR build is where the vendor
  change should appear. A diff of the LK slice between an October and a November
  build would identify exactly which function the patch moved.

None of these require a device. All can be done from `sboot.bin` and a disassembler.

---

## Safety

**The fuse is one-way.** The SVE-2026-3546 chain ends in a Secure Boot KEY2 fuse
burn. Once that fuse is programmed, it cannot be undone by software, a service
center, or a board swap. There is no rollback.

**There is no dry run.** The published chain does not have a simulation mode, a
"check only" flag, or a way to validate the loader without committing the fuse.
Any claim of a dry run should be treated as false until independently demonstrated.

**Do not run `flash_and_fuse.py` on a main phone.** Not on the phone you use, not
on the phone you might need tomorrow, not "just once to see". Use a sacrificial
device that you can afford to lose, or do not run it at all.

**No firmware redistribution.** This repository contains no Samsung binaries, no
`sboot.bin`, no BL tarballs, and no extracted LK slices. Obtain firmware from
official sources and keep it out of git.

**No device writes.** The tools here only read a local file. If a tool asks for USB
permissions, you are running something else.

See [`docs/safety.md`](docs/safety.md) for the full safety note.

---

## Credits and references

This work builds directly on the public research below. The upstream project
targets s5e8825; this repository is an independent static port study for s5e8835.
No upstream code is redistributed in full.

- **Upstream PoC** — Gabriel2392, `SVE-2026-3546`:
  <https://github.com/Gabriel2392/SVE-2026-3546>
- **UnsignedChad writeup** — CVE-2026-21155 / SVE-2026-3546:
  <https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546>
- **Samsung SMR, November 2026**:
  <https://security.samsungmobile.com/securityUpdate.smsb>
- **CVE-2026-21155**:
  <https://www.cve.org/CVERecord?id=CVE-2026-21155>
- **NotCVE entry**:
  <https://notcve.org/cve/CVE-2026-21155>
- **One UI 8 bootloader-unlock removal**:
  <https://consumerrights.wiki/w/Samsung_One_UI_8_bootloader_restriction>
- **Samsung BIT/ARB explainer**:
  <https://samfw.com/blog/what-is-bit-binary-value>
- **Capstone disassembler**:
  <https://www.capstone-engine.org/>
- **Ghidra**:
  <https://ghidra-sre.org/>

Device data was provided by four independent owners who ran the static probe on
their own `sboot.bin`. They are credited collectively; no device identifiers or
personal data are published here.

---

## License

The original scripts and documentation in this repository are released under the
**MIT License**. See [`LICENSE`](LICENSE).

`resolve.patch` is a derivative of `resolve.py` from the upstream
`Gabriel2392/SVE-2026-3546` project. It is included so it can be applied to that
project, and it carries the upstream author's terms. This repository claims no
ownership over the upstream code and does not redistribute it in full. If you
redistribute the patch, keep the upstream attribution and comply with the upstream
project's terms.

Samsung, Exynos, Galaxy, and related marks are trademarks of Samsung Electronics.
This is independent security research, not an official Samsung publication.
