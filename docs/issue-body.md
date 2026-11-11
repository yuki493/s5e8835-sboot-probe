# s5e8835 (Exynos 1380) LK: download-mode buffers match s5e8825; 4/9 heuristics after two fixes

**Scope:** static resolver port for Samsung Exynos 1380 (`s5e8835`) S-Boot/LK.
**Related:** SVE-2026-3546 / CVE-2026-21155 (the public PoC targets `s5e8825`).

No device was connected, no firmware was flashed, and no fuse was touched. All
results below come from local `sboot.bin` files and the upstream resolver's
heuristics.

---

## Device coverage

Four independent s5e8835 images now agree on the LK layout and download buffers.

| Device | Model | Build | SPL | sboot.bin sha256 | LK slice | Base | BSS |
|---|---|---|---|---|---|---|---|
| Galaxy Tab S9 FE (Wi-Fi) | SM-X510 | X510XXSGEZI3 | 2026-09-05 | `a8abc835e5b7337fd6ed6009abe74bde18882d8807841ae6d48e62eebf44f267` | `0xf1000` | `0xf4800000` | `0xf4c3d000..0xf507a908` |
| Galaxy A26 5G | SM-A266B | A266BXXS4AYGA | 2025-08-01 | `79f169c9ecc03f604add536c5d3eb3c1a097ecabb7d4c3986ad20387bcd481c4` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5105df8` |
| Galaxy A35 5G | SM-A356E | A356EXXSBDZH1 | Oct 2026 | `797fcba92b90e6ceadd55ffa6adaea64793c4a378c0dca26efc8ce9f89e37484` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5079908` |
| Galaxy A54 5G | SM-A546E | A546EXXUNGZJ5 | Oct 2026 | `cb386232b2b32fc55fb3af7c676e54fb4fb43080e4d2adb1391edd8fdf5d9dc9` | `0xf1000` | `0xf4800000` | `0xf4c44000..0xf5087270` |

All four: `end = 0xf6000000`.

The October builds match the September layout. The BSS differs per build, which is
why the probe derives it with `image_map()` instead of hardcoding it.

---

## Structure

- Whole `sboot.bin`: `0x800000`.
- LK sub-image: file offset `0xf1000`, first instruction is code.
- X510 BSS descriptor at `0xf1030`: `(0xf4c3d000, 0xf4c3d000, 0xf507a908)`.
- X510 `image_map()`: base `0xf4800000`, end `0xf6000000`.
- The `s5e8835` string at `0x5e43` is in EPBL, not in the LK slice. Extra copies
  inside LK are build-specific.

---

## Download-mode buffers are identical to s5e8825

```text
parallel_download_init   @ 0xf4863d64  (X510)
  memset(0xce800000, 0, 0x7e00000); slot 0x1e00000 (w10), 0x40 (w9), 8 (w8)

compressed_download_init @ 0xf4863fb0  (X510)
  memset(0x890010000, 0, 0x8000000)
  memset(0x89e010000, 0, 0x7e00000)
  slot 0x2000000 (w10), 0x40 (w9), 8 (w8)
```

Identical on all four devices and identical to the s5e8825 ground truth:

```text
PAR_BASE=0xce800000   PAR_SIZE=0x7e00000   PAR_SLOT=0x1e00000
IN_BASE=0x890010000   IN_SIZE=0x8000000   IN_SLOT=0x2000000
```

---

## Patch

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

### Why `w10`

s5e8825 loads the slot size into `w9`. s5e8835 loads it into `w10`; `w9` carries
the `0x40` stride/count value. The original predicate therefore sees no slot on
s5e8835.

### Why the s5e8825 guard is conditional

The base/total/slot MOVZs are ordered differently. s5e8825 emits the 64-bit base
pair before the size loads and needs the `base_offset >= min(...)` rejection.
s5e8835 can emit the base after the slot load, so that rejection would discard the
valid candidate. Applying the rejection only for `slot[2] == 9` keeps both
families correct. The ratio bound `2..64` prevents the wider `w10` search from
accepting arithmetic coincidences.

---

## Probe after the patch

**X510 and A26: 4 PASS / 5 FAIL**

```text
PASS  parallel_download_init    (0xce800000, 0x7e00000, 0x1e00000)
PASS  compressed_download_init  (0x890010000, 0x8000000, 0x2000000)
FAIL  compressed output block   compressed output: []
FAIL  Odin setter/reply         Odin setter: []
FAIL  screen printf/cursor      IndexError
PASS  blk_bread                 0xf4846b58   # X510; A26: 0xf4845fb8
PASS  blk_bwrite                0xf4846d54   # X510; A26: 0xf48461b4
FAIL  em_crypto_sha256          SHA-256 XREF not found
FAIL  blk shift                 block shift
```

Both block wrappers use the non-PAC prologue:

```text
fd7b bda9 f657 01a9 f44f 02a9 fd03 0091
```

---

## Remaining failures

| Row | Signature | Likely cause |
|---|---|---|
| `compressed output block` | `compressed output: []` | s5e8835 output-accumulator pattern not located |
| `Odin setter/reply` | `Odin setter: []` | callback/reply setter layout not located |
| `screen printf/cursor` | `IndexError` | PAC prologue; fixed non-PAC matcher fails |
| `em_crypto_sha256` | `SHA-256 XREF not found` | PAC prologue; wrapper reported at `0xf48645ec`, callee `0xf48bea04` |
| `blk shift` | `block shift` | shift pattern at `blk_bread` call sites not matched |

The X510 LK is PAC-built. `screen_fns()` and `sha256_fn()` match fixed non-PAC
prologues and cannot find the new function starts. The two block wrappers that do
pass are explicitly non-PAC, which is consistent with that explanation.

`comp_output()` and `send_info()` are the two correctness-critical rows left. Both
need a targeted disassembly pass around `send_to_parallel_download` and the Odin
callback setter.

---

## Regression

The same patch still resolves the s5e8825 A53 (`SM-A536B`,
`A536BXXSNGZG3`):

```text
base=0xf8800000 in=0x890010000 pack=0x894110000 code=0x896010100 out=0xc5000000 write=0xf8f03de8 cb=0xf8f04008 walk=0x33f03de8
```

`ground_truth/` is unchanged. The `slot[2] == 9` guard is what keeps this green.

---

## Ask

1. Would a PR that parameterizes the resolver for a second SoC be useful, or would
   you prefer this stay an issue with the patch attached?
2. Does anyone have a **November-2026-or-later** BL package for any s5e8835 model
   (X510, A26, A35, A54) and can run the same static probe? A diff of the LK slice
   between October and November is the highest-value next artifact: it should show
   exactly which function the vendor changed and unblock `comp_output` /
   `send_info`.
3. A35/A54 owners: the structural rows and input diagnostic passed, but the full
   nine-row table and block-wrapper addresses were not captured. Posting them
   would complete the family table.

I cannot test on hardware: the published chain ends in an irreversible Secure
Boot KEY2 fuse, and there is no dry run. This issue is intentionally static-only.
No firmware is redistributed.
