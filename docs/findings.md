# s5e8835 LK — static findings

**Scope:** Samsung Exynos 1380 (`s5e8835`) S-Boot/LK, as shipped in four official
BL packages. **Method:** static analysis only. No device, USB, flash, or fuse
operation was performed.

**Reference vulnerability:** SVE-2026-3546 / CVE-2026-21155.

---

## 1. Summary

The s5e8835 LK is structurally close to the s5e8825 LK that the public PoC
targets. Across four devices and four build dates:

- The LK sub-image is always at file offset `0xf1000`.
- It is always mapped at `0xf4800000` and ends at `0xf6000000`.
- The BSS range changes per build and is recovered from the image descriptor.
- The download-mode buffers `PAR_*` and `IN_*` are byte-identical to s5e8825.
- The slot size is loaded into `w10` instead of `w9`; the base/size MOVZ order
  also changes.
- Two resolver hunks make `parallel_download_init` and
  `compressed_download_init` pass, while preserving the s5e8825 A53 layout.
- Four of nine heuristics pass; five remain, all explainable by PAC prologues or
  unmapped s5e8835 code shapes.

No end-to-end exploit claim is made. The loader layout that follows these rows
has not been validated on s5e8835 hardware, and the only published validation
step is an irreversible fuse burn.

---

## 2. Device coverage

| Device | Model | Build | SPL | sboot.bin sha256 | LK slice | Base | BSS |
|---|---|---|---|---|---|---|---|
| Galaxy Tab S9 FE (Wi-Fi) | SM-X510 | X510XXSGEZI3 | 2026-09-05 | `a8abc835e5b7337fd6ed6009abe74bde18882d8807841ae6d48e62eebf44f267` | `0xf1000` | `0xf4800000` | `0xf4c3d000..0xf507a908` |
| Galaxy A26 5G | SM-A266B | A266BXXS4AYGA | 2025-08-01 | `79f169c9ecc03f604add536c5d3eb3c1a097ecabb7d4c3986ad20387bcd481c4` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5105df8` |
| Galaxy A35 5G | SM-A356E | A356EXXSBDZH1 | Oct 2026 | `797fcba92b90e6ceadd55ffa6adaea64793c4a378c0dca26efc8ce9f89e37484` | `0xf1000` | `0xf4800000` | `0xf4c3c000..0xf5079908` |
| Galaxy A54 5G | SM-A546E | A546EXXUNGZJ5 | Oct 2026 | `cb386232b2b32fc55fb3af7c676e54fb4fb43080e4d2adb1391edd8fdf5d9dc9` | `0xf1000` | `0xf4800000` | `0xf4c44000..0xf5087270` |

All four: `end = 0xf6000000`. All four `sboot.bin` files are `0x800000` bytes.

The four images are independent: one 2025 build (A26), one 2026-09 build (X510),
and two 2026-10 builds (A35, A54). The October builds reproducing the September
layout is the key stability result.

### 2.1 Marker offsets

The `s5e8835` ASCII marker appears at these file offsets:

| Device | Marker offsets |
|---|---|
| SM-X510 | `0x5e43` |
| SM-A266B | `0x5e43`, `0x26e42b`, `0x4f125f` |
| SM-A356E | `0x5e43`, `0x26ee28`, `0x4f125f` |
| SM-A546E | `0x5e43`, `0x276bf0`, `0x4f125f` |

`0x5e43` is in EPBL, before the LK slice. The later copies are inside LK and move
with the build. None of them are used as a load address.

---

## 3. LK layout

The BSS descriptor is a triple of 64-bit values near the start of the LK slice.
For the X510 the descriptor at file offset `0xf1030` is:

```text
0xf4c3d000, 0xf4c3d000, 0xf507a908
```

`resolve.image_map()` requires exactly one such triple in the first `0x400`
bytes, then locates the single mapping whose range contains the BSS and whose
name string resolves inside the image. That yields:

```text
base = 0xf4800000
end  = 0xf6000000
bss  = [0xf4c3d000, 0xf507a908)
```

The BSS ranges for all four images are in the coverage table. They differ by up
to `0x71000` in start and `0x8b4f0` in end. This is normal linker variation. Any
port that hardcodes a BSS range is wrong; the descriptor is the source of truth.

### 3.1 Slice discovery

`find_lk.py` scans for candidate BSS triples aligned to a page, rejects
candidates whose mapping cannot be validated, and reports both the accepted slice
and the rejected candidates. On the X510 and A26:

```text
BSS-triple slice candidates: ['0x81000', '0xf1000']
  reject 0x81000: LK BSS: []
```

The `0x81000` candidate is a false positive in an earlier blob. `image_map()`
rejects it because the BSS triple is not present at the start of that slice. The
real slice is `0xf1000`.

---

## 4. Download-mode buffers

After the patch, the two structural rows return the same values on all four
devices:

```text
parallel_download_init   = (0xce800000, 0x7e00000, 0x1e00000)
compressed_download_init = (0x890010000, 0x8000000, 0x2000000)
```

Which is:

```text
PAR_BASE = 0xce800000   PAR_SIZE = 0x7e00000   PAR_SLOT = 0x1e00000
IN_BASE  = 0x890010000  IN_SIZE  = 0x8000000  IN_SLOT  = 0x2000000
```

These are identical to the s5e8825 ground truth. On the X510 the two functions
resolve at:

```text
parallel_download_init   @ 0xf4863d64
compressed_download_init @ 0xf4863fb0
```

The X510 window around `compressed_download_init` contains:

```text
MOVZ/MOVK pairs:
  x13 = 0x890010000
  x0  = 0x890010000
  x0  = 0x89e010000
MOVZ constants:
  w9  = 0x8000000
  w10 = 0x2000000
  w2  = 0x8000000
  w2  = 0x7e00000
```

The presence of `w10 = 0x2000000` is the s5e8835 signature. The `w9 = 0x8000000`
value is the total size, not the slot size.

---

## 5. The `w9` / `w10` difference

The upstream predicates in both `parallel()` and `input_map()` accept only:

```python
slot[2:] == (9, 0, 0x52800000)
```

That is `mov w9, #imm` with a 16-bit immediate and no shift. It matches s5e8825.

On s5e8835 the slot size is materialized as:

```text
mov w10, #0x2000000     ; IN_SLOT
mov w9,  #0x40          ; stride/count constant
```

so the upstream resolver sees no slot candidate and returns `[]`. The patch
widens the predicate to:

```python
slot[2:] in ((9, 0, 0x52800000), (10, 0, 0x52800000))
```

The `parallel()` hunk also adds an upper bound to the total/slot ratio:

```python
2 <= total[1] // slot[1] <= 64
```

Without the bound, accepting `w10` can admit arithmetic coincidences in the
window. The valid s5e8835 ratios are far inside the range (`0x8000000 /
0x2000000 = 4` for IN; `0x7e00000 / 0x1e00000 ≈ 4.2` for PAR).

### 5.1 Ordering guard

The base, total, and slot MOVZs are not emitted in the same order on both SoCs.
Upstream relies on that order:

```python
if base_offset >= min(total[0], slot[0]):
    continue
```

On s5e8825 the 64-bit base pair precedes the size loads, so this rejects stale
candidates correctly. On s5e8835 the base pair may follow the slot load, so the
same test rejects the real candidate. The patch restricts the test to `w9`:

```python
if slot[2] == 9 and base_offset >= min(total[0], slot[0]):
    continue
```

This is the compatibility hinge. It is not cosmetic: without it, the resolver
is either empty on s5e8835 or too permissive on s5e8825.

---

## 6. A53 regression

The s5e8825 A53 (`SM-A536B`, build `A536BXXSNGZG3`) is the regression oracle.
With the final patch, `resolve.py` produces:

```text
base=0xf8800000 in=0x890010000 pack=0x894110000 code=0x896010100 out=0xc5000000 write=0xf8f03de8 cb=0xf8f04008 walk=0x33f03de8
```

`ground_truth/` was left untouched. The two block wrappers are confirmed non-PAC
by their prologue bytes at file offsets `0x137b58` and `0x137d54`:

```text
00137b58: fd7b bda9 f657 01a9 f44f 02a9 fd03 0091
00137d54: fd7b bda9 f657 01a9 f44f 02a9 fd03 0091
```

An intermediate revision that accepted `w10` without the ordering guard no
longer reproduced this line. The final guard restores it. Any future change to
the resolver must keep this exact output.

---

## 7. Probe result

Full nine-row probe on the X510 and A26 after the patch:

```text
PASS  parallel_download_init    (3464495104, 132120576, 31457280)
PASS  compressed_download_init  (36775723008, 134217728, 33554432)
FAIL  compressed output block   RuntimeError: compressed output: []
FAIL  Odin setter/reply         RuntimeError: Odin setter: []
FAIL  screen printf/cursor      IndexError: list index out of range
PASS  blk_bread                 4102318936        # X510
PASS  blk_bwrite                4102319444        # X510
FAIL  em_crypto_sha256          RuntimeError: SHA-256 XREF not found
FAIL  blk shift                 RuntimeError: block shift
```

The decimal PASS values are the same addresses shown in hex elsewhere:

```text
3464495104   = 0xce800000
132120576    = 0x7e00000
31457280     = 0x1e00000
36775723008  = 0x890010000
134217728    = 0x8000000
33554432     = 0x2000000
4102318936   = 0xf4846b58
4102319444   = 0xf4846d54
```

For the A26 the block wrappers are:

```text
blk_bread  = 0xf4845fb8  (4102315960)
blk_bwrite = 0xf48461b4  (4102316468)
```

Both wrappers begin with the non-PAC prologue `fd7b bda9 f657 01a9 f44f 02a9
fd03 0091`.

### 7.1 Failure signatures

| Row | Exact error | Interpretation |
|---|---|---|
| `compressed output block` | `RuntimeError: compressed output: []` | The s5e8825 instruction pattern for the output accumulator/base is absent or rescheduled. |
| `Odin setter/reply` | `RuntimeError: Odin setter: []` | The s5e8825 setter pattern did not match; callback/reply layout is unmapped. |
| `screen printf/cursor` | `IndexError: list index out of range` | The fixed non-PAC prologue was not found; the LK is PAC-built. |
| `em_crypto_sha256` | `RuntimeError: SHA-256 XREF not found` | Same PAC-prologue mismatch; the wrapper is reported at `0xf48645ec` calling `0xf48bea04`. |
| `blk shift` | `RuntimeError: block shift` | No qualifying `lsr`/shift pattern at the `blk_bread` call sites. |

These are not independent mysteries. The PAC explanation covers `screen` and
`sha256`; `blk shift` is downstream of the wrapper/call-site shape; `comp_output`
and `send_info` need a targeted disassembly pass.

---

## 8. Reproducibility and limits

Reproduce with:

```bash
python3 tools/find_lk.py sboot.bin
python3 tools/input_diag.py sboot.bin
```

The tools read the file, print addresses, and exit. They do not open USB, load a
driver, or write to the image.

Limits of this study:

- Four devices is a useful sample, not proof of family-wide coverage. A new
  build can move any address.
- Only the resolver stage is validated. The loader layout derived after these
  rows is not validated on s5e8835 hardware.
- The published chain's final step is irreversible. Static success does not
  imply a safe hardware path.
- A35/A54 were confirmed structurally and with the input diagnostic; their
  block-wrapper addresses and full nine-row tables were not captured.
- No November-2026-or-later image was available. That diff is the missing piece
  for the five remaining heuristics.

---

## 9. References

- Samsung SMR (November 2026): <https://security.samsungmobile.com/securityUpdate.smsb>
- CVE-2026-21155: <https://www.cve.org/CVERecord?id=CVE-2026-21155>
- NotCVE: <https://notcve.org/cve/CVE-2026-21155>
- Upstream PoC: <https://github.com/Gabriel2392/SVE-2026-3546>
- UnsignedChad writeup: <https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546>
- One UI 8 bootloader-unlock removal: <https://consumerrights.wiki/w/Samsung_One_UI_8_bootloader_restriction>
- Samsung BIT/ARB explainer: <https://samfw.com/blog/what-is-bit-binary-value>
- Capstone: <https://www.capstone-engine.org/>
- Ghidra: <https://ghidra-sre.org/>
