#!/usr/bin/env python3
"""Self-contained input_map diagnostic for an s5e8835 sboot.bin."""
import os, pathlib, struct, sys

sys.path.insert(0, os.environ.get("SVE_REPO", os.getcwd()))
import resolve


def bss_candidates(d):
    out = set()
    for off in range(0, len(d) - 0x18, 4):
        s, dup, e = struct.unpack_from("<QQQ", d, off)
        if (s == dup and 0x80000000 <= s < 0x1000000000
                and s % 0x1000 == 0 and s < e < s + 0x10000000
                and off % 0x1000 < 0x400):
            out.add(off & ~0xFFF)
    return sorted(out)


def find_slice(d):
    for start in bss_candidates(d):
        try:
            base, end, lo, hi = resolve.image_map(d[start:])
            return start, base, end, lo, hi
        except Exception as ex:
            print(f"  reject {start:#x}: {ex}")
    raise SystemExit("no valid LK slice")


def main(path):
    d = pathlib.Path(path).read_bytes()
    start, base, end, lo, hi = find_slice(d)
    data = d[start:]
    resolve.LK_BASE = base
    print(f"slice={start:#x} base={base:#x} bss=[{lo:#x},{hi:#x})")

    for ref, _, _ in resolve.str_refs(data, b"compressed_download_init"):
        s, e = max(0, ref - 0x20), min(len(data), ref + 0x90)
        print(f"\nref={start+ref:#x}  window={start+s:#x}..{start+e:#x}  ({e-s} bytes)")

        print("MOVZ/MOVK pairs (any dst):")
        found = False
        for off in range(s, e, 4):
            first = resolve.mov_wide(resolve.u32(data, off))
            if not first or first[3] != 0x52800000 or first[2] != 1:
                continue
            for off2 in range(off + 4, min(off + 0x24, e), 4):
                second = resolve.mov_wide(resolve.u32(data, off2))
                if (second and second[3] == 0x72800000 and second[2] == 1
                        and second[1] == first[1]):
                    print(f"  {start+off:#x}: x{first[1]} = {first[0] | second[0]:#x}")
                    found = True
        if not found:
            print("  (none in this window)")

        print("MOVZ constants:")
        for off in range(s, e, 4):
            dec = resolve.mov_wide(resolve.u32(data, off))
            if dec and dec[3] == 0x52800000 and dec[0]:
                print(f"  {start+off:#x}: w{dec[1]} = {dec[0]:#x}")

        try:
            print("patched input_map:", resolve.input_map(data))
        except Exception as ex:
            print("patched input_map FAIL:", ex)


if __name__ == "__main__":
    main(sys.argv[1])
