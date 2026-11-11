#!/usr/bin/env python3
"""Locate the LK sub-image inside a raw sboot.bin, then probe resolve.py heuristics."""
import hashlib, os, pathlib, struct, sys

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


def find_lk(d):
    cands = bss_candidates(d)
    print(f"BSS-triple slice candidates: {[hex(c) for c in cands]}")
    for start in cands:
        try:
            return start, resolve.image_map(d[start:])
        except Exception as e:
            print(f"  reject {start:#x}: {e}")
    raise SystemExit("no valid LK slice found")


def main(path):
    d = pathlib.Path(path).read_bytes()
    print(f"file  : {path}")
    print(f"size  : {len(d):#x}")
    print(f"sha256: {hashlib.sha256(d).hexdigest()}")
    i = d.find(b"s5e8835")
    print(f"s5e8835 marker: {i:#x}" if i >= 0 else "s5e8835 marker: absent")

    start, (base, end, lo, hi) = find_lk(d)
    print(f"\nLK slice at {start:#x}")
    print(f"base={base:#x} end={end:#x} bss=[{lo:#x},{hi:#x})\n")
    data = d[start:]
    resolve.LK_BASE = base

    results = []
    def step(name, fn):
        try:
            results.append((name, "PASS", str(fn())))
        except Exception as e:
            results.append((name, "FAIL", f"{type(e).__name__}: {e}"))

    step("parallel_download_init",   lambda: resolve.parallel(data))
    step("compressed_download_init", lambda: resolve.input_map(data))
    step("compressed output block",  lambda: resolve.comp_output(data))
    step("Odin setter/reply",        lambda: resolve.send_info(data, lo, hi))
    step("screen printf/cursor",     lambda: resolve.screen_fns(data))
    step("blk_bread",  lambda: resolve.named_fn(data, b"blk_bread", 168))
    step("blk_bwrite", lambda: resolve.named_fn(data, b"blk_bwrite", 176))
    step("em_crypto_sha256", lambda: resolve.sha256_fn(data))
    try:
        bread = resolve.named_fn(data, b"blk_bread", 168)
        step("blk shift", lambda: resolve.io_shift(data, bread))
    except Exception as e:
        results.append(("blk shift", "SKIP", str(e)))

    w = max(len(n) for n, _, _ in results)
    for name, status, detail in results:
        print(f"{status:4}  {name:<{w}}  {detail}")


if __name__ == "__main__":
    main(sys.argv[1])
