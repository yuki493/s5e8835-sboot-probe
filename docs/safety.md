# Safety note

This repository is a **static analysis toolkit**. It reads a local `sboot.bin` and
prints addresses. It does not contain, invoke, or depend on any device-write path.

The upstream research it references (SVE-2026-3546 / CVE-2026-21155) does not have
that property. Read this before touching the upstream chain.

---

## 1. The fuse is one-way

The published chain ends by programming the Secure Boot KEY2 fuse. That is a
one-time hardware write:

- It cannot be undone by software.
- It cannot be undone by a service center.
- It cannot be undone by replacing the mainboard without effectively replacing the
  device.
- It is not a "soft brick" that a recovery image can fix.

Once the fuse is burned, the device's secure-boot state has changed permanently.
The exact consequence depends on the device and the chain, but the irreversibility
does not.

There is no undo. Plan accordingly.

---

## 2. There is no dry run

The upstream chain has no `--dry-run`, no simulation mode, and no "validate only"
flag. The final operation is the fuse burn. Running the chain "to see what happens"
is running the irreversible step.

Be skeptical of anyone who claims otherwise. A dry run would require one of:

- a full instruction-level emulator of the LK and its peripherals, with the fuse
  path modeled but not executed; or
- a hardware test point that permits the same writes without programming the fuse;
  or
- a vendor-provided engineering path that bypasses the fuse.

None of these ships with the public PoC. If a tool offers a "safe" mode, verify
what it actually does before trusting it with a device you care about.

Static analysis is the available dry run for the *resolver* stage: it tells you
whether the addresses and patterns match. It does not validate the fuse path, the
USB protocol, the loader, or the post-fuse boot.

---

## 3. What a no-fuse variant would require

A genuinely no-fuse validation path is a research project of its own. At minimum it
would need one of:

1. **A full LK rehost.** Load the LK image into an emulator, model the MMIO,
   storage, USB, and crypto peripherals it touches, and execute the loader path
   with the fuse operation trapped. This validates logic, not silicon. Building the
   peripheral models is substantial work, and a mismatch between the model and the
   device can produce false confidence.
2. **A hardware write path that does not touch the fuse.** For example, a
   documented ISP/test point or a socketed eMMC/SD path that lets you restore the
   original bootloader image after a failed attempt. This requires physical access,
   board-specific knowledge, and a recovery image. It is not available on a normal
   retail phone.
3. **A vendor-signed or engineering-signed test loader.** This requires material
   that is not public and may require an NDA or a service relationship.

This repository implements none of these. It deliberately stops at the resolver.

A "no-fuse" claim that does not provide one of the above is either a simulation
with unmodeled hardware or a misunderstanding of the chain.

---

## 4. Do not test on a main phone

The rule is simple:

> **Do not run the fuse chain on a phone you rely on.**

That includes:

- your daily driver;
- the phone with your bank apps, authenticators, and SIM;
- the phone you need for work or family;
- the only phone you own;
- a phone you plan to resell or return.

Use a sacrificial device that you can afford to lose completely. If you do not have
one, do not run the chain. "I have a backup" is not the same as "I can lose this
device permanently".

The static probe in this repository is safe to run on any `sboot.bin` file. Reading
a file is not testing on a phone.

---

## 5. Firmware handling

- Do not commit `sboot.bin`, BL tarballs, `*.lz4`, `*.tar.md5`, or extracted LK
  slices to this repository or any public mirror.
- Do not redistribute Samsung firmware. Obtain it from official sources and keep it
  local.
- The `.gitignore` in this repository excludes the common firmware extensions and
  directories, but it is a convenience, not a guarantee. Check `git status` before
  every commit.
- Hashes and addresses are fine to publish. Binary content is not.

---

## 6. Legal and ethical scope

- Test only devices you own or have explicit permission to modify.
- Follow local law and the terms that apply to your device and firmware.
- Do not use this work to bypass someone else's device protections, DRM, or
  account locks.
- Security research on your own hardware is legitimate; using it to harm others is
  not.

The authors of this repository provide static analysis and documentation. They do
not provide a flashing service, a fuse service, or a guarantee that any device will
boot after modification.

---

## 7. If you are unsure

Stop. The correct action when the outcome is irreversible and the validation is
incomplete is not to "try it once". It is to:

1. Re-read the failure signatures in [`findings.md`](findings.md).
2. Confirm the resolver output on a saved image, offline.
3. Wait for a second independent result, preferably on a different build.
4. Use a sacrificial device if you proceed at all.

No address in this repository is worth a main phone.
