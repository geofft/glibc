#!/usr/bin/env python3
"""
analyze_math_symbols.py - Compare old and new versioned math symbols.

For each function that appears as both func@OLD_VER and func@@NEW_VER,
this script:
  1. Disassembles both symbol bodies.
  2. Checks whether the first branch-to-implementation instruction targets
     the same address (same underlying math = no algorithmic difference).
  3. Notes key wrapper differences (_LIB_VERSION check, direct errno set).

Works on any ELF shared library.  For cross-arch analysis, set OBJDUMP and
READELF to the appropriate cross-tools (e.g. aarch64-linux-gnu-objdump).

Usage:
  python3 analyze_math_symbols.py [/path/to/libm.so.6] [--verbose]
  OBJDUMP=aarch64-linux-gnu-objdump \\
  READELF=aarch64-linux-gnu-readelf \\
    python3 analyze_math_symbols.py /path/to/aarch64/libm.so.6
"""

import os
import re
import subprocess
import sys
from collections import defaultdict

OBJDUMP = os.environ.get("OBJDUMP", "objdump")
READELF = os.environ.get("READELF", "readelf")
VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv


def run(*cmd):
    r = subprocess.run(list(cmd), capture_output=True, text=True)
    return r.stdout


def get_versioned_funcs(lib):
    """
    Return {name: {"old": [(addr, size, ver), ...],
                   "new": [(addr, size, ver), ...]}}
    for every FUNC symbol that carries a version string.
    "new" = default version (@@), "old" = non-default (@).
    """
    out = run(READELF, "-W", "--syms", lib)
    funcs = defaultdict(lambda: {"old": [], "new": []})

    for line in out.splitlines():
        # readelf -W --syms columns:
        #   Num:  Value  Size  Type  Bind  Vis  Ndx  Name
        m = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line,
        )
        if not m:
            continue
        addr = int(m.group(1), 16)
        size = int(m.group(2))
        name_ver = m.group(3).strip()

        # Default version:     name@@VER
        dm = re.match(r"^([^@]+)@@(.+)$", name_ver)
        if dm:
            funcs[dm.group(1)]["new"].append((addr, size, dm.group(2)))
            continue

        # Non-default version: name@VER  (one @, not two)
        om = re.match(r"^([^@]+)@([^@].*)$", name_ver)
        if om:
            funcs[om.group(1)]["old"].append((addr, size, om.group(2)))

    return funcs


def disassemble(lib, addr, size):
    if size == 0:
        return ""
    end = addr + size
    return run(
        OBJDUMP, "-d", lib,
        f"--start-address=0x{addr:x}",
        f"--stop-address=0x{end:x}",
    )


def first_call_target(disasm):
    """
    Return the address of the first call-like instruction, or None.
    Handles x86/x86_64 (call/callq), AArch64/ARM (bl/blx),
    RISC-V (jal), PowerPC (bl/blr-like), s390 (brasl/bas).
    We look for the address that appears before the '<...>' annotation
    so we catch both direct calls and PLT stubs.
    """
    # Pattern: hex-address followed by optional PLT/function annotation
    # e.g.  "call   10400 <__ieee754_exp@plt>"
    #        "bl     1234 <exp@plt>"
    #        "jal    ra,5678 <exp@plt>"
    for line in disasm.splitlines():
        # Prefer lines with a <...> annotation (branch to a named target)
        m = re.search(r"\b([0-9a-f]+)\s+<[^>]+>", line)
        if m and re.search(r"\b(call[q]?|bl[x]?|jal|brasl|bas)\b", line):
            return int(m.group(1), 16)
    # Fallback: any call instruction with a hex target (no annotation)
    for line in disasm.splitlines():
        m = re.search(r"\b(call[q]?|bl[x]?|jal|brasl|bas)\b\s+\S*([0-9a-f]{4,})\b", line)
        if m:
            try:
                return int(m.group(2), 16)
            except ValueError:
                pass
    return None


def has(disasm, *patterns):
    d = disasm.lower()
    return any(p.lower() in d for p in patterns)


def analyze(lib):
    funcs = get_versioned_funcs(lib)
    pairs = {n: v for n, v in funcs.items() if v["old"] and v["new"]}

    if not pairs:
        print(f"No functions with multiple versioned symbols found in {lib}.")
        return

    print(f"Library : {lib}")
    print(f"Pairs   : {len(pairs)} functions with old+new versioned symbols\n")

    col = "{:<20} {:<24} {:<20} {:<10}  {}"
    print(col.format("Function", "Old@Version", "New@@Version", "Same fn?", "Notes"))
    print("-" * 100)

    mismatches = []
    for name in sorted(pairs):
        for old_addr, old_size, old_ver in pairs[name]["old"]:
            for new_addr, new_size, new_ver in pairs[name]["new"]:
                if old_size == 0 or new_size == 0:
                    print(col.format(
                        name, f"@{old_ver}", f"@@{new_ver}",
                        "???", "zero-size symbol — alias or plt stub, skip"))
                    continue

                old_dis = disassemble(lib, old_addr, old_size)
                new_dis = disassemble(lib, new_addr, new_size)

                old_call = first_call_target(old_dis)
                new_call = first_call_target(new_dis)

                same = (old_call is not None and
                        new_call is not None and
                        old_call == new_call)

                notes = []
                # Heuristic: _LIB_VERSION == _IEEE_ check shows up as cmp 0xffffffff
                if has(old_dis, "0xffffffff", "$-0x1"):
                    notes.append("old: checks _LIB_VERSION")
                # Direct errno = ERANGE (0x22 = 34) in new wrapper
                if has(new_dis, "$0x22,", "0x22,%"):
                    notes.append("new: sets ERANGE directly")
                # Direct errno = EDOM (0x21 = 33)
                if has(new_dis, "$0x21,", "0x21,%"):
                    notes.append("new: sets EDOM directly")
                if not same:
                    c1 = f"0x{old_call:x}" if old_call else "?"
                    c2 = f"0x{new_call:x}" if new_call else "?"
                    notes.append(f"*** DIFFERENT CALLS: old={c1} new={c2} ***")
                    mismatches.append(name)

                flag = "YES" if same else "** NO **"
                print(col.format(
                    name, f"@{old_ver}", f"@@{new_ver}",
                    flag, "; ".join(notes) if notes else "-"))

                if VERBOSE:
                    print(f"\n  --- old disasm ({old_size} bytes @ 0x{old_addr:x}) ---")
                    for ln in old_dis.splitlines()[3:]:
                        print(f"  {ln}")
                    print(f"\n  --- new disasm ({new_size} bytes @ 0x{new_addr:x}) ---")
                    for ln in new_dis.splitlines()[3:]:
                        print(f"  {ln}")
                    print()

    print()
    if mismatches:
        print(f"WARNING: {len(mismatches)} function(s) call DIFFERENT underlying implementations:")
        for n in mismatches:
            print(f"  {n}")
        print("These deserve deeper investigation.")
    else:
        print("All pairs call the same underlying implementation (wrapper-only differences).")

    # Emit version-pair table for use with test_math_compat
    print("\n# Version pairs for test_math_compat (copy-paste or pipe to bash):")
    for name in sorted(pairs):
        for old_addr, old_size, old_ver in pairs[name]["old"]:
            for new_addr, new_size, new_ver in pairs[name]["new"]:
                if old_size > 0 and new_size > 0:
                    print(f"# ./test_math_compat {name} {old_ver} {new_ver} <type>")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    lib = args[0] if args else "/lib/x86_64-linux-gnu/libm.so.6"
    analyze(lib)
