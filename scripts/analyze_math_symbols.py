#!/usr/bin/env python3
"""
analyze_math_symbols.py - Compare old and new versioned math symbols.

For each function that appears as both func@OLD_VER and func@@NEW_VER,
this script:
  1. Disassembles both symbol bodies.
  2. Determines whether they ultimately execute the same math code by
     checking three equivalent structures that glibc uses:
       (a) old wrapper calls/jumps to old_target; new symbol also
           calls/jumps to old_target  →  both call same underlying fn
       (b) old wrapper calls/jumps to old_target; new symbol's entry
           address IS old_target  →  old wraps the new implementation
       (c) new symbol calls/jumps to new_target; old symbol's entry
           address IS new_target  →  (reverse alias, unusual)
  3. Notes key wrapper differences (_LIB_VERSION check, direct errno).

Works on any ELF shared library.  For cross-arch analysis, set OBJDUMP
and READELF to the appropriate cross-tools, e.g.:
  OBJDUMP=aarch64-linux-gnu-objdump \\
  READELF=aarch64-linux-gnu-readelf \\
    python3 analyze_math_symbols.py /path/to/aarch64/libm.so.6

Usage:
  python3 analyze_math_symbols.py [/path/to/libm.so.6] [--verbose]
"""

import os
import re
import subprocess
import sys
from collections import defaultdict

OBJDUMP  = os.environ.get("OBJDUMP",  "objdump")
READELF  = os.environ.get("READELF",  "readelf")
VERBOSE  = "--verbose" in sys.argv or "-v" in sys.argv


def run(*cmd):
    r = subprocess.run(list(cmd), capture_output=True, text=True)
    return r.stdout


# ---------------------------------------------------------------------------
# Symbol extraction
# ---------------------------------------------------------------------------

def get_versioned_funcs(lib):
    """
    Return {name: {"old": [(addr, size, ver), ...],
                   "new": [(addr, size, ver), ...]}}
    for every FUNC symbol that carries a glibc version string.
    "new" = default version (@@), "old" = non-default (@).
    """
    out = run(READELF, "-W", "--syms", lib)
    funcs = defaultdict(lambda: {"old": [], "new": []})

    for line in out.splitlines():
        # readelf -W --syms columns (may have leading spaces):
        #   Num:  Value  Size  Type  Bind  Vis  Ndx  Name
        m = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line,
        )
        if not m:
            continue
        addr     = int(m.group(1), 16)
        size     = int(m.group(2))
        name_ver = m.group(3).strip()

        # Default version:      name@@VER
        dm = re.match(r"^([^@]+)@@(.+)$", name_ver)
        if dm:
            funcs[dm.group(1)]["new"].append((addr, size, dm.group(2)))
            continue

        # Non-default version:  name@VER  (exactly one @)
        om = re.match(r"^([^@]+)@([^@].*)$", name_ver)
        if om:
            funcs[om.group(1)]["old"].append((addr, size, om.group(2)))

    return funcs


# ---------------------------------------------------------------------------
# Disassembly helpers
# ---------------------------------------------------------------------------

def disassemble(lib, addr, size):
    if size == 0:
        return ""
    return run(
        OBJDUMP, "-d", lib,
        f"--start-address=0x{addr:x}",
        f"--stop-address=0x{addr + size:x}",
    )


def branch_targets(disasm):
    """
    Return a list of (address, is_call) tuples for every unconditional
    branch-to-function instruction in the disassembly.

    "Unconditional branch to a named symbol" covers all the ways glibc
    wrappers delegate to the underlying implementation:
      x86/x86_64  : call / callq  (direct call)
                    jmp  / jmpq   (tail call, e.g. to PLT or internal symbol)
      AArch64/ARM : bl / blx      (branch with link — always a call)
      RISC-V      : jal           (jump-and-link)
      PowerPC     : bl / b        (branch with link / unconditional)
      s390        : brasl / bas

    Conditional branches (jne, jae, b.ne, …) are intentionally excluded.
    """
    results = []

    # Opcodes that are always calls (set a return address)
    CALL_OPS = re.compile(r'\b(call[q]?|bl[x]?|brasl|bas|jal)\b')
    # x86 unconditional jump (not conditional variants like ja/jb/je/jne…)
    # The key is the word boundary: "jmp" or "jmpq" but NOT "jmp" as prefix
    # of a conditional like "jmpz" (which doesn't exist but be safe).
    UJMP_OPS = re.compile(r'\bjmp[q]?\b')
    # ARM/PowerPC unconditional branch WITHOUT a condition-code suffix
    # (e.g. "b <target>" but not "b.ne <target>" or "bne <target>")
    UBRANCH_OPS = re.compile(r'\bb\b')

    for line in disasm.splitlines():
        is_call   = bool(CALL_OPS.search(line))
        is_ujmp   = bool(UJMP_OPS.search(line))
        is_ubranch = bool(UBRANCH_OPS.search(line))

        if not (is_call or is_ujmp or is_ubranch):
            continue

        # Extract the target address from a "<symbol>" annotation.
        # This is most reliable: it's present for both PLT stubs
        # (  jmp  10340 <log@plt>  ) and internal symbols
        # (  jmp  28120 <__fmod_finite@GLIBC_2.15>  ).
        addr_m = re.search(r'\b([0-9a-f]+)\s+<[^>]+>', line)
        if addr_m:
            results.append((int(addr_m.group(1), 16), is_call))
            continue

        # Fallback for annotationless bare-address targets
        addr_m = re.search(
            r'(?:call[q]?|jmp[q]?|bl[x]?|brasl|bas|jal)\s+(?:\S+,\s*)?'
            r'(0x)?([0-9a-f]{4,})\b',
            line,
        )
        if addr_m:
            try:
                results.append((int(addr_m.group(2) or addr_m.group(1), 16),
                                is_call))
            except (ValueError, IndexError, TypeError):
                pass

    return results


def first_branch(disasm):
    """Return the address of the first call or PLT jmp, or None."""
    tgts = branch_targets(disasm)
    return tgts[0][0] if tgts else None


# ---------------------------------------------------------------------------
# Core comparison logic
# ---------------------------------------------------------------------------

def same_underlying(old_addr, old_dis, new_addr, new_dis):
    """
    Return True when old and new ultimately execute the same math code.

    Three structural patterns used in glibc:
      (a) Both wrappers delegate to the same target:
              old → T,  new → T
      (b) Old is a wrapper around the new implementation:
              old → T,  and  T == new_addr
      (c) New is a wrapper around the old implementation (unusual):
              new → T,  and  T == old_addr
    """
    old_tgt = first_branch(old_dis)
    new_tgt = first_branch(new_dis)

    # (a) both call same thing
    if old_tgt is not None and new_tgt is not None and old_tgt == new_tgt:
        return True, "both call same underlying fn"

    # (b) old wraps new: old calls/jumps to the new symbol's address
    if old_tgt is not None and old_tgt == new_addr:
        return True, "old is a SVID wrapper around the new implementation"

    # (c) new wraps old (rare but possible)
    if new_tgt is not None and new_tgt == old_addr:
        return True, "new calls old implementation"

    reason = (f"old_tgt=0x{old_tgt:x}" if old_tgt else "old_tgt=?") + \
             (f" new_tgt=0x{new_tgt:x}" if new_tgt else " new_tgt=?")
    return False, reason


# ---------------------------------------------------------------------------
# Wrapper-pattern heuristics (for the Notes column)
# ---------------------------------------------------------------------------

def has(text, *patterns):
    t = text.lower()
    return any(p.lower() in t for p in patterns)


def wrapper_notes(old_dis, new_dis):
    notes = []
    if has(old_dis, "0xffffffff", "$-0x1", ",-1"):
        notes.append("old: _LIB_VERSION check")
    if has(new_dis, "$0x22,", "0x22,%", "#22\t", " 22\n"):
        notes.append("new: sets ERANGE directly")
    if has(new_dis, "$0x21,", "0x21,%", "#21\t", " 21\n"):
        notes.append("new: sets EDOM directly")
    return notes


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

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
    print("-" * 105)

    genuinely_different = []

    for name in sorted(pairs):
        for old_addr, old_size, old_ver in pairs[name]["old"]:
            for new_addr, new_size, new_ver in pairs[name]["new"]:
                if old_size == 0 or new_size == 0:
                    print(col.format(
                        name, f"@{old_ver}", f"@@{new_ver}",
                        "???", "zero-size symbol (alias/plt stub) — skip"))
                    continue

                old_dis = disassemble(lib, old_addr, old_size)
                new_dis = disassemble(lib, new_addr, new_size)

                same, reason = same_underlying(
                    old_addr, old_dis, new_addr, new_dis
                )
                notes = wrapper_notes(old_dis, new_dis)
                if not same:
                    notes.append(f"*** {reason} ***")
                    genuinely_different.append((name, old_ver, new_ver, reason))

                flag = "YES" if same else "** NO **"
                print(col.format(
                    name, f"@{old_ver}", f"@@{new_ver}",
                    flag, "; ".join(notes) if notes else "-"))

                if VERBOSE:
                    print(f"\n  reason: {reason}")
                    print(f"  --- old ({old_size}B @ 0x{old_addr:x}) ---")
                    for ln in old_dis.splitlines()[3:]:
                        print(f"    {ln}")
                    print(f"  --- new ({new_size}B @ 0x{new_addr:x}) ---")
                    for ln in new_dis.splitlines()[3:]:
                        print(f"    {ln}")
                    print()

    print()
    if genuinely_different:
        print(f"NOTICE: {len(genuinely_different)} pair(s) with different underlying code:")
        for name, ov, nv, r in genuinely_different:
            print(f"  {name}  (@{ov} vs @@{nv}): {r}")
        print("  These are NOT necessarily bugs — e.g. totalorder changed its argument types.")
    else:
        print("All pairs run the same underlying math implementation.")
        print("Differences are wrapper-only (SVID error handling).")

    # Emit ready-to-use command lines for test_math_compat
    print("\n# Commands for test_math_compat (fill in type: d/dd/f/ff):")
    for name in sorted(pairs):
        for old_addr, old_size, old_ver in pairs[name]["old"]:
            for new_addr, new_size, new_ver in pairs[name]["new"]:
                if old_size > 0 and new_size > 0:
                    print(f"./test_math_compat {name:15} {old_ver:15} {new_ver:15} <type>")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    lib  = args[0] if args else "/lib/x86_64-linux-gnu/libm.so.6"
    analyze(lib)
