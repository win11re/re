#!/usr/bin/env python3
"""
match_functions.py - Paste disassembler function lines (name + address, tab
or space separated, extra columns ignored) and get a markdown match-table
per function, resolving public symbol -> Imod (via seccontrib) -> obj/lib
(via modules), the same way the pdb-function-to-obj-matching skill does it
by hand.

Usage:
    python match_functions.py [--publics publics.txt] [--seccontrib seccontrib.txt] [--modules modules.txt]

Then paste lines like:
    AccelBuildDescriptorMemoryCompress	.text	00000001406653E8	0000012C	...
    AccelFillMemory	.text	000000014040A67C	00000037	...

One function per line. End input with Ctrl-D (Ctrl-Z on Windows).
Only the function name (first whitespace-separated token) is used — the
address column is ignored, since the public symbol's own section:offset
(from publics.txt) is the authoritative one.
"""

import argparse
import re
import sys


def mangled_to_qualified(name):
    """Recover 'Namespace::Class::Function' from an MSVC-mangled public
    symbol name, ignoring the encoded return type / parameter list / calling
    convention (which come after the second '@@'). c++filt on Linux does not
    support MSVC mangling, so this is a minimal manual parser covering the
    common '?func@Class@Namespace@@...' shape. Returns None if it doesn't
    look like an MSVC-mangled name."""
    if not name.startswith("?"):
        return None
    rest = name[1:]
    end = rest.find("@@")
    if end == -1:
        return None
    qualifiers = rest[:end].split("@")
    # qualifiers[0] is the innermost name (the function/member itself);
    # the rest are enclosing scopes, innermost first -> reverse for display.
    qualifiers = [q for q in qualifiers if q]
    if not qualifiers:
        return None
    scopes = list(reversed(qualifiers[1:]))
    parts = scopes + [qualifiers[0]]
    return "::".join(parts)


def normalize_demangled(s):
    """Reduce a demangled/pretty signature down to just its qualified
    Namespace::Class::Function path, stripping return type, calling
    convention, and parameter list so both sides compare equal regardless
    of (void) vs () vs a full parameter list."""
    s = s.strip()
    paren = s.find("(")
    if paren != -1:
        s = s[:paren]
    tokens = s.split()
    s = tokens[-1] if tokens else s
    return s.strip()


PUB_RE = re.compile(
    r"S_PUB32:\s*\[([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\].*?,\s*(\S+)\s*$"
)
SECCONTRIB_RE = re.compile(
    r"\s*([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})"
)
MODULE_RE = re.compile(
    r'^\s*([0-9A-Fa-f]{4})\s+"([^"]*)"\s+"([^"]*)"'
)
# Some modules only have ONE quoted string (e.g. `001C "...\help.obj"`)
# instead of the usual "lib.lib" "obj_or_dll" pair.
MODULE_RE_SINGLE = re.compile(
    r'^\s*([0-9A-Fa-f]{4})\s+"([^"]*)"\s*$'
)


def load_publics(path):
    """name -> (section_int, offset_int, section_str, offset_str)
    Also builds table.demangled_index: normalized-demangled-name -> mangled name,
    so callers can look up either form."""
    table = {}
    demangled_index = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = PUB_RE.search(line.strip())
            if not m:
                continue
            sec, off, name = m.groups()
            table[name] = (int(sec, 16), int(off, 16), sec, off)
            qn = mangled_to_qualified(name)
            if qn:
                demangled_index[qn] = name
    return table, demangled_index


def find_suffix_matches(name, publics):
    """Some disassemblers truncate long names in narrow display columns, so a
    pasted line can show only the tail of the real symbol (e.g.
    'ReadUlongFromKey' pasted from what is actually
    'WerpEscalationReadUlongFromKey'). As a fallback when an exact lookup
    fails, look for public names ending in `name` at a plausible identifier
    boundary (preceding char is '_' or uppercase, i.e. a camelCase/word
    boundary, or the match is the whole name). Returns a list of candidate
    public names."""
    candidates = []
    for pubname in publics:
        if pubname == name:
            continue
        if not pubname.endswith(name):
            continue
        prefix_len = len(pubname) - len(name)
        boundary_char = pubname[prefix_len - 1] if prefix_len > 0 else None
        # Boundary is fine if there's no prefix, the prefix ends on '_', or
        # the suffix itself starts a new camelCase word (leading uppercase).
        if boundary_char is None or boundary_char == "_" or name[:1].isupper():
            candidates.append(pubname)
    return candidates


def load_seccontrib(path):
    """sorted list of (section_int, offset_int, size_int, imod_str)"""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SECCONTRIB_RE.match(line)
            if not m:
                continue
            imod, sec, off, size = m.groups()
            rows.append((int(sec, 16), int(off, 16), int(size, 16), imod))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def load_modules(path):
    """imod (as printed, e.g. '0640') -> (lib_path, obj_path)"""
    table = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MODULE_RE.match(line)
            if m:
                imod, lib, obj = m.groups()
                table[imod.upper()] = (lib, obj)
                continue
            m = MODULE_RE_SINGLE.match(line)
            if m:
                imod, obj = m.groups()
                table[imod.upper()] = ("", obj)
    return table


def find_imod(seccontrib_rows, sec, off):
    for row_sec, row_off, size, imod in seccontrib_rows:
        if row_sec == sec and row_off <= off < row_off + size:
            return imod
    return None


def guess_extension(name, obj_path):
    lower_obj = obj_path.lower()
    if re.search(r"\b(asm|x64|setjmp|cpu_disp)\b", lower_obj):
        return ".asm", "low-level asm stub path in obj"
    if name.startswith("?") or "@@" in name or "::" in name:
        return ".cpp", "C++ mangled/namespaced name"
    if "crt" in lower_obj or "vcstartup" in lower_obj:
        return ".c", "CRT/vcstartup path"
    return ".c", "plain C-style name, no mangling"


SECTION_SPLIT_RE = re.compile(
    r"^(.*?)(?:\.(?:text|rdata|data|pdata|rsrc|reloc|idata|bss)"
    r"|PAGE[A-Z0-9]*|INIT|CONST)"
)


def parse_function_name(line):
    """Extract just the function name, tolerating both whitespace-separated
    input and pasted input where whitespace/tabs got stripped and the name
    ran directly into the section column (e.g. 'FooBar.text0000...')."""
    line = line.strip()
    if not line:
        return None

    # Normal case: whitespace-separated columns.
    m = SECTION_SPLIT_RE.match(line)
    if m:
        name = m.group(1).strip()
        if name:
            return name

    # Fallback: no section token found at all, just take the first
    # whitespace-separated token.
    return line.split()[0] if line.split() else None


def match_one(name, publics, seccontrib_rows, modules, demangled_index=None):
    lines = []
    lines.append("**Match found:**\n")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Function | `{name}` |")

    pub = publics.get(name)
    resolved_name = name
    if not pub and demangled_index:
        mangled = demangled_index.get(normalize_demangled(name))
        if mangled:
            resolved_name = mangled
            pub = publics.get(mangled)
            lines.append(f"| Resolved mangled name | `{mangled}` |")

    if not pub:
        suffix_candidates = find_suffix_matches(name, publics)
        if len(suffix_candidates) == 1:
            resolved_name = suffix_candidates[0]
            pub = publics[resolved_name]
            lines.append(f"| Resolved (suffix match) | `{resolved_name}` |")
            lines.append(
                "| Note | Input name looked truncated (narrow disassembler "
                "column); matched by unique suffix. |"
            )
        elif len(suffix_candidates) > 1:
            lines.append("| Section:Offset | *not found in publics.txt* |")
            cand_list = ", ".join(f"`{c}`" for c in sorted(suffix_candidates))
            lines.append(
                f"| Note | Name looks truncated and matches multiple public "
                f"symbols by suffix — ambiguous: {cand_list} |"
            )
            return "\n".join(lines)
        else:
            lines.append("| Section:Offset | *not found in publics.txt* |")
            lines.append(
                "| Note | Likely a static/local (non-exported) function — "
                "not resolvable from a public PDB by name alone. |"
            )
            return "\n".join(lines)

    sec_int, off_int, sec_str, off_str = pub
    lines.append(f"| Section:Offset | `{sec_str.upper()}:{off_str.upper()}` |")

    imod = find_imod(seccontrib_rows, sec_int, off_int)
    if not imod:
        lines.append("| Imod | *no matching seccontrib row* |")
        return "\n".join(lines)
    lines.append(f"| Imod | `{imod}` |")

    mod = modules.get(imod.upper())
    if not mod:
        lines.append("| Lib/Obj | *Imod not found in modules.txt* |")
        return "\n".join(lines)
    lib, obj = mod
    lines.append(f"| Lib | `{lib}` |")
    lines.append(f"| Obj | `{obj}` |")

    ext, reason = guess_extension(resolved_name, obj)
    lines.append(f"| Guessed extension | `{ext}` ({reason}) |")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--publics", default="publics.txt")
    ap.add_argument("--seccontrib", default="seccontrib.txt")
    ap.add_argument("--modules", default="modules.txt")
    args = ap.parse_args()

    publics, demangled_index = load_publics(args.publics)
    seccontrib_rows = load_seccontrib(args.seccontrib)
    modules = load_modules(args.modules)

    print("Paste function lines below (one per line). End with Ctrl-D (Ctrl-Z+Enter on Windows):\n", file=sys.stderr)

    for raw_line in sys.stdin:
        name = parse_function_name(raw_line)
        if not name:
            continue
        print(match_one(name, publics, seccontrib_rows, modules, demangled_index))
        print()


if __name__ == "__main__":
    main()