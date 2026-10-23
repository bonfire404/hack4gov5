#!/usr/bin/env python3
"""
Hack4Gov CTF Binary Triage & Reconnaissance Script
Quick automated analysis of unknown challenge executables (ELF, PE, raw binaries).
Capabilities:
  1. Header & Architecture Identification
  2. Flag & Credential Regex Scanner
  3. String Comparison & Anti-Debug Function Detection
  4. Single-Byte XOR Key Recovery Scanner
"""

import sys
import os
import re
import struct

def identify_header(data: bytes) -> dict:
    """Inspect magic bytes and architecture header."""
    info = {"format": "Unknown / Raw Data", "arch": "Unknown", "bits": "Unknown"}

    if data.startswith(b"\x7fELF"):
        info["format"] = "Linux ELF"
        if len(data) > 5:
            info["bits"] = "32-bit" if data[4] == 1 else "64-bit"
            info["endian"] = "Little Endian" if data[5] == 1 else "Big Endian"
        if len(data) >= 19:
            machine = struct.unpack("<H" if data[5] == 1 else ">H", data[18:20])[0]
            arch_map = {0x03: "x86 (Intel 386)", 0x3E: "x86-64 (AMD64)", 0x28: "ARM", 0xB7: "AArch64 (ARM64)"}
            info["arch"] = arch_map.get(machine, f"Machine type {hex(machine)}")

    elif data.startswith(b"MZ"):
        info["format"] = "Windows PE (EXE/DLL)"
        info["bits"] = "32-bit or 64-bit PE"

    elif data.startswith(b"\xca\xfe\xba\xbe"):
        info["format"] = "Java Class file (or Mach-O Universal)"

    elif data.startswith(b"PK\x03\x04"):
        info["format"] = "ZIP Archive (or APK/JAR/DOCX container)"

    return info

def scan_strings(data: bytes, min_len: int = 4) -> list:
    """Extract printable ASCII and UTF-8 strings from binary."""
    pattern = rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}"
    return [match.group(0).decode("latin-1") for match in re.finditer(pattern, data)]

def analyze_binary(filepath: str):
    if not os.path.isfile(filepath):
        print(f"[-] File not found: {filepath}")
        return

    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        data = f.read()

    print("=" * 70)
    print(f"[*] BINARY RECONNAISSANCE: {os.path.basename(filepath)}")
    print(f"[*] File Size: {file_size:,} bytes ({file_size / 1024:.2f} KB)")
    print("=" * 70)

    # 1. Header Information
    header_info = identify_header(data)
    print("\n[+] Binary Header & Architecture:")
    for k, v in header_info.items():
        print(f"    - {k.capitalize():<10}: {v}")

    # 2. Extract strings
    all_strings = scan_strings(data, min_len=4)
    print(f"\n[+] Total Printable Strings: {len(all_strings)}")

    # 3. Flag Search
    flag_patterns = [
        re.compile(r"(hack4gov|flag|dict|ctf)\{[^\}]+\}", re.IGNORECASE),
        re.compile(r"hack4gov[a-zA-Z0-9_\-]{4,}", re.IGNORECASE)
    ]
    flags_found = set()
    for s in all_strings:
        for p in flag_patterns:
            for match in p.findall(s):
                flags_found.add(match if isinstance(match, str) else match[0])

    if flags_found:
        print("\n[!] *** POTENTIAL FLAGS DETECTED IN STRINGS ***")
        for fl in flags_found:
            print(f"    >>> {fl}")
    else:
        print("\n[-] No obvious plaintext flags detected in strings.")

    # 4. Critical Keywords
    interesting_keywords = ["pass", "password", "key", "secret", "admin", "correct", "wrong", "congrat", "winner"]
    interesting_hits = [s for s in all_strings if any(k in s.lower() for k in interesting_keywords)]
    if interesting_hits:
        print("\n[+] High-Value Keyword Hits (Up to 10 shown):")
        for hit in interesting_hits[:10]:
            print(f"    - {hit}")

    # 5. Functions & Imports
    target_functions = ["strcmp", "strncmp", "memcmp", "wcscmp", "ptrace", "IsDebuggerPresent", "printf", "puts", "system"]
    funcs_detected = [func for func in target_functions if func.encode('ascii') in data]
    if funcs_detected:
        print("\n[+] Detected Comparison / Security Functions:")
        for fn in funcs_detected:
            hint = ""
            if "cmp" in fn:
                hint = "<- (Hint: Run with ltrace to intercept plaintext comparisons!)"
            elif "ptrace" in fn or "Debugger" in fn:
                hint = "<- (Anti-debugging detected)"
            print(f"    - {fn:<20} {hint}")

    # 6. Single-Byte XOR Flag Finder
    print("\n[+] Testing Single-Byte XOR Key Permutations for 'hack4gov{' and 'flag{'...")
    found_xor = False
    for key in range(1, 256):
        xored = bytes(b ^ key for b in data)
        if b"hack4gov{" in xored.lower() or b"flag{" in xored.lower():
            for match in re.finditer(rb"(hack4gov|flag)\{[^\}]+\}", xored, re.IGNORECASE):
                print(f"    [!] FOUND XOR FLAG with key {hex(key)} ({key}): {match.group(0).decode('latin-1')}")
                found_xor = True

    if not found_xor:
        print("    [-] No single-byte XOR flag match found.")

    print("\n" + "=" * 70)
    print("[*] Next Steps:")
    print("    1. If Linux ELF: Run 'ltrace ./" + os.path.basename(filepath) + "'")
    print("    2. If logic is complex: Open in Ghidra and decompile main function.")
    print("=" * 70)

def main():
    if len(sys.argv) < 2:
        print("Usage: python Tools/Reversing/rev_triage.py <binary_file>")
        sys.exit(1)

    analyze_binary(sys.argv[1])

if __name__ == "__main__":
    main()
