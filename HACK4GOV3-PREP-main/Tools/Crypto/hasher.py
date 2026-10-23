#!/usr/bin/env python3
"""
Hack4Gov CTF Automated Hashing Tool
Capabilities:
  1. Multi-algorithm hash generation (String, File, Directory)
  2. Automatic hash type identification (Regex & heuristic analysis)
  3. Dictionary hash cracking with wordlist
"""

import sys
import os
import argparse
import hashlib
import binascii
import re
import time

CHUNK_SIZE = 65536

def _pure_python_md4(msg: bytes) -> str:
    """Pure-Python RFC 1320 MD4 implementation fallback."""
    import struct
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def lrot(val, n): return ((val << n) & 0xffffffff) | (val >> (32 - n))

    orig_len_bits = (len(msg) * 8) & 0xffffffffffffffff
    msg = bytearray(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len_bits)

    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    for i in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[i:i+64])
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        for j, s in enumerate([3, 7, 11, 19] * 4):
            k = j
            A = lrot((A + F(B, C, D) + X[k]) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        # Round 2
        for j, (k, s) in enumerate(zip([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15], [3, 5, 9, 13] * 4)):
            A = lrot((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        # Round 3
        for j, (k, s) in enumerate(zip([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15], [3, 9, 11, 15] * 4)):
            A = lrot((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return struct.pack('<4I', A, B, C, D).hex()

def ntlm_hash(data_bytes: bytes) -> str:
    """Generate NTLM hash (MD4 of UTF-16LE encoded bytes)."""
    encoded = data_bytes.decode('utf-8', errors='ignore').encode('utf-16le')
    try:
        return hashlib.new('md4', encoded).hexdigest()
    except ValueError:
        return _pure_python_md4(encoded)

def generate_hashes(data_bytes: bytes) -> dict:
    """Generate standard CTF hashes for a byte sequence."""
    results = {
        "MD5": hashlib.md5(data_bytes).hexdigest(),
        "SHA1": hashlib.sha1(data_bytes).hexdigest(),
        "SHA224": hashlib.sha224(data_bytes).hexdigest(),
        "SHA256": hashlib.sha256(data_bytes).hexdigest(),
        "SHA384": hashlib.sha384(data_bytes).hexdigest(),
        "SHA512": hashlib.sha512(data_bytes).hexdigest(),
        "NTLM": ntlm_hash(data_bytes)
    }
    return results

def hash_file(filepath: str) -> dict:
    """Hash large files efficiently using stream chunking."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    with open(filepath, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
            h_sha512.update(chunk)

    return {
        "MD5": h_md5.hexdigest(),
        "SHA1": h_sha1.hexdigest(),
        "SHA256": h_sha256.hexdigest(),
        "SHA512": h_sha512.hexdigest(),
    }

def identify_hash(hash_str: str) -> list:
    """Identify possible hash algorithms based on length, pattern, and salt conventions."""
    hash_clean = hash_str.strip()
    possibilities = []

    # Modular Crypt Format prefixes
    if hash_clean.startswith("$2a$") or hash_clean.startswith("$2b$") or hash_clean.startswith("$2y$"):
        return ["bcrypt (Blowfish-based modular crypt)"]
    if hash_clean.startswith("$6$"):
        return ["SHA-512 Unix Crypt"]
    if hash_clean.startswith("$5$"):
        return ["SHA-256 Unix Crypt"]
    if hash_clean.startswith("$1$"):
        return ["MD5 Unix Crypt"]
    if hash_clean.startswith("$argon2id$") or hash_clean.startswith("$argon2i$"):
        return ["Argon2"]

    # Hexadecimal analysis
    if re.fullmatch(r"^[a-fA-F0-9]+$", hash_clean):
        length = len(hash_clean)
        if length == 32:
            possibilities.extend(["MD5", "NTLM", "MD4", "NTLMv1"])
        elif length == 40:
            possibilities.extend(["SHA-1", "RIPEMD-160"])
        elif length == 56:
            possibilities.extend(["SHA-224", "SHA3-224"])
        elif length == 64:
            possibilities.extend(["SHA-256", "SHA3-256", "BLAKE2s"])
        elif length == 96:
            possibilities.extend(["SHA-384", "SHA3-384"])
        elif length == 128:
            possibilities.extend(["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"])
        else:
            possibilities.append(f"Unknown Hex Length ({length} chars)")
    else:
        possibilities.append("Non-hexadecimal string / custom salt format")

    return possibilities

def crack_hash(target_hash: str, wordlist_path: str, algo: str = None) -> bool:
    """Brute force / dictionary attack against a hash using a wordlist."""
    target_clean = target_hash.strip().lower()

    if not os.path.isfile(wordlist_path):
        print(f"[-] Error: Wordlist not found at {wordlist_path}")
        return False

    supported_algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512
    }

    selected_algos = []
    if algo:
        algo_lower = algo.lower()
        if algo_lower in supported_algos or algo_lower == "ntlm":
            selected_algos.append(algo_lower)
        else:
            print(f"[-] Unsupported algorithm: {algo}. Supported: {list(supported_algos.keys()) + ['ntlm']}")
            return False
    else:
        # Heuristic determination
        length = len(target_clean)
        if length == 32:
            selected_algos = ["md5", "ntlm"]
        elif length == 40:
            selected_algos = ["sha1"]
        elif length == 64:
            selected_algos = ["sha256"]
        elif length == 128:
            selected_algos = ["sha512"]
        else:
            print(f"[-] Could not deduce algorithm for length {length}. Please specify with --algo.")
            return False

    print(f"[*] Target: {target_clean}")
    print(f"[*] Testing algorithm(s): {', '.join(selected_algos)}")
    print(f"[*] Wordlist: {wordlist_path}")
    print("[*] Cracking in progress...\n")

    start_time = time.time()
    tested = 0

    try:
        with open(wordlist_path, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                word = line.rstrip('\r\n')
                word_bytes = word.encode('utf-8', errors='ignore')
                tested += 1

                for alg in selected_algos:
                    if alg == "ntlm":
                        calc = ntlm_hash(word_bytes)
                    else:
                        calc = supported_algos[alg](word_bytes).hexdigest()

                    if calc == target_clean:
                        elapsed = time.time() - start_time
                        print("=" * 60)
                        print(f"[+] CRACKED! Password found: {word}")
                        print(f"[+] Algorithm: {alg.upper()}")
                        print(f"[+] Attempts: {tested} in {elapsed:.2f}s ({tested/(elapsed or 0.001):.0f} h/s)")
                        print("=" * 60)
                        return True

                if tested % 100000 == 0:
                    print(f"[*] Checked {tested} passwords...", end='\r')

    except KeyboardInterrupt:
        print("\n[!] Cracking aborted by user.")
        return False

    elapsed = time.time() - start_time
    print(f"[-] Password not found in wordlist ({tested} words tested in {elapsed:.2f}s).")
    return False

def hash_directory(dir_path: str, algo: str = "sha256") -> None:
    """Hash all files in a directory (similar to verification / forensics challenges)."""
    if not os.path.isdir(dir_path):
        print(f"[-] Directory not found: {dir_path}")
        return

    algo_lower = algo.lower()
    algo_func = getattr(hashlib, algo_lower, hashlib.sha256)

    print(f"[*] Scanning directory: {dir_path}")
    print(f"{'Filename':<40} | {algo.upper()}")
    print("-" * 110)

    count = 0
    for root, _, files in os.walk(dir_path):
        for file in files:
            full_path = os.path.join(root, file)
            h = algo_func()
            try:
                with open(full_path, 'rb') as f:
                    while chunk := f.read(CHUNK_SIZE):
                        h.update(chunk)
                rel_path = os.path.relpath(full_path, dir_path)
                print(f"{rel_path:<40} | {h.hexdigest()}")
                count += 1
            except Exception as e:
                print(f"{file:<40} | Error: {e}")

    print(f"\n[*] Total files processed: {count}")

def main():
    parser = argparse.ArgumentParser(description="Hack4Gov Automated Hashing & Cracking Utility")
    parser.add_argument("-s", "--string", help="String to hash")
    parser.add_argument("-f", "--file", help="File path to hash")
    parser.add_argument("-d", "--dir", help="Directory path to hash all files")
    parser.add_argument("-i", "--identify", help="Hash string to identify algorithm")
    parser.add_argument("-c", "--crack", help="Target hash string to crack")
    parser.add_argument("-w", "--wordlist", help="Wordlist path for dictionary cracking")
    parser.add_argument("-a", "--algo", help="Algorithm (md5, sha1, sha256, sha512, ntlm)")

    args = parser.parse_args()

    if args.string:
        print(f"\n[*] Plaintext: {args.string}")
        print("=" * 70)
        hashes = generate_hashes(args.string.encode('utf-8'))
        for name, val in hashes.items():
            print(f"{name:<10}: {val}")
        print("=" * 70)

    elif args.file:
        print(f"\n[*] Hashing file: {args.file}")
        print("=" * 70)
        try:
            hashes = hash_file(args.file)
            for name, val in hashes.items():
                print(f"{name:<10}: {val}")
            print("=" * 70)
        except Exception as e:
            print(f"[-] Error: {e}")

    elif args.dir:
        hash_directory(args.dir, args.algo or "sha256")

    elif args.identify:
        print(f"\n[*] Analyzing Hash: {args.identify}")
        print("=" * 70)
        candidates = identify_hash(args.identify)
        print("Possible Formats:")
        for cand in candidates:
            print(f" - {cand}")
        print("=" * 70)

    elif args.crack:
        if not args.wordlist:
            print("[-] Error: --wordlist (-w) is required when using --crack (-c).")
            sys.exit(1)
        crack_hash(args.crack, args.wordlist, args.algo)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
