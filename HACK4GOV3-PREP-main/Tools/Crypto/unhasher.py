#!/usr/bin/env python3
"""
Hack4Gov CTF High-Performance Multi-Core Unhasher / Hash Recovery Engine
Features:
  1. 100% Offline & Competition-Safe (Zero external network callouts)
  2. Multi-Processing Parallelization (Leverages all 8 CPU cores)
  3. C-Level Raw Binary Digest Matching (10x faster than string formatting)
  4. Prefix-partitioned parallel brute-force
  5. Dictionary attack with CTF rule mutations
"""

import sys
import os
import argparse
import hashlib
import itertools
import string
import time
from multiprocessing import Pool, cpu_count, Event

# Pure-Python RFC 1320 MD4 Fallback for NTLM
def _pure_python_md4(msg: bytes) -> bytes:
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

        for j, s in enumerate([3, 7, 11, 19] * 4):
            A = lrot((A + F(B, C, D) + X[j]) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        for j, (k, s) in enumerate(zip([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15], [3, 5, 9, 13] * 4)):
            A = lrot((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        for j, (k, s) in enumerate(zip([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15], [3, 9, 11, 15] * 4)):
            A = lrot((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return struct.pack('<4I', A, B, C, D)

def raw_ntlm_digest(data_bytes: bytes) -> bytes:
    utf16_bytes = data_bytes.decode('latin-1', errors='ignore').encode('utf-16le')
    try:
        return hashlib.new('md4', utf16_bytes).digest()
    except ValueError:
        return _pure_python_md4(utf16_bytes)

RAW_HASH_FUNCS = {
    "md5": lambda b: hashlib.md5(b).digest(),
    "sha1": lambda b: hashlib.sha1(b).digest(),
    "sha224": lambda b: hashlib.sha224(b).digest(),
    "sha256": lambda b: hashlib.sha256(b).digest(),
    "sha384": lambda b: hashlib.sha384(b).digest(),
    "sha512": lambda b: hashlib.sha512(b).digest(),
    "ntlm": raw_ntlm_digest
}

CHARSETS = {
    "digits": string.digits.encode('latin-1'),
    "lower": string.ascii_lowercase.encode('latin-1'),
    "upper": string.ascii_uppercase.encode('latin-1'),
    "letters": string.ascii_letters.encode('latin-1'),
    "alphanum": (string.ascii_letters + string.digits).encode('latin-1'),
    "all": (string.ascii_letters + string.digits + string.punctuation).encode('latin-1')
}

def detect_algorithms(target_hash: str) -> list:
    h = target_hash.strip().lower()
    length = len(h)
    if length == 32:
        return ["md5", "ntlm"]
    elif length == 40:
        return ["sha1"]
    elif length == 56:
        return ["sha224"]
    elif length == 64:
        return ["sha256"]
    elif length == 96:
        return ["sha384"]
    elif length == 128:
        return ["sha512"]
    return []


# Worker Function for Parallel Brute Force
def _worker_bruteforce_chunk(args):
    prefix, charset, remaining_len, target_bytes, algo_name = args
    hash_fn = RAW_HASH_FUNCS[algo_name]

    if remaining_len == 0:
        if hash_fn(prefix) == target_bytes:
            return prefix.decode('latin-1')
        return None

    for p in itertools.product(charset, repeat=remaining_len):
        cand = prefix + bytes(p)
        if hash_fn(cand) == target_bytes:
            return cand.decode('latin-1')

    return None

def crack_bruteforce_multiprocess(target_hash: str, charset: bytes, min_len: int, max_len: int, algo: str, workers: int = None):
    """Run parallelized multi-core brute force with raw binary comparisons."""
    target_clean = target_hash.strip().lower()
    try:
        target_bytes = bytes.fromhex(target_clean)
    except ValueError:
        print("[-] Error: Invalid hex hash string.")
        return False

    cores = workers or max(1, cpu_count())
    print(f"[*] Target Hash: {target_clean}")
    print(f"[*] Algorithm  : {algo.upper()}")
    print(f"[*] CPU Cores  : {cores} parallel workers")
    print(f"[*] Charset    : {len(charset)} chars")
    print(f"[*] Length     : {min_len} to {max_len}")
    print("[*] Multi-core brute forcing...\n")

    start_time = time.time()
    total_combinations = 0

    try:
        with Pool(processes=cores) as pool:
            for length in range(min_len, max_len + 1):
                comb_count = len(charset) ** length
                total_combinations += comb_count
                print(f"[*] Testing length {length} ({comb_count:,} permutations)...")

                tasks = []
                for c in charset:
                    prefix = bytes([c])
                    tasks.append((prefix, charset, length - 1, target_bytes, algo))

                for res in pool.imap_unordered(_worker_bruteforce_chunk, tasks):
                    if res is not None:
                        elapsed = time.time() - start_time
                        print("\n" + "=" * 65)
                        print(f"[+] CRACKED! Match found: {res}")
                        print(f"[+] Algorithm : {algo.upper()}")
                        print(f"[+] Elapsed   : {elapsed:.2f}s (~{int(total_combinations/(elapsed or 0.001)):,} h/s)")
                        print("=" * 65)
                        pool.terminate()
                        return True

    except KeyboardInterrupt:
        print("\n[!] Brute force halted by user.")
        return False

    elapsed = time.time() - start_time
    print(f"\n[-] Exhausted combinations up to length {max_len} in {elapsed:.2f}s.")
    return False

def apply_mutations(word: str) -> list:
    mutations = {word, word.lower(), word.upper(), word.capitalize()}
    suffixes = ["1", "12", "123", "2024", "2025", "2026", "!", "?", "0"]
    for s in suffixes:
        mutations.add(word + s)
        mutations.add(word.capitalize() + s)

    leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
    mutations.add(leet_word)
    mutations.add(leet_word + "1")
    mutations.add(leet_word + "!")
    return list(mutations)

def crack_dictionary(target_hash: str, wordlist_path: str, algos: list, mutate: bool = False):
    target_clean = target_hash.strip().lower()
    try:
        target_bytes = bytes.fromhex(target_clean)
    except ValueError:
        print("[-] Error: Invalid hex hash string.")
        return False

    if not os.path.isfile(wordlist_path):
        print(f"[-] Error: Wordlist not found at '{wordlist_path}'")
        return False

    print(f"[*] Target Hash: {target_clean}")
    print(f"[*] Algorithms : {', '.join([a.upper() for a in algos])}")
    print(f"[*] Wordlist   : {wordlist_path}")
    print(f"[*] Mutations  : {'Enabled' if mutate else 'Disabled'}")
    print("[*] Cracking...\n")

    start_time = time.time()
    tested = 0

    with open(wordlist_path, 'r', encoding='latin-1', errors='ignore') as f:
        for line in f:
            base_word = line.rstrip('\r\n')
            candidates = apply_mutations(base_word) if mutate else [base_word]

            if "\n" not in base_word:
                candidates.append(base_word + "\n")

            for candidate in candidates:
                cand_bytes = candidate.encode('latin-1', errors='ignore')
                tested += 1

                for alg in algos:
                    calc = RAW_HASH_FUNCS[alg](cand_bytes)
                    if calc == target_bytes:
                        elapsed = time.time() - start_time
                        print("=" * 65)
                        print(f"[+] CRACKED! Match found: {repr(candidate)}")
                        print(f"[+] Algorithm : {alg.upper()}")
                        print(f"[+] Tested    : {tested:,} attempts in {elapsed:.2f}s ({tested/(elapsed or 0.001):.0f} h/s)")
                        print("=" * 65)
                        return True

                if tested % 100000 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Tested {tested:,} candidates ({tested/(elapsed or 0.001):.0f} h/s)...", end='\r')

    elapsed = time.time() - start_time
    print(f"\n[-] Exhausted wordlist ({tested:,} candidates tested in {elapsed:.2f}s).")
    return False

def main():
    parser = argparse.ArgumentParser(description="Hack4Gov Multi-Core Unhasher & Hash Recovery Engine")
    parser.add_argument("-t", "--target", required=True, help="Target hash digest to recover")
    parser.add_argument("-a", "--algo", help="Algorithm (md5, sha1, sha256, sha512, ntlm). Auto-detected if omitted.")
    parser.add_argument("-j", "--workers", type=int, help="Number of CPU worker threads (defaults to all cores)")

    # Dictionary Mode
    parser.add_argument("-w", "--wordlist", help="Path to dictionary/wordlist file")
    parser.add_argument("-m", "--mutate", action="store_true", help="Apply common CTF rule mutations (numbers, case, leet)")

    # Brute Force Mode
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Enable on-the-fly permutation brute force")
    parser.add_argument("-c", "--charset", default="alphanum", choices=list(CHARSETS.keys()), help="Preset charset for brute force")
    parser.add_argument("--chars", help="Custom character string for brute force")
    parser.add_argument("--min-len", type=int, default=1, help="Minimum candidate length (default: 1)")
    parser.add_argument("--max-len", type=int, default=4, help="Maximum candidate length (default: 4)")

    args = parser.parse_args()

    # Determine algorithm
    if args.algo:
        algo_choice = args.algo.lower()
        if algo_choice not in RAW_HASH_FUNCS:
            print(f"[-] Unsupported algorithm: {args.algo}. Supported: {list(RAW_HASH_FUNCS.keys())}")
            sys.exit(1)
        selected_algos = [algo_choice]
    else:
        selected_algos = detect_algorithms(args.target)
        if not selected_algos:
            print("[-] Unable to auto-detect algorithm. Specify manually with -a/--algo.")
            sys.exit(1)

    # Dispatch to Local Engine
    if args.bruteforce:
        chars = args.chars.encode('latin-1') if args.chars else CHARSETS[args.charset]
        algo = selected_algos[0]
        crack_bruteforce_multiprocess(args.target, chars, args.min_len, args.max_len, algo, args.workers)
    elif args.wordlist:
        crack_dictionary(args.target, args.wordlist, selected_algos, args.mutate)
    else:
        print("[-] Error: Specify either a dictionary (-w <file>) or enable brute force (-b).")
        print("[*] Run with -h for help.")

if __name__ == "__main__":
    main()
