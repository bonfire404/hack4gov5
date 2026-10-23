# Cryptography Tools

### 1. Automated Hashing Utility (`hasher.py`)
- **File**: `Tools/Crypto/hasher.py`
- **Cheatsheet**: `Tools/Crypto/hashing_instruction.txt`
  - Multi-hash generator (MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM).
  - Pure-Python RFC 1320 MD4 fallback for offline NTLM calculation without OpenSSL dependencies.
  - Automatic hash identification (modular crypt format + length analysis).
  - Directory mass file hashing for forensic checksum audits.

#### Usage:
```bash
python Tools/Crypto/hasher.py -s "admin"
python Tools/Crypto/hasher.py -f path/to/file.bin
python Tools/Crypto/hasher.py -i "5d41402abc4b2a76b9719d911017c592"
python Tools/Crypto/hasher.py -d Challenges/Forensics/Solved/Verify/files/
```

---

### 2. Automated Unhasher & Cracking Engine (`unhasher.py`)
- **File**: `Tools/Crypto/unhasher.py`
- **Cheatsheet**: `Tools/Crypto/unhashing_instruction.txt`
  - **On-the-fly Brute Force**: Recovers hashes without needing any wordlist on disk (PINs, lowercase, alphanumeric, custom charsets).
  - **Rule-Based Mutations**: Mutates base dictionary words with suffixes (`123`, `!`, `2026`), case changes, and leetspeak (`@dm!n`).
  - **Auto-Detection**: Infers target algorithms automatically from hash length (MD5, SHA-1, SHA-256, SHA-512, NTLM).
  - **Trailing Whitespace Awareness**: Tests both trimmed and newline-terminated candidates to crack file hashes directly.

#### Usage:
```bash
# Brute-force 4-digit PIN (instant)
python Tools/Crypto/unhasher.py -t "e48e13207341b6bffb7fb1622282247b" -b --charset digits --max-len 4

# Brute-force lowercase alphanumeric
python Tools/Crypto/unhasher.py -t "b0759e17c7cc70d7522a6b63a05c914e" -b --charset lower --max-len 5

# Dictionary crack with wordlist
python Tools/Crypto/unhasher.py -t "63a9f0ea7bb98050796b649e85481845" -w wordlist.txt

# Dictionary crack with rule mutations
python Tools/Crypto/unhasher.py -t "5d41402abc4b2a76b9719d911017c592" -w wordlist.txt -m
```

---

### 3. QuipQiup (Automated Substitution Solver)
- **Reference**: `Tools/Crypto/quipqiup.txt`
- **Link**: https://www.quipqiup.com/
- **Use Case**: Fast automated solving of classical monoalphabetic substitution ciphers.

---

### 4. Morse Code Engine & Listener (`morse.py`)
- **File**: `Tools/Crypto/morse.py`
- **Cheatsheet**: `Tools/Crypto/morse_instruction.txt`
  - **Interactive REPL (`-l`)**: Real-time bidirectional listener (auto-detects Morse vs plaintext).
  - **Mouse & Keyboard Tapper (`-t`)**: Discrete inputs (Left Click = Dot, Right Click = Dash, Spacebar = Letter/Word break).
  - **Live Microphone Listener (`-m`, `--mic`)**: Captures live microphone sound, isolates beep tones via FFT, and decodes Morse in real time.
  - **WAV Signal Parser (`-a`)**: Automatic PCM audio pulse extractor that decodes Morse beeps from `.wav` recordings.
  - **Direct Decoder / Encoder (`-d`, `-e`)**: Supports dots/dashes, binary (`0`/`1`), and spoken `dit`/`dah`.
  - **Audio Beep Synthesis (`-s`)**: Audible verification via Windows sound hardware.

#### Usage:
```bash
python Tools/Crypto/morse.py -l
python Tools/Crypto/morse.py -t        # Left Click: '.', Right Click: '-', Space: Break
python Tools/Crypto/morse.py -t -s     # With live audio beeps
python Tools/Crypto/morse.py --mic     # Real-time microphone audio listener
python Tools/Crypto/morse.py -d "... --- ..."
python Tools/Crypto/morse.py -a challenge_audio.wav
```

