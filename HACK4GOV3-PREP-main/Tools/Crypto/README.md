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

### 2. Multi-Core Unhasher & Cracking Engine (`unhasher.py`)
- **File**: `Tools/Crypto/unhasher.py`
- **Cheatsheet**: `Tools/Crypto/unhashing_instruction.txt`
- **Wordlist Support**: Directly streams `.txt` and compressed `.gz` archives (e.g. `rockyou.txt.gz`) across all CPU cores.
  - **Transparent Gzip Decompression**: Never requires unpacking large archives to disk.
  - **On-the-fly Multi-Core Brute Force**: Permutations across custom or preset charsets (`digits`, `lower`, `alphanum`, `all`).
  - **Rule-Based Mutations (`-m`)**: Tests combinations of numbers, dates (`2026`), case changes, and leetspeak (`@dm!n`).
  - **Auto-Detection**: Infers target algorithms automatically from hash length (MD5, SHA-1, SHA-256, SHA-512, NTLM).
  - **Top-N Fast Scan (`--top <N>`)**: Allows scanning the top 10k or 100k most frequent passwords in milliseconds.

#### Usage:
```bash
# Dictionary attack directly from rockyou.txt.gz
python Tools/Crypto/unhasher.py -t "5f4dcc3b5aa765d61d8327deb882cf99" -w ../rockyou.txt.gz

# Dictionary attack with mutations and top 10k limit
python Tools/Crypto/unhasher.py -t "<TARGET_HASH>" -w ../rockyou.txt.gz -m --top 10000

# Multi-core brute-force 4-digit PIN (instant <0.2s)
python Tools/Crypto/unhasher.py -t "e48e13207341b6bffb7fb1622282247b" -b --charset digits --max-len 4

# Multi-core brute-force alphanumeric string up to length 4
python Tools/Crypto/unhasher.py -t "21232f297a57a5a743894a0e4a801fc3" -b --charset alphanum --max-len 4
```

---

### 3. Morse Code Engine & Listener (`morse.py`)
- **File**: `Tools/Crypto/morse.py`
- **Cheatsheet**: `Tools/Crypto/morse_instruction.txt`
  - **Interactive REPL (`-l`)**: Real-time bidirectional listener (auto-detects Morse vs plaintext).
  - **Mouse & Keyboard Tapper (`-t`)**: Discrete inputs (Left Click = Dot, Right Click = Dash, Spacebar = Letter/Word break, Backspace = Undo).
  - **Live Microphone Listener (`--mic`)**: Real-time FFT speech-filtered audio listener (<460 Hz human voice suppression).
  - **WAV Signal Parser (`-a`)**: Automatic PCM pulse amplitude extractor that decodes Morse beeps from `.wav` recordings.
  - **Direct Decoder / Encoder (`-d`, `-e`)**: Supports dots/dashes, binary (`0`/`1`), and spoken `dit`/`dah`.
  - **Audio Beep Synthesis (`-s`)**: Audible verification via Windows sound hardware.

#### Usage:
```bash
python Tools/Crypto/morse.py -l
python Tools/Crypto/morse.py -t        # Left Click: '.', Right Click: '-', Space: Break
python Tools/Crypto/morse.py -t -s     # With live audio beeps
python Tools/Crypto/morse.py --mic     # Real-time microphone audio listener
python Tools/Crypto/morse.py -a challenge_audio.wav
python Tools/Crypto/morse.py -d "... --- ..."
```

---

### 4. QuipQiup (Automated Substitution Solver)
- **Reference**: `Tools/Crypto/quipqiup.txt`
- **Link**: https://www.quipqiup.com/
- **Use Case**: Fast automated solving of classical monoalphabetic substitution ciphers.
