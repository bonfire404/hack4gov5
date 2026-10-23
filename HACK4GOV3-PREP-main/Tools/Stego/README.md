# Steganography Tools Quick Reference

### 1. StegSolve
- **File**: `Tools/Forensics/stegsolve.jar`
- **Cheatsheet**: `Tools/Stego/stego_instruction.txt`
- **Usage**:
  ```bash
  java -jar Tools/Forensics/stegsolve.jar
  ```
  Or launch with `Tools/Forensics/run_stegsolve.bat` on Windows.
- **Use Case**: Examining color planes (RGB/alpha), extracting hidden LSB payloads, stereograms, and frame browsing.

---

### 2. Zsteg (PNG/BMP LSB Extraction)
- **Install (Debian/Ubuntu/Kali)**:
  ```bash
  sudo gem install zsteg
  ```
- **Usage**:
  ```bash
  zsteg -a image.png
  zsteg -E "b1,bgr,lsb,xy" image.png > payload.bin
  ```

---

### 3. Steghide & Stegseek (JPEG Steganography)
- **Usage**:
  ```bash
  # Extract with blank password
  steghide extract -sf image.jpg -p ""

  # Fast dictionary crack using rockyou.txt.gz
  stegseek image.jpg ../rockyou.txt.gz
  ```

---

### 4. Sonic Visualiser (Audio Spectrogram Analysis)
- **Download**: https://www.sonicvisualiser.org/download.html
- **Use Case**: Spectrogram analysis for visual text and hidden signals in audio frequencies.

---

### 5. Encrypted Archive Cracking (fcrackzip & John)
- **Usage**:
  ```bash
  fcrackzip -u -D -p ../rockyou.txt.gz encrypted.zip
  zip2john encrypted.zip > zip.hash && john --wordlist=../rockyou.txt.gz zip.hash
  ```
