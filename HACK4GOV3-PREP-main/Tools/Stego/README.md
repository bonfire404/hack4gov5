# Steganography Tools Quick Reference

### 1. StegSolve
- **File**: `Tools/Forensics/stegsolve.jar`
- **Usage**:
  ```bash
  java -jar stegsolve.jar
  ```
- **Use Case**: Examining color planes (RGB/alpha), extracting hidden LSB payloads, and frame browsing.

### 2. fcrackzip (ZIP Password Cracker)
- **Install (Debian/Ubuntu/Kali)**:
  ```bash
  sudo apt update && sudo apt install -y fcrackzip
  ```
- **Usage**:
  ```bash
  fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt target.zip
  ```

### 3. Sonic Visualiser (Audio Steganography)
- **Install (Debian/Ubuntu/Kali)**:
  ```bash
  sudo apt update && sudo apt install -y sonic-visualiser
  ```
- **Official Download**: https://www.sonicvisualiser.org/download.html
- **Use Case**: Spectrogram analysis for hidden audio text/signals (DTMF, morse, visual text in frequencies).
