#!/usr/bin/env python3
"""
Hack4Gov CTF Morse Code Toolkit
Capabilities:
  1. Interactive Live Listener / REPL (Auto-detects Morse vs Text)
  2. Spacebar Key Tapper (Duration-based Morse generator and live decoder)
  3. CLI Direct Encoder & Decoder (Supports standard, binary 0/1, dit/dah)
  4. Audio Sound Player (Audible beeps via Windows winsound)
  5. WAV Audio Signal Decoder (Automated pulse extraction from .wav files)
"""

import sys
import os
import time
import argparse
import wave
import struct
import re

# ==============================================================================
# MORSE CODE DICTIONARIES & MAPPINGS
# ==============================================================================

MORSE_CODE_DICT = {
    'A': '.-',     'B': '-...',   'C': '-.-.',   'D': '-..',    'E': '.',
    'F': '..-.',   'G': '--.',    'H': '....',   'I': '..',     'J': '.---',
    'K': '-.-',    'L': '.-..',   'M': '--',     'N': '-.',     'O': '---',
    'P': '.--.',   'Q': '--.-',   'R': '.-.',    'S': '...',    'T': '-',
    'U': '..-',    'V': '...-',   'W': '.--',    'X': '-..-',   'Y': '-.--',
    'Z': '--..',
    '0': '-----',  '1': '.----',  '2': '..---',  '3': '...--',  '4': '....-',
    '5': '.....',  '6': '-....',  '7': '--...',  '8': '---..',  '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.',  '(': '-.--.',  ')': '-.--.-', '&': '.-...',  ':': '---...',
    ';': '-.-.-.', '=': '-...-',  '+': '.-.-.',  '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.', '{': '-.--.', '}': '-.--.-'
}

REVERSE_MORSE_DICT = {code: char for char, code in MORSE_CODE_DICT.items()}
# CTF alternative mappings
REVERSE_MORSE_DICT['-.--.'] = '{'  # Default bracket fallback in CTF context
REVERSE_MORSE_DICT['-.--.-'] = '}'

# ==============================================================================
# NORMALIZATION & PARSING UTILITIES
# ==============================================================================

def normalize_morse(raw_input: str) -> str:
    """
    Normalizes diverse Morse representations:
    - Replaces 'dit'/'di' with '.', 'dah'/'da' with '-'
    - Replaces '0' with '.', '1' with '-' if purely binary
    - Standardizes word separators ('/' or '|' or multiple spaces)
    """
    s = raw_input.strip()

    # Detect and normalize dit/dah format (e.g. 'di-di-dit dah-dah-dah di-di-dit')
    if 'dit' in s.lower() or 'dah' in s.lower():
        # Collapse intra-letter hyphens (e.g. di-di-dit -> dididit)
        while re.search(r'(?i)(di|dit|dah)-(di|dit|dah)', s):
            s = re.sub(r'(?i)(di|dit|dah)-(di|dit|dah)', r'\1\2', s)
        s = re.sub(r'(?i)dah', '-', s)
        s = re.sub(r'(?i)di[t]?', '.', s)


    # Detect binary 0/1 Morse (e.g. 000 111 000)
    tokens = s.split()
    is_binary = len(tokens) > 0 and all(set(t).issubset({'0', '1', '/', '|'}) for t in tokens)
    if is_binary and not any(c in s for c in '.-'):
        s = s.replace('0', '.').replace('1', '-')

    # Replace underscore with dash
    s = s.replace('_', '-')

    return s

def decode_morse(morse_str: str) -> str:
    """Decodes a Morse code string into readable ASCII."""
    norm = normalize_morse(morse_str)
    
    # Split words by slash or triple space
    if '/' in norm:
        words = norm.split('/')
    elif '|' in norm:
        words = norm.split('|')
    elif '   ' in norm:
        words = norm.split('   ')
    else:
        words = [norm]

    decoded_words = []
    for word in words:
        chars = word.strip().split()
        decoded_chars = []
        for code in chars:
            clean_code = code.strip()
            if not clean_code:
                continue
            char = REVERSE_MORSE_DICT.get(clean_code, f'[{clean_code}?brain]')
            decoded_chars.append(char)
        decoded_words.append(''.join(decoded_chars))

    return ' '.join(decoded_words)

def encode_morse(text: str) -> str:
    """Encodes ASCII text into standard Morse code."""
    words = text.upper().split()
    encoded_words = []
    for word in words:
        chars = []
        for char in word:
            code = MORSE_CODE_DICT.get(char, '')
            if code:
                chars.append(code)
            else:
                chars.append(f'[{char}]')
        encoded_words.append(' '.join(chars))
    return ' / '.join(encoded_words)

def play_morse_sound(morse_str: str):
    """Audible playback via Windows winsound (or terminal beep fallback)."""
    norm = normalize_morse(morse_str)
    try:
        import winsound
        freq = 800
        dot_ms = 100
        dash_ms = 300
        pause_symbol = 0.08
        pause_letter = 0.25
        pause_word = 0.6

        for char in norm:
            if char == '.':
                winsound.Beep(freq, dot_ms)
                time.sleep(pause_symbol)
            elif char == '-':
                winsound.Beep(freq, dash_ms)
                time.sleep(pause_symbol)
            elif char == ' ':
                time.sleep(pause_letter)
            elif char in ('/', '|'):
                time.sleep(pause_word)
    except Exception as e:
        print(f"[-] Audio playback error: {e}")

# ==============================================================================
# MODE 1: INTERACTIVE LIVE LISTENER / REPL  (Dynamic Two-Line HUD)
# ==============================================================================

def _getch():
    """
    Read a single keypress without waiting for Enter.
    Returns bytes on Windows, str on Unix.
    """
    if os.name == 'nt':
        import msvcrt
        ch = msvcrt.getch()
        # Handle special/extended keys (arrows, function keys, etc.)
        if ch in (b'\x00', b'\xe0'):
            msvcrt.getch()          # consume the second byte
            return None             # ignore extended keys
        return ch
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        return ch.encode('latin-1') if ch else None


def _hud_render(morse_buf: str, decoded_text: str, letter_buf: str):
    """
    Redraws the live two-line HUD in-place using ANSI escape codes.
      Line 1 (MORSE) : raw Morse symbols being typed
      Line 2 (TEXT)   : live decoded ASCII plaintext
    """
    # Preview: if a partial letter buffer exists, show its best-match attempt
    preview = ""
    if letter_buf:
        preview = REVERSE_MORSE_DICT.get(letter_buf, "·")

    line1 = f"  \033[36mMORSE >\033[0m {morse_buf}\033[90m{letter_buf}\033[0m"
    line2 = f"  \033[33mTEXT  >\033[0m {decoded_text}\033[90m{preview}\033[0m"

    # Move cursor up 2, clear both lines, redraw
    sys.stdout.write(f"\033[2A\r\033[K{line1}\n\033[K{line2}\n")
    sys.stdout.flush()


def interactive_listener():
    """
    Dynamic Two-Line HUD — real-time Morse-to-Text retranslator.
    Every keystroke instantly updates the decoded output without pressing Enter.

    Controls:
      .  /  -         : Append dot / dash to current letter
      SPACE            : Commit letter (1st) / Word break (2nd consecutive)
      /                : Explicit word separator
      BACKSPACE        : Undo last symbol
      ENTER            : Finalize & print decoded message, reset HUD
      ESC / CTRL+C     : Exit
    """
    # Enable VT100 ANSI processing on Windows 10+ terminals
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass

    print("=" * 70)
    print("  HACK4GOV MORSE CODE — REAL-TIME DYNAMIC HUD")
    print("  ─────────────────────────────────────────────")
    print("  .  or  -        Dot / Dash (append to current letter)")
    print("  SPACE           Commit letter  |  Double-SPACE = word break")
    print("  /               Explicit word separator")
    print("  BACKSPACE       Undo last symbol")
    print("  ENTER           Finalize & print full decoded message")
    print("  ESC / CTRL+C    Exit")
    print("=" * 70)

    # --- State ---
    letter_buf = ""       # current uncommitted letter (e.g. ".-")
    morse_display = ""    # full Morse string shown on line 1
    decoded_parts = []    # committed decoded characters/words
    last_was_space = False  # track double-space for word break
    history = []          # undo stack: list of (action, data) tuples

    # Reserve 2 lines for the HUD
    sys.stdout.write("\n\n")
    sys.stdout.flush()

    def _decoded_text():
        return ''.join(decoded_parts)

    # Initial render
    _hud_render(morse_display, _decoded_text(), letter_buf)

    try:
        while True:
            ch = _getch()
            if ch is None:
                continue

            byte_val = ch[0] if isinstance(ch[0], int) else ord(ch[0])

            # ── ESC (0x1B) ──
            if byte_val == 0x1B:
                break

            # ── CTRL+C (0x03) ──
            if byte_val == 0x03:
                break

            # ── ENTER (0x0D) ── Finalize message
            if byte_val == 0x0D:
                # Commit any pending letter
                if letter_buf:
                    char = REVERSE_MORSE_DICT.get(letter_buf, f'[{letter_buf}?]')
                    decoded_parts.append(char)
                    morse_display += letter_buf
                    letter_buf = ""

                final_text = _decoded_text()
                # Move below HUD and print result
                sys.stdout.write(f"\n\033[32m[+] DECODED MESSAGE:\033[0m {final_text}\n\n")
                sys.stdout.flush()

                # Reset state
                letter_buf = ""
                morse_display = ""
                decoded_parts = []
                last_was_space = False
                history = []

                # Reserve fresh HUD lines
                sys.stdout.write("\n\n")
                sys.stdout.flush()
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # ── BACKSPACE (0x08 or 0x7F) ── Undo
            if byte_val in (0x08, 0x7F):
                if letter_buf:
                    letter_buf = letter_buf[:-1]
                elif history:
                    action, data = history.pop()
                    if action == 'char':
                        # Remove last decoded char
                        if decoded_parts:
                            decoded_parts.pop()
                        # Remove trailing Morse for that char + space from display
                        morse_display = morse_display.rstrip()
                        # Try to remove the last letter code
                        parts = morse_display.rsplit(' ', 1)
                        if len(parts) == 2:
                            morse_display = parts[0] + ' '
                        else:
                            morse_display = ""
                    elif action == 'word_break':
                        # Remove the word-break space from decoded
                        if decoded_parts and decoded_parts[-1] == ' ':
                            decoded_parts.pop()
                        # Remove ' / ' from morse display
                        if morse_display.endswith(' / '):
                            morse_display = morse_display[:-3]
                last_was_space = False
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # ── DOT (.) ──
            if byte_val == ord('.'):
                letter_buf += '.'
                last_was_space = False
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # ── DASH (-) ──
            if byte_val == ord('-'):
                letter_buf += '-'
                last_was_space = False
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # ── SLASH (/) ── Explicit word separator
            if byte_val == ord('/'):
                # Commit pending letter first
                if letter_buf:
                    char = REVERSE_MORSE_DICT.get(letter_buf, f'[{letter_buf}?]')
                    decoded_parts.append(char)
                    morse_display += letter_buf + ' '
                    history.append(('char', letter_buf))
                    letter_buf = ""
                # Add word break
                decoded_parts.append(' ')
                morse_display += '/ '
                history.append(('word_break', '/'))
                last_was_space = False
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # ── SPACE (0x20) ── Letter break / Word break
            if byte_val == 0x20:
                if last_was_space:
                    # Double-space = word separator
                    decoded_parts.append(' ')
                    morse_display += '/ '
                    history.append(('word_break', ' '))
                    last_was_space = False
                else:
                    # Commit current letter
                    if letter_buf:
                        char = REVERSE_MORSE_DICT.get(letter_buf, f'[{letter_buf}?]')
                        decoded_parts.append(char)
                        morse_display += letter_buf + ' '
                        history.append(('char', letter_buf))
                        letter_buf = ""
                    last_was_space = True
                _hud_render(morse_display, _decoded_text(), letter_buf)
                continue

            # Ignore all other keys
            continue

    except (KeyboardInterrupt, EOFError):
        pass

    # Final flush on exit
    final_text = _decoded_text()
    if letter_buf:
        leftover = REVERSE_MORSE_DICT.get(letter_buf, f'[{letter_buf}?]')
        final_text += leftover

    sys.stdout.write(f"\n\033[32m[*] Exiting HUD. Final text:\033[0m {final_text}\n")
    sys.stdout.flush()

# ==============================================================================
# MODE 2: INTERACTIVE SPACEBAR KEY TAPPER
# ==============================================================================

def interactive_tapper(sound_enabled: bool = False):
    """
    Interactive Mouse & Keyboard Morse Tapper:
      - LEFT CLICK  (or '.' key) : Dot (.)
      - RIGHT CLICK (or '-' key) : Dash (-)
      - SPACEBAR                 : Letter Break (1st tap) / Word Break (2nd tap)
      - BACKSPACE                : Undo last symbol
      - ENTER                    : Print full decoded message
      - ESC / CTRL+C             : Exit tapper
    """
    print("=" * 70)
    print("  HACK4GOV INTERACTIVE MOUSE & KEYBOARD MORSE TAPPER")
    print("  - LEFT CLICK  (or '.') : Dot (.)")
    print("  - RIGHT CLICK (or '-') : Dash (-)")
    print("  - SPACEBAR             : Letter Break / Word Break")
    print("  - BACKSPACE            : Undo last symbol")
    print("  - ENTER                : Print full decoded message")
    print("  - ESC / CTRL+C         : Exit tapper")
    print("=" * 70)

    try:
        import ctypes
        import winsound
        user32 = ctypes.windll.user32
        has_win32 = True
    except Exception:
        has_win32 = False

    if not has_win32:
        print("[-] Windows user32 not detected. Falling back to CLI listener.")
        return

    VK_LBUTTON = 0x01
    VK_RBUTTON = 0x02
    VK_BACK = 0x08
    VK_RETURN = 0x0D
    VK_ESCAPE = 0x1B
    VK_SPACE = 0x20
    VK_OEM_PERIOD = 0xBE  # '.' key
    VK_OEM_MINUS = 0xBD   # '-' key

    current_letter = []
    current_word = []
    full_sentence = []

    prev_state = {
        'lbutton': False,
        'rbutton': False,
        'space': False,
        'back': False,
        'enter': False,
        'escape': False,
        'dot_key': False,
        'dash_key': False
    }

    print("\n[READY] Click Left/Right mouse buttons or Spacebar to tap (ESC to quit)...")
    sys.stdout.write("\n> ")
    sys.stdout.flush()

    try:
        while True:
            def is_down(vk):
                return (user32.GetAsyncKeyState(vk) & 0x8000) != 0

            l_down = is_down(VK_LBUTTON)
            r_down = is_down(VK_RBUTTON)
            sp_down = is_down(VK_SPACE)
            bk_down = is_down(VK_BACK)
            ent_down = is_down(VK_RETURN)
            esc_down = is_down(VK_ESCAPE)
            dot_down = is_down(VK_OEM_PERIOD)
            dash_down = is_down(VK_OEM_MINUS)

            # ESC to exit
            if esc_down and not prev_state['escape']:
                break

            # LEFT CLICK or '.' KEY -> DOT
            if (l_down and not prev_state['lbutton']) or (dot_down and not prev_state['dot_key']):
                current_letter.append('.')
                sys.stdout.write(".")
                sys.stdout.flush()
                if sound_enabled:
                    winsound.Beep(800, 80)

            # RIGHT CLICK or '-' KEY -> DASH
            elif (r_down and not prev_state['rbutton']) or (dash_down and not prev_state['dash_key']):
                current_letter.append('-')
                sys.stdout.write("-")
                sys.stdout.flush()
                if sound_enabled:
                    winsound.Beep(800, 240)

            # SPACEBAR -> LETTER / WORD BREAK
            elif sp_down and not prev_state['space']:
                if current_letter:
                    code = ''.join(current_letter)
                    char = REVERSE_MORSE_DICT.get(code, f'[{code}?]')
                    current_word.append(char)
                    sys.stdout.write(f" ({char}) ")
                    sys.stdout.flush()
                    current_letter = []
                elif current_word:
                    full_sentence.append(''.join(current_word))
                    sys.stdout.write(" / ")
                    sys.stdout.flush()
                    current_word = []

            # BACKSPACE -> UNDO
            elif bk_down and not prev_state['back']:
                if current_letter:
                    current_letter.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                elif current_word:
                    current_word.pop()
                    sys.stdout.write(" [DEL] ")
                    sys.stdout.flush()

            # ENTER -> PRINT MESSAGE
            elif ent_down and not prev_state['enter']:
                if current_letter:
                    code = ''.join(current_letter)
                    char = REVERSE_MORSE_DICT.get(code, f'[{code}?]')
                    current_word.append(char)
                    current_letter = []
                if current_word:
                    full_sentence.append(''.join(current_word))
                    current_word = []

                decoded_str = ' '.join(full_sentence)
                print(f"\n[+] DECODED MESSAGE: {decoded_str}")
                full_sentence = []
                sys.stdout.write("\n> ")
                sys.stdout.flush()

            prev_state['lbutton'] = l_down
            prev_state['rbutton'] = r_down
            prev_state['space'] = sp_down
            prev_state['back'] = bk_down
            prev_state['enter'] = ent_down
            prev_state['escape'] = esc_down
            prev_state['dot_key'] = dot_down
            prev_state['dash_key'] = dash_down

            time.sleep(0.015)

    except KeyboardInterrupt:
        pass

    if current_letter:
        code = ''.join(current_letter)
        current_word.append(REVERSE_MORSE_DICT.get(code, f'[{code}?]'))
    if current_word:
        full_sentence.append(''.join(current_word))

    final_output = ' '.join(full_sentence)
    print(f"\n[*] Tapper Closed. Final decoded text: {final_output}\n")

# ==============================================================================
# MODE 3: AUDIO WAV FILE SIGNAL DECODER
# ==============================================================================

def decode_wav_file(wav_path: str, threshold: float = 0.15):
    """
    Decodes Morse code from uncompressed PCM .wav audio file.
    Calculates amplitude bursts and translates signal durations to dots/dashes.
    """
    if not os.path.isfile(wav_path):
        print(f"[-] File not found: {wav_path}")
        return

    print(f"[*] Analyzing Audio Signal: {wav_path}")
    try:
        with wave.open(wav_path, 'rb') as wf:
            num_channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            framerate = wf.getframerate()
            num_frames = wf.getnframes()
            duration = num_frames / float(framerate)

            print(f"    - Channels   : {num_channels}")
            print(f"    - Sample Rate: {framerate} Hz")
            print(f"    - Duration   : {duration:.2f} seconds")

            raw_bytes = wf.readframes(num_frames)

        # Parse audio samples (16-bit or 8-bit mono/stereo)
        if sample_width == 2:
            fmt = f"<{num_frames * num_channels}h"
            samples = struct.unpack(fmt, raw_bytes)
            max_val = 32767.0
        elif sample_width == 1:
            fmt = f"<{num_frames * num_channels}B"
            samples = [s - 128 for s in struct.unpack(fmt, raw_bytes)]
            max_val = 128.0
        else:
            print("[-] Unsupported sample width for direct PCM analysis.")
            return

        # Downsample to mono if stereo
        if num_channels > 1:
            samples = samples[0::num_channels]

        # Slice into 10ms windows to calculate signal energy
        window_size = int(framerate * 0.01)  # 10ms
        energy_levels = []
        for i in range(0, len(samples), window_size):
            chunk = samples[i:i + window_size]
            if not chunk:
                continue
            rms = (sum(abs(x) for x in chunk) / len(chunk)) / max_val
            energy_levels.append(1 if rms >= threshold else 0)

        # Run-length encode on/off pulses
        pulses = []
        current_state = energy_levels[0]
        count = 0
        for bit in energy_levels:
            if bit == current_state:
                count += 1
            else:
                pulses.append((current_state, count * 0.01))
                current_state = bit
                count = 1
        pulses.append((current_state, count * 0.01))

        # Separate on-durations (tones) to estimate dot duration
        on_durations = [dur for state, dur in pulses if state == 1 and dur >= 0.03]
        if not on_durations:
            print("[-] No clear Morse tone pulses detected above threshold.")
            return

        on_durations.sort()
        # The shortest cluster is the dot
        dot_est = on_durations[int(len(on_durations) * 0.15)]
        dash_min = dot_est * 2.0

        print(f"[*] Estimated Dot Duration : {dot_est * 1000:.1f} ms")
        print(f"[*] Estimated Dash Cutoff  : {dash_min * 1000:.1f} ms")

        # Convert pulses to dots, dashes, and spaces
        morse_tokens = []
        for state, dur in pulses:
            if state == 1:  # Tone
                if dur < dash_min:
                    morse_tokens.append('.')
                else:
                    morse_tokens.append('-')
            else:  # Silence
                if dur >= dot_est * 5.0:
                    morse_tokens.append(' / ')
                elif dur >= dot_est * 2.2:
                    morse_tokens.append(' ')

        morse_string = ''.join(morse_tokens).strip()
        print(f"\n[+] Extracted Morse Code:\n{morse_string}")
        decoded_text = decode_morse(morse_string)
        print(f"\n[+] Decoded ASCII Text  :\n{decoded_text}\n")

    except Exception as e:
        print(f"[-] Audio decoding failed: {e}")

# ==============================================================================
# MODE 4: LIVE MICROPHONE AUDIO MORSE LISTENER
# ==============================================================================

def live_microphone_listener(target_freq: float = 750.0, threshold: float = 0.025, transcript_path: str = None):
    """
    Listens to real-time audio from the default microphone, isolates Morse tones,
    rejects human speech using tonality purity and low-frequency suppression,
    and displays decoded ASCII text live.
    """
    print("=" * 70)
    print("  HACK4GOV MICROPHONE MORSE CODE LISTENER (SPEECH-FILTERED)")
    if target_freq == 750.0:
        print("  - Frequency Band        : Wide Auto-Detect (520 Hz - 1250 Hz)")
    else:
        print(f"  - Target Tone Frequency : {target_freq:.0f} Hz (+/- 120 Hz)")
    print("  - Speech Rejection      : Low-frequency voice fundamental filter active (< 460 Hz)")
    print("  - Tonality Filter       : Pure sinusoidal tone purity check (>= 7.5x)")
    if transcript_path:
        print(f"  - Transcript Logging    : {transcript_path}")
    print("  - Press Ctrl+C to stop listening")
    print("=" * 70)

    try:
        import sounddevice as sd
        import numpy as np
    except ImportError as e:
        print(f"[-] Error loading audio libraries: {e}")
        print("[*] Ensure 'sounddevice' and 'numpy' are available.")
        return

    sample_rate = 16000
    block_size = 480  # 30ms window (frequency resolution ~33.3 Hz)

    # 1. Quick Ambient Noise Calibration
    print("[*] Calibrating ambient room noise (0.3s)...")
    try:
        noise_readings = []
        with sd.InputStream(samplerate=sample_rate, channels=1, blocksize=block_size) as cal_stream:
            for _ in range(12):
                cal_data, _ = cal_stream.read(block_size)
                cal_rms = float(np.sqrt(np.mean(cal_data.flatten() ** 2)))
                noise_readings.append(cal_rms)
        ambient_noise = float(np.mean(noise_readings)) if noise_readings else 0.01
        if threshold == 0.025:
            threshold = max(0.015, ambient_noise * 2.0)
        print(f"[*] Noise Floor: {ambient_noise:.4f} | Dynamic Threshold: {threshold:.4f}")
    except Exception as e:
        print(f"[-] Calibration warning: {e}. Using threshold: {threshold:.4f}")

    # 2. Timing Parameters & Hysteresis
    dot_est = 0.09
    dot_cutoff = 0.20
    letter_pause = 0.50
    word_pause = 1.40

    MIN_TONE_FRAMES = 2       # Need 2 frames (60ms) of tone to start
    MIN_SILENCE_FRAMES = 2    # Need 2 frames (60ms) of silence to end

    consecutive_tone_frames = 0
    consecutive_silence_frames = 0

    tone_active = False
    tone_start_time = 0.0
    tone_end_time = time.time()

    current_letter = []
    current_word = []
    full_sentence = []

    def log_trans(text):
        if not transcript_path:
            return
        try:
            with open(transcript_path, 'a', encoding='utf-8') as f:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] {text}\n")
        except Exception:
            pass

    print("\n[*] Listening for Morse beeps now (human speech is automatically filtered)...")
    sys.stdout.write("\n> ")
    sys.stdout.flush()

    try:
        with sd.InputStream(samplerate=sample_rate, channels=1, blocksize=block_size) as stream:
            while True:
                data, overflowed = stream.read(block_size)
                samples = data.flatten()

                # Calculate RMS energy
                rms = float(np.sqrt(np.mean(samples ** 2)))

                is_tone = False
                if rms >= threshold:
                    spectrum = np.abs(np.fft.rfft(samples))
                    freqs = np.fft.rfftfreq(len(samples), 1.0 / sample_rate)

                    # Frequency bands
                    if target_freq == 750.0:
                        morse_mask = (freqs >= 520) & (freqs <= 1250)
                    else:
                        morse_mask = (freqs >= (target_freq - 120)) & (freqs <= (target_freq + 120))
                    
                    voice_mask = (freqs >= 75) & (freqs < 460)

                    if np.any(morse_mask):
                        morse_spectrum = spectrum[morse_mask]
                        morse_peak = float(np.max(morse_spectrum))
                        morse_mean = float(np.mean(morse_spectrum))
                        morse_energy = float(np.sum(morse_spectrum))

                        voice_spectrum = spectrum[voice_mask]
                        voice_energy = float(np.sum(voice_spectrum)) if np.any(voice_mask) else 0.0

                        # Metric 1: Tonality Purity (Pure sine wave concentrates in 1 bin, speech spreads across many)
                        purity_ratio = morse_peak / (morse_mean + 1e-9)

                        # Metric 2: Voice Fundamental Energy (Human voice has heavy energy below 460 Hz, beeps don't)
                        voice_ratio = voice_energy / (morse_energy + 1e-9)

                        # Pure Morse beep condition: High purity AND low voice fundamental energy
                        if purity_ratio >= 7.5 and voice_ratio < 0.38:
                            is_tone = True

                # Hysteresis frame counting
                if is_tone:
                    consecutive_tone_frames += 1
                    consecutive_silence_frames = 0
                else:
                    consecutive_silence_frames += 1
                    consecutive_tone_frames = 0

                now = time.time()

                # Tone transition: Silence -> Beep (debounced)
                if not tone_active and consecutive_tone_frames >= MIN_TONE_FRAMES:
                    tone_active = True
                    tone_start_time = now - (MIN_TONE_FRAMES * (block_size / sample_rate))

                # Tone transition: Beep -> Silence (debounced)
                elif tone_active and consecutive_silence_frames >= MIN_SILENCE_FRAMES:
                    tone_active = False
                    tone_end_time = now - (MIN_SILENCE_FRAMES * (block_size / sample_rate))
                    dur = tone_end_time - tone_start_time

                    if dur >= 0.040:
                        if dur < dot_cutoff:
                            sym = '.'
                            dot_est = 0.85 * dot_est + 0.15 * dur
                            dot_cutoff = max(0.16, dot_est * 2.2)
                            letter_pause = max(0.40, dot_est * 3.8)
                            word_pause = max(1.05, dot_est * 8.5)
                        else:
                            sym = '-'

                        current_letter.append(sym)
                        sys.stdout.write(sym)
                        sys.stdout.flush()

                # Silence processing: check letter / word breaks
                elif not tone_active:
                    silence_dur = now - tone_end_time

                    # Letter break
                    if current_letter and silence_dur >= letter_pause:
                        code = ''.join(current_letter)
                        char = REVERSE_MORSE_DICT.get(code, f'[{code}?]')
                        current_word.append(char)
                        sys.stdout.write(f" ({char}) ")
                        sys.stdout.flush()
                        current_letter = []

                    # Word break
                    if current_word and silence_dur >= word_pause:
                        word = ''.join(current_word)
                        full_sentence.append(word)
                        sys.stdout.write(" / ")
                        sys.stdout.flush()
                        log_trans(f"DECODED: {word}")
                        current_word = []

                time.sleep(0.005)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n[-] Microphone stream error: {e}")

    # Flush remaining
    if current_letter:
        code = ''.join(current_letter)
        current_word.append(REVERSE_MORSE_DICT.get(code, f'[{code}?]'))
    if current_word:
        full_sentence.append(''.join(current_word))

    final_msg = ' '.join(full_sentence)
    print(f"\n\n[*] Listener Stopped. Final Transcription:\n{final_msg}\n")
    if transcript_path and final_msg:
        log_trans(f"FINAL FULL MESSAGE: {final_msg}")

# ==============================================================================
# MAIN CLI ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hack4Gov CTF Morse Code Engine: Interactive Listener, Tapper, Encoder & Decoder"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--listen", action="store_true", help="Start interactive live listener REPL")
    group.add_argument("-t", "--tap", action="store_true", help="Start interactive mouse (Left=Dot, Right=Dash) & keyboard Morse tapper")
    group.add_argument("-m", "--mic", action="store_true", help="Start real-time live microphone Morse code listener")
    group.add_argument("-d", "--decode", help="Decode Morse code string into plaintext")
    group.add_argument("-e", "--encode", help="Encode plaintext string into Morse code")
    group.add_argument("-a", "--audio", help="Decode Morse code pulses from a .wav audio file")
    
    parser.add_argument("-f", "--file", help="Input text file containing Morse or plaintext to process")
    parser.add_argument("-s", "--sound", action="store_true", help="Play audible beeps for result / live tapping (Windows)")
    parser.add_argument("--threshold", type=float, default=0.025, help="Audio energy threshold (default: auto-calibrated ~0.025)")
    parser.add_argument("--freq", type=float, default=750.0, help="Target Morse tone frequency in Hz (default: 750)")
    parser.add_argument("-o", "--output", help="File to log live decoded transcript")

    args = parser.parse_args()

    # Priority 1: Interactive Modes
    if args.listen:
        interactive_listener()
        return

    if args.tap:
        interactive_tapper(args.sound)
        return

    if args.mic:
        live_microphone_listener(target_freq=args.freq, threshold=args.threshold, transcript_path=args.output)
        return

    # Priority 2: Audio File Decoder
    if args.audio:
        decode_wav_file(args.audio, args.threshold)
        return

    # Priority 3: File Input
    content = ""
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()

    # Priority 4: Direct CLI String
    if args.decode:
        content = args.decode
        decoded = decode_morse(content)
        print(f"[+] DECODED: {decoded}")
        if args.sound:
            play_morse_sound(content)
        return

    if args.encode:
        content = args.encode
        encoded = encode_morse(content)
        print(f"[+] ENCODED: {encoded}")
        if args.sound:
            play_morse_sound(encoded)
        return

    if content:
        # Auto-detect file content
        sample = content.replace(' ', '').replace('/', '').replace('|', '')
        if set(sample).issubset(set('.-_01')):
            print(f"[+] DECODED FROM FILE: {decode_morse(content)}")
        else:
            print(f"[+] ENCODED FROM FILE: {encode_morse(content)}")
        return

    # Default: Show help if no arguments
    parser.print_help()

if __name__ == "__main__":
    main()
