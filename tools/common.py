from datetime import datetime
import re
from typing import List, Dict

def log_progress(message: str, prefix: str = "🔍"):
    """Helper function to log progress with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {prefix} {message}")

# Prompt-Injection Firewall (from todo.md 1B)

# Minimal, spec-aligned patterns targeting instruction hijacks and common injection closers.
DANGEROUS_PATTERNS: List[str] = [
    r"(?i)\bignore\b.*\bprevious\b.*\binstruction",   # "ignore previous instructions"
    r"(?i)\bsystem\s+prompt\b",                        # "system prompt"
    r"(?i)\bdisregard\b.*\bpolicy\b",                 # "disregard ... policy"
    r"[\"')\]}]\s*;?\s*--?\s*end",                    # injection-ish closers
]

# Pre-compile regexes for performance.
_COMPILED_PATTERNS = [(p, re.compile(p)) for p in DANGEROUS_PATTERNS]

# Control characters to strip (including DEL 0x7F). Matches spec intent.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B-\x1F\x7F]")

def sanitize_log(msg: str) -> Dict[str, object]:
    """
    Prompt-injection firewall for log text before LLM ingestion.

    Returns:
      {
        "text": <cleaned text>,
        "pi_flags": [<pattern strings that matched>],
        "safe": <bool indicating no matches found>
      }

    Behavior:
    - Flags instruction-hijack phrases and injection-like closers.
    - Removes ASCII control characters.
    - Leaves content otherwise intact for downstream review/weighting.
    """
    if msg is None:
        msg = ""

    # Detect matches
    flags: List[str] = []
    for patt, creg in _COMPILED_PATTERNS:
        if creg.search(msg):
            flags.append(patt)

    # Strip control characters (preserve printable text)
    clean = _CONTROL_CHARS.sub(" ", msg)

    # Normalize redundant whitespace introduced by stripping controls
    clean = re.sub(r"[ \t]{2,}", " ", clean)
    clean = re.sub(r"\s+\n", "\n", clean)
    clean = clean.strip()

    return {"text": clean, "pi_flags": flags, "safe": len(flags) == 0}

def is_safe(msg: str) -> bool:
    """
    Convenience: True if no prompt-injection patterns found.
    """
    return sanitize_log(msg)["safe"]