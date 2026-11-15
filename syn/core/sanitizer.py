"""
SYN - Input Validation and Output Sanitization Helpers
"""

import html
import re
from typing import Any, List, Tuple
from rich.markup import escape as rich_escape

# Match ANSI CSI sequences, OSC sequences, and single ESC sequences
_ANSI_RE = re.compile(
    r"\x1B(?:\][^\x07\x1B]*(?:\x07|\x1B\\)|\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])"
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars(text: Any, single_line: bool = True) -> str:
    """Remove ANSI escape codes and unsafe non-printable control characters."""
    if text is None:
        return ""
    cleaned = str(text)
    cleaned = _ANSI_RE.sub("", cleaned)
    cleaned = _CONTROL_RE.sub("", cleaned)
    if single_line:
        cleaned = re.sub(r"[\r\n\t]+", " ", cleaned)
        cleaned = re.sub(r" {2,}", " ", cleaned).strip()
    return cleaned


def truncate_text(text: str, max_len: int) -> str:
    """Safely truncate text to max_len if positive."""
    if max_len > 0 and len(text) > max_len:
        if max_len <= 3:
            return text[:max_len]
        return text[: max_len - 3] + "..."
    return text


def sanitize_terminal_text(text: Any, max_len: int = 0) -> str:
    """Sanitize untrusted text for safe Rich console rendering (no ANSI/Markup injection)."""
    cleaned = strip_control_chars(text, single_line=True)
    cleaned = truncate_text(cleaned, max_len)
    return rich_escape(cleaned)


def escape_html(text: Any, max_len: int = 0) -> str:
    """Sanitize and HTML-escape untrusted text."""
    cleaned = strip_control_chars(text, single_line=True)
    cleaned = truncate_text(cleaned, max_len)
    return html.escape(cleaned, quote=True)


def escape_markdown_cell(text: Any, max_len: int = 0) -> str:
    """Sanitize and escape untrusted text for safe Markdown table cells."""
    cleaned = strip_control_chars(text, single_line=True)
    cleaned = truncate_text(cleaned, max_len)
    # Escape characters that can break tables, inline code, links, or inject raw HTML
    for src, dst in (
        ("\\", "\\\\"),
        ("`", "'"),
        ("|", "/"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("[", "\\["),
        ("]", "\\]"),
    ):
        cleaned = cleaned.replace(src, dst)
    return cleaned


def is_valid_port(port: Any) -> bool:
    """Check if value is a valid TCP/UDP port (1..65535)."""
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def validate_port_range(start_port: int, end_port: int) -> Tuple[int, int]:
    """Validate and return (start_port, end_port) or raise ValueError."""
    if not is_valid_port(start_port) or not is_valid_port(end_port):
        raise ValueError(f"Ports must be integers between 1 and 65535 (got {start_port}-{end_port}).")
    if start_port > end_port:
        raise ValueError(f"Start port ({start_port}) cannot exceed end port ({end_port}).")
    return start_port, end_port


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse flexible port specification strings such as '22,80,443,8000-8100'
    into a deduplicated sorted list of validated TCP/UDP ports.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Port specification must be a non-empty string.")

    selected = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            raise ValueError(f"Empty port token in specification: '{spec}'.")
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not parts[0].strip().isdigit() or not parts[1].strip().isdigit():
                raise ValueError(f"Invalid port range token: '{token}'.")
            start_p = int(parts[0].strip())
            end_p = int(parts[1].strip())
            validate_port_range(start_p, end_p)
            selected.update(range(start_p, end_p + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port value: '{token}'.")
            port_val = int(token)
            if not is_valid_port(port_val):
                raise ValueError(f"Port must be between 1 and 65535 (got {port_val}).")
            selected.add(port_val)

    return sorted(selected)
