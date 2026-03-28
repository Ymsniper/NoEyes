# Wire framing and file utilities for NoEyes client.
import json
import socket
import struct
from pathlib import Path
from typing import Optional

RECEIVE_BASE = Path(__file__).parent.parent / "received_files"
FILE_CHUNK_SIZE = 512 * 1024

_TYPE_MAP = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
               ".ico", ".tiff", ".tif", ".heic", ".heif"},
    "videos": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
               ".m4v", ".mpg", ".mpeg"},
    "audio":  {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma",
               ".opus", ".aiff"},
    "docs":   {".pdf", ".doc", ".docx", ".txt", ".md", ".xlsx", ".xls",
               ".pptx", ".ppt", ".csv", ".odt", ".rtf", ".pages"},
}


def _file_type_folder(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    for folder, exts in _TYPE_MAP.items():
        if ext in exts:
            return folder
    return "other"


def _unique_dest(filename: str) -> Path:
    """Return a unique Path in the right received_files sub-folder."""
    folder = RECEIVE_BASE / _file_type_folder(filename)
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / filename
    counter = 1
    while dest.exists():
        stem, suffix = Path(filename).stem, Path(filename).suffix
        dest = folder / f"{stem}_{counter}{suffix}"
        counter += 1
    return dest


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Optional[tuple]:
    """Read one frame. Returns (header_dict, raw_payload_bytes) or None."""
    size_buf = _recv_exact(sock, 8)
    if size_buf is None:
        return None
    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]

    if header_len == 0 or header_len > 65536:
        return None

    _MAX_PAYLOAD = 16 * 1024 * 1024
    if payload_len > _MAX_PAYLOAD:
        return None

    header_bytes  = _recv_exact(sock, header_len)
    if header_bytes is None:
        return None
    payload_bytes = _recv_exact(sock, payload_len) if payload_len else b""
    if payload_bytes is None:
        return None

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    return header, payload_bytes


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> bool:
    try:
        hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
        sock.sendall(struct.pack(">I", len(hb)) + struct.pack(">I", len(payload)) + hb + payload)
        return True
    except OSError:
        return False