"""明文 wxapkg 文件表解析与解包."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from io import BytesIO
from typing import Iterator


class WxapkgUnpackError(ValueError):
    """解包失败."""


@dataclass
class WxapkgEntry:
    name: str
    offset: int
    size: int


@dataclass
class UnpackResult:
    file_count: int
    entries: list[WxapkgEntry]
    written: list[str]


def parse_file_table(data: bytes) -> list[WxapkgEntry]:
    if len(data) < 18:
        raise WxapkgUnpackError("文件过短")
    bio = BytesIO(data)
    first = struct.unpack("B", bio.read(1))[0]
    _info = struct.unpack(">I", bio.read(4))[0]
    _index_len = struct.unpack(">I", bio.read(4))[0]
    _body_len = struct.unpack(">I", bio.read(4))[0]
    last = struct.unpack("B", bio.read(1))[0]
    if first != 0xBE or last != 0xED:
        raise WxapkgUnpackError("非法 wxapkg 头（需要 0xBE ... 0xED）")

    file_count = struct.unpack(">I", bio.read(4))[0]
    if file_count <= 0 or file_count > 100_000:
        raise WxapkgUnpackError(f"异常文件数: {file_count}")

    entries: list[WxapkgEntry] = []
    for _ in range(file_count):
        name_len = struct.unpack(">I", bio.read(4))[0]
        if name_len <= 0 or name_len > 2048:
            raise WxapkgUnpackError(f"异常文件名长度: {name_len}")
        raw_name = bio.read(name_len)
        if len(raw_name) != name_len:
            raise WxapkgUnpackError("文件名读取不完整")
        name = raw_name.decode("utf-8", errors="replace")
        offset = struct.unpack(">I", bio.read(4))[0]
        size = struct.unpack(">I", bio.read(4))[0]
        if offset + size > len(data):
            raise WxapkgUnpackError(f"文件越界: {name}")
        entries.append(WxapkgEntry(name=name, offset=offset, size=size))
    return entries


def _safe_join(out_dir: str, name: str) -> str:
    """阻止路径穿越；name 通常以 / 开头."""
    rel = name.lstrip("/\\").replace("\\", "/")
    parts = [p for p in rel.split("/") if p and p not in (".", "..")]
    if not parts:
        raise WxapkgUnpackError(f"非法路径: {name!r}")
    dest = os.path.normpath(os.path.join(out_dir, *parts))
    out_root = os.path.normpath(out_dir)
    if dest != out_root and not dest.startswith(out_root + os.sep):
        raise WxapkgUnpackError(f"拒绝写出到包外: {name}")
    return dest


def unpack_bytes(data: bytes, out_dir: str) -> UnpackResult:
    os.makedirs(out_dir, exist_ok=True)
    entries = parse_file_table(data)
    written: list[str] = []
    for ent in entries:
        dest = _safe_join(out_dir, ent.name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data[ent.offset : ent.offset + ent.size])
        written.append(dest)
    return UnpackResult(file_count=len(entries), entries=entries, written=written)


def iter_js_files(root: str) -> Iterator[str]:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.lower().endswith((".js", ".wxs")):
                yield os.path.join(dirpath, name)
