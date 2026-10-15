"""Small, bounds-checked reader for ELF64 ARM64 kernel module metadata."""
from __future__ import annotations

import struct

from .common import Error


def module_info(data: bytes) -> dict:
    def region(offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
            raise Error("Truncated ELF section")
        return data[offset:offset + length]

    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise Error("Expected a little-endian ELF64 module")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 1 or machine != 183:
        raise Error("Expected a relocatable ARM64 module")
    table = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, name_index = struct.unpack_from("<HHH", data, 58)
    if entry_size != 64 or not count or name_index >= count:
        raise Error("Invalid ELF section table")
    region(table, count * entry_size)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, table + i * 64) for i in range(count)]

    def section_data(section: tuple) -> bytes:
        return region(section[4], section[5])

    def string(strings: bytes, offset: int) -> str:
        if offset >= len(strings):
            raise Error("Invalid ELF string offset")
        end = strings.find(b"\0", offset)
        if end < 0:
            raise Error("Unterminated ELF string")
        try:
            return strings[offset:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise Error("Non-ASCII ELF metadata") from exc

    names = section_data(sections[name_index])
    result: dict = {"architecture": "aarch64", "undefined_symbols": [], "absolute_symbols": []}
    for section in sections:
        name = string(names, section[0])
        if name == ".modinfo":
            for field in section_data(section).split(b"\0"):
                if b"=" in field:
                    key, value = field.decode("ascii").split("=", 1)
                    if key in {"name", "vermagic", "license"}:
                        result[key] = value
        if section[1] == 2:
            if section[6] >= count or section[9] != 24 or section[5] % 24:
                raise Error("Invalid ELF symbol table")
            strings = section_data(sections[section[6]])
            symbols = section_data(section)
            for offset in range(0, len(symbols), 24):
                n, _, _, index, value, _ = struct.unpack_from("<IBBHQQ", symbols, offset)
                if n and index == 0:
                    result["undefined_symbols"].append(string(strings, n))
                elif n and index == 0xfff1 and value >= 0xffff000000000000:
                    result["absolute_symbols"].append(string(strings, n))
    if not result.get("vermagic") or result.get("name") != "kernelsu":
        raise Error("Not a KernelSU module with vermagic")
    return result
