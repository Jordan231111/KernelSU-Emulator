"""Small, exact-hash repairs to vendor helpers; original binaries are not shipped."""
import hashlib
import json

from .common import Error
from .profiles import repository_file


def repair_binary(before: bytes, item: dict) -> bytes:
    patch = json.loads(repository_file(item["patch"]).read_text())
    if patch.get("schema") != 1 or any(patch.get(key) != item.get(key) for key in
                                      ("path", "before_sha256", "after_sha256")):
        raise Error("Vendor helper patch does not match its specification")
    if hashlib.sha256(before).hexdigest() != item["before_sha256"]:
        raise Error("Vendor helper differs from the reviewed binary: " + item["path"])
    edits = patch.get("edits")
    if not isinstance(edits, list) or not edits:
        raise Error("Vendor helper patch has no reviewed edits")
    output = bytearray(before)
    end = 0
    for edit in edits:
        if not isinstance(edit, dict):
            raise Error("Invalid vendor helper edit")
        try:
            offset = edit["offset"]
            old, new = bytes.fromhex(edit["before"]), bytes.fromhex(edit["after"])
        except (KeyError, TypeError, ValueError) as exc:
            raise Error("Invalid vendor helper edit") from exc
        if (type(offset) is not int or offset < end or not old or len(old) != len(new)
                or offset + len(old) > len(before) or before[offset:offset+len(old)] != old):
            raise Error("Vendor helper edits overlap, exceed the binary or mismatch its bytes")
        output[offset:offset+len(old)] = new
        end = offset + len(old)
    if hashlib.sha256(output).hexdigest() != item["after_sha256"]:
        raise Error("Patched vendor helper checksum differs from the reviewed result")
    return bytes(output)
