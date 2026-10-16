import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.ksu_emulator.build import extract_source
from src.ksu_emulator.bundle import validate_bundle
from src.ksu_emulator.common import Error, load_profile, save_json
from src.ksu_emulator.elf import module_info
from src.ksu_emulator.install import install
from src.ksu_emulator.mumu import MuMu
from src.ksu_emulator.probe import validate_guest


def elf_fixture(*, architecture=183, truncated=False):
    names = b"\0.shstrtab\0.modinfo\0.strtab\0.symtab\0"
    modinfo = b"name=kernelsu\0vermagic=4.19.195-test SMP preempt mod_unload aarch64\0license=GPL\0"
    strings = b"\0missing_function\0"
    symbols = bytes(24) + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0)
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 1, architecture, 1)
    sections = [(0,) * 10]
    for name, kind, content, link, entsize in [
        (1, 3, names, 0, 0), (11, 1, modinfo, 0, 0),
        (20, 3, strings, 0, 0), (28, 2, symbols, 3, 24),
    ]:
        offset = len(data)
        data.extend(content)
        sections.append((name, kind, 0, 0, offset, len(content), link, 0, 1, entsize))
    struct.pack_into("<Q", data, 40, len(data))
    struct.pack_into("<HHH", data, 58, 64, len(sections), 1)
    for section in sections:
        data.extend(struct.pack("<IIQQQQIIQQ", *section))
    return bytes(data[:-8] if truncated else data)


class ElfTests(unittest.TestCase):
    def test_reads_module_contract(self):
        info = module_info(elf_fixture())
        self.assertEqual(info["undefined_symbols"], ["missing_function"])
        self.assertEqual(info["name"], "kernelsu")

    def test_rejects_wrong_architecture(self):
        with self.assertRaises(Error):
            module_info(elf_fixture(architecture=62))

    def test_rejects_truncated_sections(self):
        with self.assertRaises(Error):
            module_info(elf_fixture(truncated=True))

    def test_rejects_out_of_bounds_string_table(self):
        data = bytearray(elf_fixture())
        table = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<Q", data, table + 64 + 24, 2**63)
        with self.assertRaises(Error):
            module_info(bytes(data))


class GuardTests(unittest.TestCase):
    def test_exact_guest_identity_is_required(self):
        profile = load_profile()
        evidence = {**profile, "adb_uid": "0", "config": {"CONFIG_MODULES": "y"}}
        validate_guest(evidence, profile)
        for key in ("kernel_release", "kernel_version", "architecture", "android_version", "config_gz_sha256"):
            with self.subTest(key=key), self.assertRaises(Error):
                validate_guest({**evidence, key: "different"}, profile)

    def test_bootstrap_root_is_required(self):
        with self.assertRaises(Error):
            validate_guest({**load_profile(), "adb_uid": "2000"}, load_profile())

    def test_arbitrary_instance_selector_is_rejected(self):
        mumu = object.__new__(MuMu)
        mumu.call = Mock()
        for index in ("all", "0,1", -1, True):
            with self.subTest(index=index), self.assertRaises(Error):
                mumu.info(index)
        mumu.call.assert_not_called()

    def test_corrupt_bundle_cannot_stop_or_change_instance(self):
        mumu = Mock()
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(Error):
            install(mumu, 2, Path(temp))
        self.assertFalse(mumu.mock_calls)

    def test_bundle_cannot_inject_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            save_json(path / "manifest.json", {"schema": 1, "profile": load_profile(), "files": {"../outside": "0" * 64}})
            with self.assertRaises(Error):
                validate_bundle(path)

    def test_archive_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            archive = path / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                entry = tarfile.TarInfo("../../escaped")
                entry.size = 1
                output.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaises(tarfile.FilterError):
                extract_source(archive, path / "dest")
            self.assertFalse((path / "escaped").exists())


if __name__ == "__main__":
    unittest.main()
