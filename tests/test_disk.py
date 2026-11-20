import struct
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock

from src.ksu_emulator.common import Error
from src.ksu_emulator.disk import Ext4Tools, debugfs_rows, partition_bounds


def mbr(start=2048, sectors=4194304, kind=0x83):
    data = bytearray(512)
    data[510:512] = b"\x55\xaa"
    data[450] = kind
    struct.pack_into("<II", data, 454, start, sectors)
    return data


class DiskContractTests(unittest.TestCase):
    def fsck(self, *codes):
        tools = object.__new__(Ext4Tools)
        tools.call = Mock(side_effect=[CompletedProcess([], code, b"inode diagnostic", b"tool version") for code in codes])
        return tools

    def test_staged_automatic_repair_requires_clean_readback(self):
        tools = self.fsck(1, 0)
        self.assertTrue(tools.check_partition("part", Path("."), prepare=True))
        self.assertEqual([c.args[1][0] for c in tools.call.call_args_list], ["-fp", "-fn"])
        self.assertFalse(self.fsck(0).check_partition("part", Path("."), prepare=True))

    def test_unresolved_or_operational_failure_preserves_fsck_diagnostics(self):
        for codes in ((2,), (4,), (5,), (8,), (1, 4)):
            with self.subTest(codes=codes), self.assertRaisesRegex(Error, "inode diagnostic") as exc:
                self.fsck(*codes).check_partition("part", Path("."), prepare=True)
            self.assertIn("tool version", str(exc.exception))

    def test_final_check_never_repairs_a_modified_partition(self):
        tools = self.fsck(4)
        with self.assertRaises(Error):
            tools.check_partition("part", Path("."))
        self.assertEqual([c.args[1][0] for c in tools.call.call_args_list], ["-fn"])

    def test_partition_bounds_are_bytes_and_bounded(self):
        self.assertEqual(partition_bounds(mbr(), 2685403136), (1048576, 2147483648))
        with self.assertRaises(Error):
            partition_bounds(mbr(), 1024)

    def test_gpt_or_wrong_partition_is_not_guessed(self):
        for data in (mbr(kind=0xEE), mbr(start=0), bytes(512), b"short"):
            with self.subTest(data=data[:4]), self.assertRaises(Error):
                partition_bounds(data, 4 << 30)

    def test_overlapping_partitions_are_rejected(self):
        data = mbr()
        data[466] = 0x83
        struct.pack_into("<II", data, 470, 4096, 1024)
        with self.assertRaises(Error):
            partition_bounds(data, 4 << 30)

    def test_debugfs_listing_has_explicit_inode_and_type(self):
        rows = debugfs_rows("/962/040755/0/0/.//\n/901/040755/0/0/..//\n/966/100644/0/0/config.txt/12/\n")
        self.assertEqual(rows[-1], (966, 0o100644, "config.txt"))

    def test_missing_directory_is_not_an_empty_success(self):
        with self.assertRaises(Error):
            debugfs_rows("")

    def test_guest_names_cannot_inject_debugfs_commands(self):
        for name in ('bad"name', "a;quit", "name with spaces"):
            with self.subTest(name=name), self.assertRaises(Error):
                debugfs_rows(f"/1/040755/0/0/.//\n/2/100644/0/0/{name}/12/\n")
