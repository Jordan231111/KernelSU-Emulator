import struct
import unittest

from src.ksu_emulator.common import Error
from src.ksu_emulator.disk import debugfs_rows, partition_bounds


def mbr(start=2048, sectors=4194304, kind=0x83):
    data = bytearray(512)
    data[510:512] = b"\x55\xaa"
    data[450] = kind
    struct.pack_into("<II", data, 454, start, sectors)
    return data


class DiskContractTests(unittest.TestCase):
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
