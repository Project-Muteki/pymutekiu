from typing import cast
import unittest
import unittest.mock as mock
import struct

from pymutekiu.hle.storage import VFS


class VFSWithCDrive(unittest.TestCase):
    def setUp(self):
        self._vfs = VFS(mock.MagicMock(), mock.MagicMock())
        self._vfs.mount_drive('C', 'mem://')
        self._fs = self._vfs.get_underlying_fs('C')

    def test_open_sfn(self):
        """
        Should be able to read a file with its SFN.
        """
        self._fs.writetext('/nyancat.8bpp.hca', 'hello')
        result = self._vfs.open('C:\\NYAN~0WU.HCA', 'r')
        self.assertEqual(result.read(), 'hello')

    def test_open_lfn(self):
        """
        Should be able to read a file with its LFN.
        """
        self._fs.writetext('/nyancat.8bpp.hca', 'hello')
        result = self._vfs.open('C:\\nyancat.8bpp.hca', 'r')
        self.assertEqual(result.read(), 'hello')
