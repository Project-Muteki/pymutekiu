from typing import TYPE_CHECKING, Protocol, Optional

import fs
import logging
import string
import pathlib
import itertools
import ntpath

from .errno import GuestOSError, ErrnoCauseKernel, ErrnoNamespace

if TYPE_CHECKING:
    from fs.base import FS, SubFS
    from unicorn import Uc
    from .states import OSStates

_logger = logging.getLogger('loader')


_WINEHASH_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'


def _winehash(str_: str, seed: int = 0xbeef) -> str:
    """
    An implementation of the hash function used by Wine to mangle a path part into SFN.
    :param str_: A Python string.
    :param seed: Seed. Wine used 0xbeef.
    :return: A 3 character string that is safe to be used in 8.3 filenames.
    """
    bytes_ = str_.lower().encode('utf-16le')
    h = seed
    for a, b in itertools.pairwise(itertools.batched(bytes_, 2)):
        h = ((h << 3) ^ (h >> 5) ^ (a[0] | (a[1] << 8)) ^ (b[0] << 8)) & 0xffff
    h = ((h << 3) ^ (h >> 5) ^ (bytes_[-2] | (bytes_[-1] << 8))) & 0xffff
    return f'{_WINEHASH_B32[(h >> 10) & 0x1f]}{_WINEHASH_B32[(h >> 5) & 0x1f]}{_WINEHASH_B32[h & 0x1f]}'


class BlockDeviceIO(Protocol):
    """
    Base protocol for block device IO.
    """
    def write(self, offset: int, data: bytes | bytearray | memoryview): ...
    def read(self, offset: int, size: int) -> bytes: ...
    def block_write(self, block_offset: int, data: bytes | bytearray | memoryview): ...
    def block_read(self, block_offset: int, block_count: int) -> bytes: ...
    def close(self) -> None: ...

    @property
    def block_size(self) -> int:
        return 0

    @property
    def size(self) -> int:
        return 0


class DevNullZeroBlockDevice:
    """
    Dummy block device that always return all 0 on read and discard all writes.
    """
    def __init__(self, size: Optional[int] = None):
        self._size = size if size is not None else (1 << 64) - 1

    def write(self, block_addr: int, data: bytes | bytearray | memoryview):
        return

    def read(self, block_addr: int, size: int) -> bytes:
        return b'\x00' * size

    def block_write(self, block_offset: int, data: bytes | bytearray | memoryview):
        return

    def block_read(self, block_offset: int, block_count: int) -> bytes:
        return b'\x00' * block_count * self.block_size

    def close(self) -> None:
        return

    @property
    def block_size(self) -> int:
        return 512

    @property
    def size(self) -> int:
        return self._size


class VFS:
    """
    Virtual File System wrapper.
    """
    _uc: 'Uc'
    _states: 'OSStates'
    _drives: dict[str, 'FS']
    _cwd: dict[str, pathlib.PureWindowsPath]
    _cwd_fs: dict[str, 'SubFS']
    _current_drive: str

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._drives = {}
        self._cwd = {}
        self._cwd_fs = {}
        self._current_drive = 'C'

    def mount_drive(self, letter: str, fs_path: str) -> None:
        assert letter not in self._drives, f'Drive letter {repr(letter)} already in use.'
        self._drives[letter] = fs.open_fs(fs_path)
        self._cwd[letter] = pathlib.PureWindowsPath('\\')

    def unmount_drive(self, letter: str) -> None:
        assert letter in self._drives, f'Drive {repr(letter)} not mounted.'
        self._drives[letter].close()
        del self._drives[letter]
        del self._cwd[letter]

    def getcwd(self, sfn: bool = False):
        # TODO handle sfn
        return f'{self._current_drive}:{str(self._cwd[self._current_drive])}'

    # TODO
    def open(self, path: str, mode: str):
        ...


class BlockDeviceManager:
    """
    Block device manager class.
    """
    _uc: 'Uc'
    _states: 'OSStates'
    _drives: dict[str, BlockDeviceIO]

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._drives = {}


class StorageManager:
    """
    VFS and block device manager class.
    """
    _uc: 'Uc'
    _states: 'OSStates'
    _drives: set[str]
    vfs: VFS
    blkdev: BlockDeviceManager
    _VALID_DRIVE_LETTER: frozenset[str] = frozenset(string.ascii_uppercase)
    _DRIVE_ID_TO_LETTER: str = f'CAB{string.ascii_uppercase[3:]}'

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states
        self.vfs = VFS(uc, states)
        self.blkdev = BlockDeviceManager(uc,states)

    def _rectify_id_or_letter(self, letter_or_id: str | int) -> str:
        if isinstance(letter_or_id, int):
            letter = self._DRIVE_ID_TO_LETTER[letter_or_id]
        else:
            letter = letter_or_id.upper()
        return letter

    def _check_drive_before_mount(self, letter_or_id: str | int) -> str:
        letter = self._rectify_id_or_letter(letter_or_id)

        if letter not in self._VALID_DRIVE_LETTER:
            _logger.error('Invalid drive letter %s requested.', repr(letter))
            raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_INVALID_DRIVE_LETTER)
        if letter in self._drives:
            _logger.error('Drive letter %s already in use.', repr(letter))
            raise ValueError(f'Drive letter {repr(letter)} already in use.')
        return letter

    def mount_directory(self, letter_or_id: str | int, path: str) -> None:
        letter = self._check_drive_before_mount(letter_or_id)
        self.vfs.mount_drive(letter, path)
        # self.block_device.mount_os_block_device(letter, path)
        self._drives.add(letter)

    def unmount_drive(self, letter_or_id: str | int) -> None:
        letter = self._rectify_id_or_letter(letter_or_id)

        if letter not in self._drives:
            _logger.error('Drive %s not mounted.', repr(letter))
            raise ValueError(f'Drive {repr(letter)} not mounted.')
        self._drives.remove(letter)
