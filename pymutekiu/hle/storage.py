import functools
from typing import TYPE_CHECKING, Protocol, Optional, AnyStr, IO
from fs.errors import FSError, ResourceNotFound

import fs
import logging
import string
import pathlib
import itertools
import re
import ntpath

from .errno import GuestOSError, ErrnoCauseKernel, ErrnoNamespace

if TYPE_CHECKING:
    from fs.base import FS, SubFS
    from unicorn import Uc
    from .states import OSStates

_logger = logging.getLogger('loader')


_WINEHASH_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

_SFN_INVALID_CHARS = re.escape(r'\x00*?<>|"+=,;[]~.')
_SFN_INVALID_CHARS_M = re.compile(f"[{_SFN_INVALID_CHARS}|[\u007f-\U0010ffff]")


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


def _strip_drive_from_abs_path(path: pathlib.PureWindowsPath) -> pathlib.PureWindowsPath:
    if path.drive == '':
        return path
    return pathlib.PureWindowsPath('\\', path.relative_to(path.anchor))


@functools.lru_cache(128)
def _shrink_lfn_part(part_str: str) -> str:
    part = pathlib.PureWindowsPath(part_str)
    stem_no_invalid = _SFN_INVALID_CHARS_M.sub('_', part.stem.replace(' ', ''))
    suffix_no_invalid = _SFN_INVALID_CHARS_M.sub('_', part.suffix[1:].replace(' ', '_'))
    if part_str[-1] != '.' and \
            stem_no_invalid == part.stem and suffix_no_invalid == part.suffix[1:] and \
            len(stem_no_invalid) <= 8 and len(suffix_no_invalid) <= 3:
        new_stem = stem_no_invalid.upper()
        new_suffix = suffix_no_invalid.upper()
    else:
        new_stem_1 = stem_no_invalid.upper()[:4]
        new_stem_2 = '~' * (5 - len(new_stem_1))
        new_stem_3 = _winehash(part_str)
        new_stem = ''.join((new_stem_1, new_stem_2, new_stem_3))
        new_suffix = suffix_no_invalid.upper()[:3]
    return new_stem if new_suffix == '' else '.'.join((new_stem, new_suffix))


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

    def get_underlying_fs(self, letter: str) -> 'FS':
        return self._drives[letter]

    def mount_drive(self, letter: str | pathlib.PureWindowsPath, fs_path: str) -> None:
        assert letter not in self._drives, f'Drive letter {repr(letter)} already in use.'
        self._drives[letter] = fs.open_fs(fs_path)
        self._cwd[letter] = pathlib.PureWindowsPath('\\')
        self._cwd_fs[letter] = self._drives[letter].opendir('/')

    def unmount_drive(self, letter: str) -> None:
        assert letter in self._drives, f'Drive {repr(letter)} not mounted.'
        self._drives[letter].close()
        del self._drives[letter]
        del self._cwd[letter]
        del self._cwd_fs[letter]

    def _expand_sfn(self, path: pathlib.PureWindowsPath) -> pathlib.PureWindowsPath:
        if path.anchor != '':
            path_rel_to_anchor = path.relative_to(path.anchor)
        else:
            path_rel_to_anchor = path

        drive = self._current_drive if path.drive == '' else path.drive[:-1]

        path_lfn_parts = []
        is_terminal = False
        if drive not in self._cwd_fs:
            raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.SYS_STORAGE_DEVICE_NOT_FOUND)
        search_path = self._cwd_fs[drive]
        for part in path_rel_to_anchor.parts:
            if is_terminal:
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_NO_SUCH_ENTRY)
            if search_path.exists(part):
                path_lfn_parts.append(part)
                continue
            # Basic sanity check to rule out an LFN mismatch
            # TODO do more test here
            if len(part) > 12:
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_NO_SUCH_ENTRY)
            found_entry: Optional[str] = None
            for entry in search_path.listdir('.'):
                if _shrink_lfn_part(entry) == part:
                    found_entry = entry
                    continue
            if found_entry is None:
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_NO_SUCH_ENTRY)
            path_lfn_parts.append(found_entry)
            if search_path.isdir(found_entry):
                search_path = search_path.opendir(found_entry)
            else:
                is_terminal = True
        return pathlib.PureWindowsPath(path.anchor, *path_lfn_parts)

    def _shrink_lfn(self, path: pathlib.PureWindowsPath) -> pathlib.PureWindowsPath:
        if path.is_absolute():
            path_driveless = path.relative_to(path.anchor)
        else:
            path_driveless = path
        new_parts: list[str] = []
        for part_str in path_driveless.parts:
            new_parts.append(_shrink_lfn_part(part_str))
        return pathlib.PureWindowsPath(path.anchor, *new_parts)

    def getcwd(self, sfn: bool = False) -> pathlib.PureWindowsPath:
        cwd_nodrive = self._cwd[self._current_drive]
        # TODO handle sfn
        if sfn:
            cwd_nodrive = self._shrink_lfn(cwd_nodrive)
        return pathlib.PureWindowsPath(f'{self._current_drive}:', cwd_nodrive)

    # TODO
    def open(self, path: str | pathlib.PureWindowsPath, mode: str) -> IO[AnyStr]:
        path = pathlib.PureWindowsPath(path)
        if path.is_absolute():
            drive = path.drive
            if drive == '':
                # Use current drive if drive is not set
                drive = self._current_drive
            elif drive[-1] == ':':
                # Use the specified drive letter if available
                drive = drive[:-1]
            else:
                # TODO handle UNC (do we need to do it here or do we have another layer that handles device IO?)
                _logger.error('UNC path %s not supported on VFS.', repr(str(path)))
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_INVALID_FILENAME)
            parts = _strip_drive_from_abs_path(path)
        else:
            drive = self._current_drive
            parts = path
        parts = self._expand_sfn(parts)
        try:
            return self._cwd_fs[drive].open(parts.as_posix(), mode)
        except FSError as e:
            if isinstance(e, ResourceNotFound):
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_NO_SUCH_ENTRY) from e
            else:
                raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.FS_INTERNAL) from e


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
