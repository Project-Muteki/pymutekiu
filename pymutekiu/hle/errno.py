from typing import Type
import enum
from enum import auto


class ErrnoNamespace(enum.IntEnum):
    USER = 0x2
    KERNEL = 0x4
    EXEC = 0x8
    APPLET_SPECIFIC = 0x2000


class ErrnoCauseUser(enum.IntEnum):
    THREADING_QUEUE_BUSY = 0x000a
    THREADING_QUEUE_FULL = 0x001e
    THREADING_QUEUE_EMPTY = 0x001f
    THREADING_SLOT_IN_USE = 0x0028
    THREADING_SLOT_FULL = 0x002b
    THREADING_STRUCT_MALLOC_FAILED = 0x0046
    THREADING_THREAD_NOT_SUSPENDED = 0x0065
    THREADING_STACK_MALLOC_FAILED = 0x0066
    THREADING_INVALID_DESCRIPTOR = 0x006e
    THREADING_DESCRIPTOR_BUSY = 0x008c


class ErrnoCauseKernel(enum.IntEnum):
    # Peripheral communication failed.
    PERIPHERAL_COMM_FAILED = 0x0003
    # General hardware error.
    GENERAL_HW_ERROR = auto()

    # FTL: Data corruption detected.
    FTL_DATA_CORRUPTED = 0x0010
    # FTL: Data corruption detected and error correction attempt failed.
    FTL_ECC_FAILED = auto()
    # FTL: Data corruption detected and error correction attempt succeeded.
    FTL_ECC_TRIGGERED = 0x0018
    # FTL: Invalid Logical Block Address.
    FTL_INVALID_LBA = 0x0021
    # Medium is write-protected.
    MEDIUM_WP_ENABLED = 0x0027
    # Medium changed
    MEDIUM_CHANGED = auto()
    # Medium is of an incompatible type.
    MEDIUM_INCOMPATIBLE = 0x0030
    # Medium I/O error.
    MEDIUM_ERROR = auto()
    # Medium is not loaded.
    MEDIUM_UNLOADED = 0x003a

    # Storage device not found.
    SYS_STORAGE_DEVICE_NOT_FOUND = 0x0060
    # Erase of storage device failed.
    SYS_ERASE_FAILED = auto()
    # Out of memory.
    SYS_OUT_OF_MEMORY = auto()
    # Low battery.
    SYS_LOW_BATTERY = auto()
    # Lock switch is on. System is locked.
    SYS_LOCK_SWITCH_ENABLED = auto()

    # Block device format prompt.
    MKFS_PROMPT = 0x0102
    # Block device needs formatting.
    MKFS_UNSUPPORTED = auto()
    # mkfs: No space left for device.
    MKFS_NO_SPACE_LEFT = auto()
    # mkfs: Mode error.
    MKFS_MODE_ERROR = auto()
    # mkfs: I/O error.
    MKFS_IO_ERROR = auto()

    # Invalid drive letter
    FS_INVALID_DRIVE_LETTER = 0x0113

    # Filename contains invalid characters.
    FS_INVALID_FILENAME = 0x0140
    # General filesystem I/O error.
    FS_OPERATION_ERROR = auto()
    # File or directory exists.
    FS_ENTRY_EXISTS = auto()
    # Too many files in this directory.
    FS_DIR_FULL = auto()
    # No such file or directory.
    FS_NO_SUCH_ENTRY = auto()
    # File/directory is not available.
    FS_FILE_UNAVAILABLE = auto()
    # Accessing file out of bound.
    FS_FILE_OOB_ACCESS = auto()
    # Conflicting file/directory attributes
    FS_CONFLICTING_ATTR = auto()
    # Too many open files.
    FS_TOO_MANY_OPEN_FILES = auto()
    # File/directory is locked for exclusive access.
    FS_FILE_LOCKED = auto()
    # Attribute error.
    FS_FILE_ATTR_ERROR = auto()
    # No space left for device.
    FS_NO_SPACE_LEFT = auto()

    # No such file or directory (alternative).
    FS_NO_SUCH_ENTRY_ALT = 0x0154
    # File is read-only.
    FS_READ_ONLY_FILE = 0x0158
    # Path too long.
    FS_PATH_TOO_LONG = 0x0162
    # Internal error. (?)
    FS_INTERNAL = auto()
    # Too many files in this directory (alternative).
    FS_DIR_FULL_ALT1 = 0x0165
    # Too many files in this directory (alternative).
    FS_DIR_FULL_ALT2 = auto()

    # Database is corrupted.
    DB_CORRUPTED = 0x0200
    # Failed to open database.
    DB_OPEN_FAILED = auto()
    # Database index is full. Suggesting entry cleanup.
    DB_INDEX_FULL_DELETE = 0x0203
    # Database is full.
    DB_FULL = auto()
    # Database index is full. Suggesting sync with PC.
    DB_INDEX_FULL_SYNC = auto()
    # Database: too many open files.
    DB_TOO_MANY_OPEN_FILES = auto()


class ErrnoCauseExec(enum.IntEnum):
    EXEC_UNSUPPORTED = 0x0001
    EXEC_INVALID = auto()
    EXEC_OPEN_FAILED = auto()
    EXEC_LOADER_FAILURE = auto()
    EXEC_MALLOC_FAILED = auto()
    EXEC_DECOMPRESSION_FAILED = auto()
    EXEC_MP3_PLAYER_IS_RUNNING = auto()
    EXEC_UNKNOWN_FORMAT = 0x000a


ErrnoCause = ErrnoCauseUser | ErrnoCauseKernel | ErrnoCauseExec | int
ErrnoCauseType = Type[ErrnoCauseUser | ErrnoCauseKernel | ErrnoCauseExec]


def errnotuple2int(namespace: ErrnoNamespace, cause: ErrnoCause):
    return (namespace << 16 | cause) & 0xffffffff


CAUSE_MAP: dict[ErrnoNamespace, ErrnoCauseType] = {
    ErrnoNamespace.USER: ErrnoCauseUser,
    ErrnoNamespace.KERNEL: ErrnoCauseKernel,
    ErrnoNamespace.EXEC: ErrnoCauseExec,
}

STRERROR_USER: dict[ErrnoCauseUser, str] = {
    ErrnoCauseUser.THREADING_QUEUE_BUSY: 'Queue is used by another thread.',
    ErrnoCauseUser.THREADING_QUEUE_FULL: 'Queue is full.',
    ErrnoCauseUser.THREADING_QUEUE_EMPTY: 'Queue is empty.',
    ErrnoCauseUser.THREADING_SLOT_IN_USE: 'Slot is already assigned to another thread.',
    ErrnoCauseUser.THREADING_SLOT_FULL: 'No normal priority slots left for new thread.',
    ErrnoCauseUser.THREADING_STRUCT_MALLOC_FAILED: 'Failed to allocate memory for new thread descriptor.',
    ErrnoCauseUser.THREADING_STACK_MALLOC_FAILED: 'Failed to allocate memory for stack.',
    ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR: 'Invalid thread descriptor.',
    ErrnoCauseUser.THREADING_DESCRIPTOR_BUSY: 'Event descriptor is busy.',
}

STRERROR_KERNEL: dict[ErrnoCauseKernel, str] = {
    ErrnoCauseKernel.PERIPHERAL_COMM_FAILED: 'Peripheral communication failed.',
    ErrnoCauseKernel.GENERAL_HW_ERROR: 'General hardware error.',
    ErrnoCauseKernel.FTL_DATA_CORRUPTED: 'FTL: Data corruption detected.',
    ErrnoCauseKernel.FTL_ECC_FAILED: 'FTL: Data corruption detected and error correction attempt failed.',
    ErrnoCauseKernel.FTL_ECC_TRIGGERED: 'FTL: Data corruption detected and error correction attempt succeeded.',
    ErrnoCauseKernel.FTL_INVALID_LBA: 'FTL: Invalid Logical Block Address.',
    ErrnoCauseKernel.MEDIUM_WP_ENABLED: 'Medium is write protected.',
    ErrnoCauseKernel.MEDIUM_CHANGED: 'Medium changed.',
    ErrnoCauseKernel.MEDIUM_INCOMPATIBLE: 'Medium is of an incompatible type.',
    ErrnoCauseKernel.MEDIUM_ERROR: 'Medium I/O error.',
    ErrnoCauseKernel.MEDIUM_UNLOADED: 'Medium is not loaded.',
    ErrnoCauseKernel.SYS_STORAGE_DEVICE_NOT_FOUND: 'Storage device not found.',
    ErrnoCauseKernel.SYS_ERASE_FAILED: 'Erase of storage device failed.',
    ErrnoCauseKernel.SYS_OUT_OF_MEMORY: 'Out of memory.',
    ErrnoCauseKernel.SYS_LOW_BATTERY: 'Low battery.',
    ErrnoCauseKernel.SYS_LOCK_SWITCH_ENABLED: 'Lock switch is on. System is locked.',
    ErrnoCauseKernel.MKFS_PROMPT: 'Block device format prompt.',
    ErrnoCauseKernel.MKFS_UNSUPPORTED: 'Block device needs formatting.',
    ErrnoCauseKernel.MKFS_NO_SPACE_LEFT: 'mkfs: No space left for device.',
    ErrnoCauseKernel.MKFS_MODE_ERROR: 'mkfs: Mode error.',
    ErrnoCauseKernel.MKFS_IO_ERROR: 'mkfs: I/O error.',
    ErrnoCauseKernel.FS_INVALID_DRIVE_LETTER: 'Invalid drive letter.',
    ErrnoCauseKernel.FS_INVALID_FILENAME: 'Filename contains invalid characters.',
    ErrnoCauseKernel.FS_OPERATION_ERROR: 'General filesystem I/O error.',
    ErrnoCauseKernel.FS_ENTRY_EXISTS: 'File or directory exists.',
    ErrnoCauseKernel.FS_DIR_FULL: 'Too many files in this directory.',
    ErrnoCauseKernel.FS_NO_SUCH_ENTRY: 'No such file or directory.',
    ErrnoCauseKernel.FS_FILE_UNAVAILABLE: 'File/directory is not available.',
    ErrnoCauseKernel.FS_FILE_OOB_ACCESS: 'Accessing file out of bound.',
    ErrnoCauseKernel.FS_CONFLICTING_ATTR: 'Conflicting file/directory attributes.',
    ErrnoCauseKernel.FS_TOO_MANY_OPEN_FILES: 'Too many open files.',
    ErrnoCauseKernel.FS_FILE_LOCKED: 'File/directory is locked for exclusive access.',
    ErrnoCauseKernel.FS_FILE_ATTR_ERROR: 'Attribute error.',
    ErrnoCauseKernel.FS_NO_SPACE_LEFT: 'No space left for device.',
    ErrnoCauseKernel.FS_NO_SUCH_ENTRY_ALT: 'No such file or directory.',
    ErrnoCauseKernel.FS_READ_ONLY_FILE: 'File is read-only.',
    ErrnoCauseKernel.FS_PATH_TOO_LONG: 'Path too long.',
    ErrnoCauseKernel.FS_DIR_FULL_ALT1: 'Too many files in this directory.',
    ErrnoCauseKernel.FS_DIR_FULL_ALT2: 'Too many files in this directory.',
    ErrnoCauseKernel.DB_CORRUPTED: 'Database is corrupted.',
    ErrnoCauseKernel.DB_OPEN_FAILED: 'Failed to open database.',
    ErrnoCauseKernel.DB_INDEX_FULL_DELETE: 'Database index is full. Suggesting entry cleanup.',
    ErrnoCauseKernel.DB_FULL: 'Database is full.',
    ErrnoCauseKernel.DB_INDEX_FULL_SYNC: 'Database index is full. Suggesting sync with PC.',
    ErrnoCauseKernel.DB_TOO_MANY_OPEN_FILES: 'Database: too many open files.',
}

STRERROR_EXEC: dict[ErrnoCauseExec, str] = {
    ErrnoCauseExec.EXEC_UNSUPPORTED: 'Unsupported executable format.',
    ErrnoCauseExec.EXEC_INVALID: 'Invalid executable file.',
    ErrnoCauseExec.EXEC_OPEN_FAILED: 'Failed to open executable file.',
    ErrnoCauseExec.EXEC_LOADER_FAILURE: 'An error occurred when loading the executable.',
    ErrnoCauseExec.EXEC_MALLOC_FAILED: 'Loader failed to allocate memory.',
    ErrnoCauseExec.EXEC_DECOMPRESSION_FAILED: 'Executable decompression failed.',
    ErrnoCauseExec.EXEC_MP3_PLAYER_IS_RUNNING: 'MP3 player is running. Cannot load new executable.',
    ErrnoCauseExec.EXEC_UNKNOWN_FORMAT: 'Unknown executable format.',
}

STRERROR: dict[int, dict[ErrnoCause, str]] = {
    ErrnoNamespace.USER: STRERROR_USER,
    ErrnoNamespace.KERNEL: STRERROR_KERNEL,
    ErrnoNamespace.EXEC: STRERROR_EXEC,
}


def guest_os_strerror(errno: int) -> str:
    ns = (errno >> 16) & 0xffff
    cause = errno & 0xffff
    return STRERROR.get(ns, {}).get(cause, '')


class GuestOSError(RuntimeError):
    """
    Besta RTOS errno in exception form.
    """
    def __init__(self, namespace: ErrnoNamespace, cause: ErrnoCause):
        self.namespace = namespace
        self.cause = cause
        super().__init__(namespace, cause)

    def __str__(self) -> str:
        if hasattr(self.namespace, 'name'):
            namespace_name = self.namespace.name
        else:
            try:
                namespace_name = ErrnoNamespace(self.namespace)
            except ValueError:
                namespace_name = hex(self.namespace)

        if hasattr(self.cause, 'name'):
            cause_name = self.cause.name
        elif self.namespace not in CAUSE_MAP:
            cause_name = hex(self.cause)
        else:
            cause_enum = CAUSE_MAP[self.namespace]
            try:
                cause_name = cause_enum(self.cause)
            except ValueError:
                cause_name = hex(self.cause)

        return f'[Namespace {namespace_name}, Cause {cause_name}] {guest_os_strerror(self.errno)}'

    @property
    def errno(self) -> int:
        return errnotuple2int(self.namespace, self.cause)
