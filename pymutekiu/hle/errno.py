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
    THREADING_STACK_MALLOC_FAILED = 0x0066
    THREADING_INVALID_DESCRIPTOR = 0x006e
    THREADING_DESCRIPTOR_BUSY = 0x008c


class ErrnoCauseKernel(enum.IntEnum):
    ...


class ErrnoCauseExec(enum.IntEnum):
    ...


ErrnoCause = ErrnoCauseUser | int
ErrnoCauseType = Type[ErrnoCauseUser]


def errnotuple2int(namespace: ErrnoNamespace, cause: ErrnoCause):
    return (namespace << 16 | cause) & 0xffffffff


CAUSE_MAP: dict[ErrnoNamespace, ErrnoCauseType] = {
    ErrnoNamespace.USER: ErrnoCauseUser,
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

STRERROR: dict[int, dict[ErrnoCause, str]] = {
    ErrnoNamespace.USER: STRERROR_USER,
}


def guest_os_strerror(errno: int) -> str:
    ns = (errno >> 16) & 0xffff
    cause = errno & 0xffff
    return STRERROR.get(ns, {}).get(cause, '')


class GuestOSError(RuntimeError):
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
