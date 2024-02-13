import logging

from .common import syscalldef, SyscallModule
from ..errno import GuestOSError, ErrnoNamespace, ErrnoCauseUser

_logger = logging.getLogger('syscall.threading')


class Threading(SyscallModule):
    @syscalldef(0x10000, 'pointer', ['pointer', 'pointer', 'uint32', 'bool'])
    def OSCreateThread(self, func: int, user_data: int, stack_size: int, defer_start: bool) -> int:
        try:
            thr = self._states.sched.new_thread(func, user_data, stack_size, defer_start)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0
        return thr

    @syscalldef(0x10001, 'int', ['pointer', 'int'])
    def OSTerminateThread(self, thr: int, exit_code: int) -> int:
        _logger.info('OSTerminateThread: Thread %08x exiting with code %d.', thr, exit_code)
        self._states.sched.delete_thread(thr)
        return 0

    @syscalldef(0x10002, 'bool', ['pointer', 'short'])
    def OSSetThreadPriority(self, thr: int, new_slot: int) -> bool:
        try:
            self._states.sched.move_thread_to_slot(thr, new_slot)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return False
        return True

    @syscalldef(0x10003, 'short', ['pointer'])
    def OSGetThreadPriority(self, thr: int) -> int:
        try:
            if thr == 0:
                raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)
            desc = self._states.sched.read_thread_descriptor(thr)
            desc.validate()
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            # This seems to be what Besta RTOS returns when there's an error.
            return 0x78
        return desc.slot

    @syscalldef(0x10007, 'int', ['int'])
    def OSExitThread(self, exit_code: int) -> int:
        thr = self._states.sched.current_thread
        _logger.info('OSExitThread: Thread %08x exiting with code %d.', thr, exit_code)
        self._states.sched.delete_thread(thr)
        return 0

    @syscalldef(0x10008, 'void', ['short'])
    def OSSleep(self, millis: int) -> None:
        self._states.sched.request_sleep_from_syscall(millis)
