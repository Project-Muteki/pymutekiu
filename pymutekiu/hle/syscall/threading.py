import logging

from .common import syscalldef, SyscallModule
from ..errno import GuestOSError, ErrnoNamespace, ErrnoCauseUser

_logger = logging.getLogger('syscall.threading')


class Threading(SyscallModule):
    @syscalldef(0x10000, 'pointer', ['pointer', 'pointer', 'uint32', 'bool'])
    def on_os_create_thread(self, func: int, user_data: int, stack_size: int, defer_start: bool) -> int:
        try:
            thr = self._states.sched.new_thread(func, user_data, stack_size, defer_start)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0
        return thr

    @syscalldef(0x10001, 'int', ['pointer', 'int'])
    def on_os_terminate_thread(self, thr: int, exit_code: int) -> int:
        _logger.info('OSTerminateThread: Thread %08x exiting with code %d.', thr, exit_code)
        self._states.sched.delete_thread(thr)
        return 0

    @syscalldef(0x10002, 'bool', ['pointer', 'short'])
    def on_os_set_thread_priority(self, thr: int, new_slot: int) -> bool:
        try:
            self._states.sched.move_thread_to_slot(thr, new_slot)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return False
        return True

    @syscalldef(0x10003, 'short', ['pointer'])
    def on_os_get_thread_priority(self, thr: int) -> int:
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

    @syscalldef(0x10004, 'bool', ['pointer'])
    def on_os_suspend_thread(self, thr: int) -> bool:
        try:
            self._states.sched.request_suspend(thr)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return False
        return True

    @syscalldef(0x10005, 'bool', ['pointer'])
    def on_os_resume_thread(self, thr: int) -> bool:
        try:
            self._states.sched.request_resume(thr)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return False
        return True

    @syscalldef(0x10006, 'bool', ['pointer'])
    def on_os_wake_up_thread(self, thr: int) -> bool:
        try:
            self._states.sched.request_wakeup(thr)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return False
        return True

    @syscalldef(0x10007, 'int', ['int'])
    def on_os_exit_thread(self, exit_code: int) -> int:
        thr = self._states.sched.current_thread
        _logger.info('OSExitThread: Thread %08x exiting with code %d.', thr, exit_code)
        self._states.sched.delete_thread(thr)
        return 0

    @syscalldef(0x10008, 'void', ['short'])
    async def on_os_sleep(self, millis: int) -> None:
        await self._states.sched.sleep(millis)
