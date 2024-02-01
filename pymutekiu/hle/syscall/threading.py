from .common import syscalldef, SyscallModule
from ..errno import GuestOSError


class Threading(SyscallModule):
    @syscalldef(0x10000, 'pointer', ['pointer', 'pointer', 'uint32', 'bool'])
    def OSCreateThread(self, func: int, user_data: int, stack_size: int, defer_start: bool) -> int:
        try:
            thr = self._states.sched.new_thread(func, user_data, stack_size)
            self._states.sched.register(thr, unmask=not defer_start)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0
        return thr

    @syscalldef(0x10008, 'void', ['int16'])
    def OSSleep(self, millis: int):
        self._states.sched.request_sleep_from_syscall(millis)
