from . import syscalldef, SyscallSubHandler
from ..errno import GuestOSError


class Threading(SyscallSubHandler):
    @syscalldef(0x10000, 'pointer', ['pointer', 'pointer', 'uint32', 'bool'])
    def OSCreateThread(self, func: int, user_data: int, stack_size: int, defer_start: bool) -> int:
        try:
            thr = self.states.sched.new_thread(func, user_data, stack_size)
            if not defer_start:
                self.states.sched.schedule(thr)
        except GuestOSError as err:
            self.states.sched.set_errno(err.errno)
            return 0
        return thr
