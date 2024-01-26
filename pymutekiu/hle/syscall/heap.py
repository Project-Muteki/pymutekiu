from . import syscalldef, SyscallSubHandler
from ..errno import GuestOSError


class Memory(SyscallSubHandler):
    @syscalldef(0x10037, 'pointer', ['uint'])
    def lmalloc(self, size: int) -> int:
        try:
            gptr = self.states.heap.malloc(size)
            return gptr
        except GuestOSError as err:
            self.states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x10038, 'pointer', ['uint', 'uint'])
    def lcalloc(self, nmemb: int, size: int) -> int:
        try:
            gptr = self.states.heap.calloc(nmemb, size)
            return gptr
        except GuestOSError as err:
            self.states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x10039, 'pointer', ['pointer', 'uint'])
    def lrealloc(self, ptr: int, size: int) -> int:
        try:
            gptr = self.states.heap.realloc(ptr, size)
            return gptr
        except GuestOSError as err:
            self.states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x1003a, 'void', ['pointer'])
    def _lfree(self, ptr: int) -> None:
        self.states.heap.free(ptr)

    @syscalldef(0x20063, 'uint', [])
    def GetFreeMemory(self) -> int:
        return self.states.heap.get_free_space()
