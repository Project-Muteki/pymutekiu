from .common import syscalldef, SyscallModule
from ..errno import GuestOSError


class Memory(SyscallModule):
    @syscalldef(0x10037, 'pointer', ['uint'])
    def on_lmalloc(self, size: int) -> int:
        try:
            gptr = self._states.heap.malloc(size)
            return gptr
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x10038, 'pointer', ['uint', 'uint'])
    def on_lcalloc(self, nmemb: int, size: int) -> int:
        try:
            gptr = self._states.heap.calloc(nmemb, size)
            return gptr
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x10039, 'pointer', ['pointer', 'uint'])
    def on_lrealloc(self, ptr: int, size: int) -> int:
        try:
            gptr = self._states.heap.realloc(ptr, size)
            return gptr
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0

    @syscalldef(0x1003a, 'void', ['pointer'])
    def on__lfree(self, ptr: int) -> None:
        self._states.heap.free(ptr)

    @syscalldef(0x20063, 'uint', [])
    def on_get_free_memory(self) -> int:
        return self._states.heap.get_free_space()
