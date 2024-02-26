from typing import TYPE_CHECKING, Optional, TypeVar, Any, cast
from collections.abc import Sequence, Awaitable, Generator, Coroutine

import enum
import functools
import logging
import struct
import time
import math

from dataclasses import dataclass, astuple

from unicorn import (
    Uc,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_QUERY_TIMEOUT,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
)

from .. import utils
from .errno import GuestOSError, ErrnoNamespace, ErrnoCauseUser

if TYPE_CHECKING:
    from unicorn.unicorn import UcContext
    from .states import OSStates

_logger = logging.getLogger('threading')


class ThreadWaitReason(enum.IntFlag):
    NONE = 0x0
    SEMAPHORE = 0x1
    EVENT = 0x2
    QUEUE = 0x4
    SUSPEND = 0x8
    CRITICAL_SECTION = 0x10
    SLEEP = 0x20
    ANY = SEMAPHORE | EVENT | QUEUE | SUSPEND | CRITICAL_SECTION | SLEEP


@dataclass
class ThreadDescriptor:
    """
    Thread descriptor reader.
    """

    magic: int = 0x100
    "Magic. Always 0x100."
    sp: int = 0
    "Last stack pointer that points to the CPU context."
    stack: int = 0
    "Pointer to allocated stack top."
    exit_code: int = 0
    "Exit code passed from OSExitThread()."
    kerrno: int = 0
    "Error code."
    unk_0x14: int = 0x80000000
    "Unknown. Initializes to 0x80000000."
    thread_func_ptr: int = 0
    "Thread function entrypoint."
    unk_0x1c: int = 0
    "Unknown."
    sleep_counter: int = 0
    "Jiffies left to sleep."
    wait_reason: int = 0
    "Current wait reason of the thread."
    slot: int = 0
    "Slot number."
    slot_low3b: int = 0
    "Lower 3 bit of slot number."
    slot_high3b: int = 0
    "Higher 3 bit of slot number."
    slot_low3b_bit: int = 0b000
    "Lower 3 bit bitmask of slot number."
    slot_high3b_bit: int = 0b000
    "Higher 3 bit bitmask of slot number."
    event: int = 0
    "Pointer to event descriptor that belongs to the event the thread is currently waiting for."
    prev: int = 0
    "Previous thread descriptor."
    next: int = 0
    "Next thread descriptor."
    unk_0x34: bytes = b'\x00' * 0x20
    "Unknown and seems to be uninitialized."

    _STRUCT = struct.Struct('<iIIiiIIhHhh2b2BI2I32s')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ThreadDescriptor':
        """
        Read thread descriptor from bytes.
        :param data: Raw thread descriptor data.
        :return: Thread descriptor object
        """
        return cls(*cls._STRUCT.unpack(data))

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(*astuple(self))

    @classmethod
    def sizeof(cls) -> int:
        return cls._STRUCT.size

    def set_slot(self, slot: int) -> None:
        self.slot = slot
        self.slot_low3b = slot & 0b111
        self.slot_high3b = (slot >> 3) & 0b111
        self.slot_low3b_bit = 1 << self.slot_low3b
        self.slot_high3b_bit = 1 << self.slot_high3b

    def populate_unk_0x1c(self):
        # TODO wth is this
        self.unk_0x1c = (64 - self.slot) // 16 + 1 if self.slot < 64 else (64 - self.slot + 15) // 16 + 1

    def validate(self):
        if self.magic != 0x100:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)


@dataclass
class CPUContext:
    """
    Besta RTOS CPU context reader/writer.
    """
    cpsr: int
    r0: int
    r1: int
    r2: int
    r3: int
    r4: int
    r5: int
    r6: int
    r7: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    lr: int
    pc: int

    _CONTEXT_SEQ = (
        UC_ARM_REG_CPSR,
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
        UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
        UC_ARM_REG_LR, UC_ARM_REG_PC,
    )
    _STRUCT = struct.Struct('<16I')

    @classmethod
    def sizeof(cls) -> int:
        return cls._STRUCT.size

    @classmethod
    def from_emulator_context(cls, uc: 'Uc | UcContext'):
        return cls(*map(uc.reg_read, cls._CONTEXT_SEQ))

    @classmethod
    def from_bytes(cls, b: bytes):
        return cls(*cls._STRUCT.unpack(b))

    @classmethod
    def for_new_thread(cls, func: int, user_data: int, on_exit: int):
        return cls(
            cpsr=0x13,
            r0=user_data, r1=0, r2=0, r3=0, r4=0, r5=0, r6=0,
            r7=0, r8=0, r9=0, r10=0, r11=0, r12=0,
            lr=on_exit, pc=func,
        )

    def to_emulator_context(self, uc: 'Uc | UcContext'):
        for reg, val in zip(self._CONTEXT_SEQ, astuple(self)):
            uc.reg_write(reg, val)

    def to_bytes(self):
        return self._STRUCT.pack(*astuple(self))


@functools.cache
def _bcs(n: int) -> int:
    """
    Return the index of the first bit 1 (counting from LSB) aka the binary carry sequence.
    https://oeis.org/A007814
    :param n: A number.
    :return: Index of the first bit 1 from LSB of n.
    """
    if n % 2 == 1 or n == 0:
        return 0
    return _bcs(n // 2) + 1


class MaskTable:
    """
    Parametric uC/OS-II mask table implementation.

    Note that while this supports x and y size > 8 therefore allowing more than 64 active threads, doing so will break
    the threading ABI.
    """
    _first_unmasked_table: Sequence[int]
    _xshift: int
    _xmask: int
    _y: int
    _x: bytearray

    def __init__(self, xsize: int = 8, ysize: int = 8):
        bcs_size = 2 ** max(xsize, ysize)
        self._first_unmasked_table = tuple(_bcs(n) for n in range(bcs_size))

        self._xshift = math.ceil(math.log2(xsize))
        self._xmask = (1 << self._xshift) - 1

        self._y = 0
        self._x = bytearray(xsize)

    def unmask(self, slot_or_x: int, y: Optional[int] = None) -> tuple[int, int]:
        """
        Unmask a specific slot (set the bit) in the table.
        :param slot_or_x: Slot number or the x (LSB) part of the slot number.
        :param y: Either None, or the y (MSB) part of the slot number.
        :return: The slot's (x, y) value as a tuple.
        """
        if y is None:
            y = slot_or_x >> self._xshift
            x = slot_or_x & self._xmask
        else:
            x = slot_or_x

        self._y |= 1 << y
        self._x[y] |= 1 << x

        return x, y

    def mask(self, slot_or_x: int, y: Optional[int] = None) -> tuple[int, int]:
        """
        Mask a specific slot (clear the bit) in the table.
        :param slot_or_x: Slot number or the x (LSB) part of the slot number.
        :param y: Either None, or the y (MSB) part of the slot number.
        :return: The slot's (x, y) value as a tuple.
        """
        if y is None:
            y = slot_or_x >> self._xshift
            x = slot_or_x & self._xmask
        else:
            x = slot_or_x

        self._x[y] &= ~(1 << x)
        if self._x[y] == 0:
            self._y &= ~(1 << y)

        return x, y

    def get(self, slot_or_x: int, y: Optional[int] = None) -> bool:
        """
        Get the current status of a slot.
        :param slot_or_x: Slot number or the x (LSB) part of the slot number.
        :param y: Either None, or the y (MSB) part of the slot number.
        :return: True if the slot is unmasked (bit set), False otherwise.
        """
        if y is None:
            y = slot_or_x >> self._xshift
            x = slot_or_x & self._xmask
        else:
            x = slot_or_x
        return bool((self._x[y] >> x) & 1)

    def first_unmasked(self) -> Optional[int]:
        """
        Query and return the first unmasked slot (offset of the first set bit).
        :return: First unmasked slot, or None if everything is masked.
        """
        if self._y == 0:
            return None

        first_y = self._first_unmasked_table[self._y]
        first_x = self._first_unmasked_table[self._x[first_y]]
        return (first_y << self._xshift) | first_x


class YieldReason(enum.Flag):
    """
    Reason of thread yield.
    """
    NONE = 0
    "Nothing."
    TIMEOUT = enum.auto()
    "Scheduler timeout. A reschedule will happen automatically."
    REQUEST_SYSCALL = enum.auto()
    "Syscall request. The handler will then decide whether to continue execution or to reschedule."
    REQUEST_HLE_FUNC = enum.auto()
    "HLE function call. The handler will then decide whether to continue execution or to reschedule."
    REQUEST_HANDLER_EVENT = enum.auto()
    "Yield or return from an async request handler."
    NO_THREAD = enum.auto()
    "No thread registered."


_ReturnT_co = TypeVar('_ReturnT_co', covariant=True)


class LiteFuture(Awaitable[_ReturnT_co]):
    """
    Future class for use with Scheduler. It loosely follows the API of asyncio.Future with some features such as
    callbacks missing.
    """
    _PENDING = 0
    _FINISHED = 1
    _CANCELLED = 2

    _val: Optional[_ReturnT_co]
    _exc: Optional[BaseException]
    _state: int
    _cancel_msg: Optional[str]

    def __init__(self):
        self._state = self._PENDING
        self._ret = None
        self._exc = None
        self._cancel_msg = None

    def cancel(self, msg: Optional[str] = None) -> bool:
        if self.done():
            return False
        self._cancel_msg = msg
        self._state = self._CANCELLED
        return True

    def cancelled(self) -> bool:
        return self._state == self._CANCELLED

    def done(self):
        return self._state != self._PENDING

    def result(self) -> _ReturnT_co:
        if self.cancelled():
            raise RuntimeError(self._cancel_msg)
        if self._exc is not None:
            raise self._exc
        return self._ret

    def set_result(self, val: _ReturnT_co):
        self._val = val

    def set_exception(self, exc: BaseException):
        self._exc = exc

    def __await__(self) -> Generator['LiteFuture', None, _ReturnT_co]:
        if not self.done():
            yield self
        # Check against unexpected await exits
        if not self.done():
            raise RuntimeError('Exiting await when result is not ready. Possible scheduler bug?')
        # Pass result/exception over to the coroutine
        return self.result()


@dataclass
class SchedulerCoroutineTask:
    cr: Coroutine[Any, Any, None]
    "Scheduler coroutine."
    aw: Optional[LiteFuture[Any]] = None
    "Scheduler awaitable."
    _exception: Optional[BaseException] = None
    _done: bool = False

    def tick(self) -> bool:
        if self.aw is None or self.aw.done():
            try:
                aw = self.cr.send(None)
                if not isinstance(aw, LiteFuture):
                    self.cr.throw(RuntimeError(f'Unsupported awaitable type {type(aw)} used in request handler.'))
                self.aw = cast(LiteFuture[Any], aw)
            except StopIteration:
                self._done = True
            except BaseException as err:
                self._exception = err
                self._done = True
        return self._done

    def done(self) -> bool:
        return self._done

    def result(self) -> None:
        if self._done and self._exception:
            raise self._exception


class Scheduler:
    """
    The thread scheduler and guest event handler class. It's responsible for scheduling threads on each scheduler tick
    and catching syscall/HLE function call requests from the emulator.

    At high level the scheduling part of this class behaves very similarly to the uC/OS-II scheduler since the Besta
    RTOS kernel is basically a modified uC/OS-II kernel with some differences in availability of synchronization
    primitives, ABI and API signatures.
    """
    JIFFY_TARGET_US = 1000

    STACK_BASE = 0xff000000
    STACK_LIMIT = 8*1024*1024
    STACK_GUARD_SIZE = 4096

    HIGH_PRIO_CUTOFF = 8
    LOW_PRIO_CUTOFF = 46
    THREAD_TABLE_SIZE = 64

    SLOT_HIGH_PRIO = range(0, HIGH_PRIO_CUTOFF)
    SLOT_NORMAL_PRIO = range(HIGH_PRIO_CUTOFF, LOW_PRIO_CUTOFF)
    SLOT_LOW_PRIO = range(LOW_PRIO_CUTOFF, THREAD_TABLE_SIZE)

    _uc: Uc
    _states: 'OSStates'
    _stack_page_allocator: utils.MemPageTracker
    _stack_page_map: dict[int, int]
    _sched_tick_starts_at: int
    _sched_tick_fired: bool
    _current_slot: Optional[int]
    _slots: list[Optional[int]]
    _masks: MaskTable
    _desc_head: Optional[int]
    _desc_tail: Optional[int]
    _yield_reason: YieldReason
    _yield_request_num: Optional[int]
    _pending_handlers: dict[int, SchedulerCoroutineTask]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self._uc = uc
        self._states = states

        self._stack_page_allocator = utils.MemPageTracker(self.STACK_LIMIT)
        self._stack_page_map = {}

        self._sched_tick_starts_at = 0
        self._sched_tick_fired = True

        self._current_slot = None
        self._slots = [None] * self.THREAD_TABLE_SIZE
        self._masks = MaskTable()

        self._desc_head = None
        self._desc_tail = None

        self._yield_reason = YieldReason.NONE
        self._yield_request_num = None

        self._pending_handlers = {}

    @property
    def current_slot(self) -> Optional[int]:
        """
        The slot number of the current active thread.
        :return: The slot number of the current active thread, or None if the scheduler hasn't got a thread to execute.
        """
        return self._current_slot

    @property
    def current_thread(self) -> Optional[int]:
        """
        The guest pointer of current active thread.
        :return: The guest pointer of current active thread, or None if the scheduler hasn't got a thread to execute.
        """
        return self._slots[self._current_slot] if self._current_slot is not None else None

    @property
    def yield_reason(self):
        return self._yield_reason

    @property
    def yield_request_num(self):
        return self._yield_request_num

    def find_empty_normal_slot(self) -> int:
        """
        Finds the next empty normal slot.
        :return: The next empty normal slot.
        """
        slot_found: Optional[int] = None
        for slot in self.SLOT_NORMAL_PRIO:
            if self._slots[slot] is None:
                slot_found = slot
                break
        if slot_found is None:
            raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseUser.THREADING_SLOT_FULL)
        return slot_found

    def new_thread(self,
                   func: int,
                   user_data: Optional[int] = None,
                   stack_size: int = 0x8000,
                   defer_start: bool = False,
                   slot: Optional[int] = None) -> int:
        """
        Create a new guest thread.
        :param func: Thread entrypoint function.
        :param user_data: User data passed to the thread entrypoint, or NULL if unset.
        :param stack_size: Stack size in bytes. Must be page-aligned.
        :param defer_start: Set to True to not start the thread immediately.
        :param slot: Specify an unused slot number. The next available slot will be selected if this is unset.
        :return:
        """
        # TODO more robust error handling (i.e. free already allocated resources before raising exceptions)
        if stack_size % 4096 != 0:
            _logger.warning('Stack size is not a multiple of minimum page size.')
            stack_size = utils.align(stack_size, 4096)

        # Find/check the slot.
        if slot is None:
            slot = self.find_empty_normal_slot()

        # Allocate thread stack on target memory
        # Add extra 1 page as guard page. This page will be mapped as protected.
        page_offset = self._stack_page_allocator.add(stack_size + self.STACK_GUARD_SIZE)
        stack_bottom = self.STACK_BASE - page_offset
        stack_top = stack_bottom - stack_size
        stack_guard_top = stack_top - self.STACK_GUARD_SIZE
        self._stack_page_map[stack_top] = page_offset
        _logger.debug('Mapping stack memory pages @ %#010x, size %#x', stack_top, stack_size)
        self._uc.mem_map(stack_top, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        _logger.debug('Mapping stack guard pages @ %#010x, size %#x', stack_guard_top, self.STACK_GUARD_SIZE)
        self._uc.mem_map(stack_guard_top, self.STACK_GUARD_SIZE, UC_PROT_NONE)

        # Save initial CPU context to stack
        context_offset = stack_bottom - CPUContext.sizeof()
        # TODO define a magic exit for thread that calls OSExitThread and use it here
        context = CPUContext.for_new_thread(func, user_data if user_data is not None else 0, 0)
        self._uc.mem_write(context_offset, context.to_bytes())

        # Allocate the thread descriptor on target heap.
        # TODO keep at least head and tail of all threads created
        thr_ptr = self._states.heap.malloc(ThreadDescriptor.sizeof())
        desc = ThreadDescriptor(
            thread_func_ptr=func,
            stack=stack_top,
            sp=context_offset,
        )
        desc.set_slot(slot)

        # Update the linked list
        if self._desc_tail is not None:
            desc_prev = self.read_thread_descriptor(self._desc_tail)
            desc_prev.next = thr_ptr
            desc.prev = self._desc_tail
            self.write_thread_descriptor(self._desc_tail, desc_prev)
        if self._desc_head is None:
            self._desc_head = thr_ptr
        self._desc_tail = thr_ptr

        self.write_thread_descriptor(thr_ptr, desc)

        self.set_slot(slot, thr_ptr, not defer_start)
        if not defer_start:
            self.switch()

        return thr_ptr

    def delete_thread(self, addr: int) -> None:
        """
        Stop and delete a guest thread by its descriptor.
        :param addr: Guest pointer to the thread descriptor.
        """
        if addr == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)
        desc = self.read_thread_descriptor(addr)
        desc.validate()

        # Splice the linked list
        if desc.prev != 0:
            desc_prev = self.read_thread_descriptor(desc.prev)
            desc_prev.next = desc.next
            self.write_thread_descriptor(desc.prev, desc_prev)
        if desc.next != 0:
            desc_next = self.read_thread_descriptor(desc.next)
            desc_next.prev = desc.prev
            self.write_thread_descriptor(desc.next, desc_next)

        # Free the stack allocation
        stack_top = desc.stack
        page_offset = self._stack_page_map[stack_top]
        stack_bottom = self.STACK_BASE - page_offset
        stack_guard_top = stack_top - self.STACK_GUARD_SIZE
        stack_size = stack_bottom - stack_top
        self._stack_page_allocator.remove(page_offset)
        self._uc.mem_unmap(stack_guard_top, self.STACK_GUARD_SIZE)
        self._uc.mem_unmap(stack_top, stack_size)
        del self._stack_page_map[stack_top]

        self.unregister(desc.slot)

        # Free the thread itself
        self._states.heap.free(addr)

    def read_thread_descriptor(self, addr: int) -> ThreadDescriptor:
        """
        Convenient method to read a thread descriptor.
        :param addr: Guest pointer to the thread descriptor.
        :return: The parsed thread descriptor.
        """
        return ThreadDescriptor.from_bytes(self._uc.mem_read(addr, ThreadDescriptor.sizeof()))

    def write_thread_descriptor(self, addr: int, desc: ThreadDescriptor) -> None:
        """
        Convenient method to write to a thread descriptor.
        :param addr: Guest pointer to the thread descriptor.
        :param desc: The descriptor object.
        """
        self._uc.mem_write(addr, desc.to_bytes())

    def get_slot(self, slot: int) -> Optional[int]:
        """
        Directly get the pointer saved in a slot. This is exposed mostly for debugging/tracing, and it's normally not
        needed to call this directly during normal emulator operation.

        TODO: Replace this with an actual tracing API that also collects other stats of threads
        :param slot: Slot number.
        :return: Guest pointer to the thread descriptor, or None if the slot is not set.
        """
        return self._slots[slot]

    def set_slot(self, slot: int, thr: int, unmask: bool = False):
        """
        Directly set a slot. This is exposed mostly for debugging, and it's normally not needed to call this directly
        during normal emulator operation.

        Unlike register(), this will not synchronize the slot number saved on the descriptor nor change the mask.
        :param slot: Slot number.
        :param thr: Guest pointer to a thread descriptor.
        :param unmask: Whether to also unmask the slot.
        """
        self._slots[slot] = thr
        if unmask:
            self._masks.unmask(slot)

    def move_thread_to_slot(self, thr: int, new_slot: int) -> None:
        """
        Move a thread from its current slot to another, effectively changing its priority.
        :param thr: Guest pointer to thread descriptor.
        :param new_slot: New slot.
        """
        if self._slots[new_slot] is not None:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_SLOT_IN_USE)

        desc = self.read_thread_descriptor(thr)
        desc.validate()
        if desc.slot == new_slot:
            return

        self.unregister(desc.slot)

        desc.set_slot(new_slot)

        self.write_thread_descriptor(thr, desc)
        self.set_slot(new_slot, thr, True)

    def read_thread_descriptor_by_slot(self, slot: int) -> Optional[ThreadDescriptor]:
        """
        Return parsed descriptor in a slot.
        :param slot: Slot number.
        :return: Parsed descriptor, or None if the slot is not set.
        """
        thr = self._slots[slot]
        return self.read_thread_descriptor(thr) if thr is not None else None

    def register(self, thr: int, unmask: bool = True):
        """
        Register a thread with the scheduler and unmask it.
        :param thr: Guest pointer to the thread descriptor.
        :param unmask: Also unmask the registered thread and make it executable on next scheduler tick.
        """
        if thr == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)
        desc = self.read_thread_descriptor(thr)
        desc.validate()
        if self._slots[desc.slot] is not None:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_SLOT_IN_USE)
        self.set_slot(desc.slot, thr, unmask)

    def unregister(self, slot: int):
        """
        Unregister a thread already registered with the scheduler by slot number.
        :param slot: Slot number
        """
        self._masks.mask(slot)
        self._slots[slot] = None
        if slot == self._current_slot:
            self.switch()

    def set_errno(self, errno: int):
        """
        Set errno on current thread.
        :param errno: Error code.
        """
        thr = self.current_thread
        desc = self.read_thread_descriptor(thr)
        desc.kerrno = errno
        self.write_thread_descriptor(thr, desc)

    def get_errno(self) -> int:
        """
        Get errno from current thread.
        :return: Error code
        """
        desc = self.read_thread_descriptor(self.current_thread)
        return desc.kerrno

    def save_context(self, slot: Optional[int] = None) -> None:
        """
        Switch out from a thread by saving current context to it.
        :param slot: Force the slot number. Uses the current running slot when left unset.
        """
        thr = self.current_thread if slot is None else self._slots[slot]

        # Read the current thread descriptor
        desc_from = self.read_thread_descriptor(thr)

        # Save the context to the stack
        ctx = CPUContext.from_emulator_context(self._uc)
        sp = self._uc.reg_read(UC_ARM_REG_SP) - CPUContext.sizeof()
        self._uc.mem_write(sp, ctx.to_bytes())
        desc_from.sp = sp

        # Commit the descriptor change
        self.write_thread_descriptor(thr, desc_from)

    def load_context(self, slot: int) -> None:
        """
        Restore context from a thread descriptor registered to a specific slot.
        :param slot: Slot number.
        """
        # Read the target thread descriptor
        desc_to = self.read_thread_descriptor(self._slots[slot])
        assert desc_to.slot == slot

        # Restore saved context
        ctx = CPUContext.from_bytes(self._uc.mem_read(desc_to.sp, CPUContext.sizeof()))
        ctx.to_emulator_context(self._uc)
        # Restore SP
        sp = desc_to.sp + CPUContext.sizeof()
        self._uc.reg_write(UC_ARM_REG_SP, sp)

        # Context switch to the target thread
        self._current_slot = slot

    def switch(self, slot: Optional[int] = None) -> bool:
        """
        Perform a context switch when needed.
        :param slot: Force switch to this context.
        :return: Whether a context switch was actually performed or not.
        """
        if slot is None:
            slot = self._masks.first_unmasked()

        # If there's no next slot to run, set the current slot to None and report changes accordingly.
        if slot is None:
            if self._current_slot is not None:
                self._current_slot = None
                return True
            return False

        if self._slots[slot] is None:
            raise ValueError(f'Slot {slot} is empty.')

        # Resolve the request handler future linked to this slot
        # The actual callback will not be performed here, instead it will be done in tick() before Unicorn resumes to
        # keep the behavior consistent with the rest of the scheduler.
        if slot in self._pending_handlers:
            fut = self._pending_handlers[slot].aw
            if fut is not None and not fut.done():
                fut.set_result(None)

        # If the current thread is the same as the target, skip.
        if self._current_slot == slot:
            return False
        # Otherwise, if we are switching slots, save the context first if current slot is populated.
        if self._current_slot is not None:
            self.save_context()
        # Actually switch over.
        self.load_context(slot)
        self._current_slot = slot

        return True

    def yield_from_svc(self) -> None:
        """
        Trigger a yield due to incoming SVC call.
        """
        svc_offset = self._uc.reg_read(UC_ARM_REG_PC) - 4
        syscall_no = int.from_bytes(self._uc.mem_read(svc_offset, 4), 'little') & 0xffffff

        # Recover from syscall state to prepare for returning
        sp = self._uc.reg_read(UC_ARM_REG_SP)
        lr = int.from_bytes(self._uc.mem_read(sp, 4), 'little')
        r0 = int.from_bytes(self._uc.mem_read(sp + 4, 4), 'little')
        self._uc.reg_write(UC_ARM_REG_SP, sp + 8)
        self._uc.reg_write(UC_ARM_REG_LR, lr)
        self._uc.reg_write(UC_ARM_REG_R0, r0)

        _logger.debug('syscall triggered from %#010x', lr)

        self._yield_reason = YieldReason.REQUEST_SYSCALL
        self._yield_request_num = syscall_no
        self._uc.emu_stop()

    def yield_from_hle_func(self, addr: int) -> None:
        self._yield_reason = YieldReason.REQUEST_HLE_FUNC
        self._yield_request_num = addr
        self._uc.emu_stop()

    def request_sleep(self, jiffies: int) -> None:
        """
        Sets the sleep counter on current thread and reschedule. Returns immediately when requesting 0 jiffy.

        This method should be called from a guest request handler.
        :param jiffies: Number of jiffies to sleep.
        """
        if jiffies == 0:
            return

        if self._current_slot is None:
            raise RuntimeError('BUG: Attempt to request sleep when no thread is running. '
                               'Possible state inconsistency.')

        # Mask the current thread and update the sleep counter
        self._masks.mask(self._current_slot)
        desc = self.read_thread_descriptor(self.current_thread)
        desc.wait_reason |= ThreadWaitReason.SLEEP
        desc.sleep_counter = jiffies
        self.write_thread_descriptor(self.current_thread, desc)

        self.switch()

    def sleep(self, jiffy: int) -> LiteFuture[None]:
        """
        Block an async request handler for the amount of jiffy specified.

        This method should be called from a guest request handler.
        :param jiffy: Number of jiffies to sleep.
        :return: A `LiteFuture` instance that can be used with `await` in request handler coroutines
        """
        fut = LiteFuture()

        # If requesting 0 jiffy, resolve and immediately return the future with no delay.
        if jiffy == 0:
            fut.set_result(None)
            return fut

        if self._current_slot in self._pending_handlers:
            _logger.warning(
                'Some request handler already awaiting on slot %d. Rejecting before starting a new one...',
                self._current_slot
            )
            self._pending_handlers[self._current_slot].aw.set_exception(RuntimeError('Dual await cancelled.'))

        # Actually request for sleep
        self.request_sleep(jiffy)

        return fut

    def request_wakeup(self, thr: int):
        """
        Request to wake up a thread (canceling sleep).

        This method should be called from a guest request handler.
        :param thr: Guest pointer to a thread descriptor.
        """
        if thr == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)

        desc = self.read_thread_descriptor(thr)
        desc.validate()

        if desc.sleep_counter == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_THREAD_NOT_SLEEPING)

        desc.sleep_counter = 0
        desc.wait_reason &= ~ThreadWaitReason.SLEEP
        self.write_thread_descriptor(thr, desc)

        if not (desc.wait_reason & ThreadWaitReason.SUSPEND):
            self._masks.unmask(desc.slot)
            self.switch()

    def request_suspend(self, thr: int) -> None:
        """
        Request to suspend a running thread.

        This method should be called from a guest request handler.
        :param thr: Guest pointer to a thread descriptor.
        """
        if thr == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)

        desc = self.read_thread_descriptor(thr)
        desc.validate()
        desc.wait_reason |= ThreadWaitReason.SUSPEND
        self._masks.mask(desc.slot)
        self.write_thread_descriptor(thr, desc)

        if self._current_slot == desc.slot:
            self.switch()

    def request_resume(self, thr: int) -> None:
        """
        Request to resume a suspended thread.

        This method should be called from a guest request handler.
        :param thr: Guest pointer to a thread descriptor.
        """
        if thr == 0:
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_INVALID_DESCRIPTOR)

        desc = self.read_thread_descriptor(thr)
        desc.validate()

        if not (desc.wait_reason & ThreadWaitReason.SUSPEND):
            raise GuestOSError(ErrnoNamespace.USER, ErrnoCauseUser.THREADING_THREAD_NOT_SUSPENDED)
        desc.wait_reason &= ~ThreadWaitReason.SUSPEND
        self.write_thread_descriptor(thr, desc)

        # Reschedule if needed
        # In uC/OS-II this part will simply be
        # if not (desc.wait_reason & ThreadWaitReason.ANY) and desc.sleep_counter == 0:
        #     self._masks.unmask(desc.slot)
        #     self.switch()
        # However Besta RTOS seems to check everything other than SLEEP and if they are all unset, do some random
        # shenanigans to unk_0x1c and clears the SLEEP flag without clearing the actual counter. Strange...

        # if not (desc.wait_reason & (~ThreadWaitReason.SLEEP)):
        #     self._masks.unmask(desc.slot)
        #     desc.populate_unk_0x1c()
        #     desc.wait_reason &= ~ThreadWaitReason.SLEEP
        #     self.write_thread_descriptor(thr, desc)
        #     self.switch()

        # TODO something doesn't add up. Use uC/OS-II behavior here for now.
        if not (desc.wait_reason & ThreadWaitReason.ANY) and desc.sleep_counter == 0:
            self._masks.unmask(desc.slot)
            #desc.populate_unk_0x1c()
            self.write_thread_descriptor(thr, desc)
            self.switch()

    def run_coroutine(self, cr: Coroutine[Any, Any, None]) -> SchedulerCoroutineTask:
        """
        Inject a coroutine into the scheduler loop.

        This will immediately run the coroutine synchronously until the first block. Then the rest of the coroutine
        will be finished over time before the linked guest thread gets executed by the scheduler.
        :param cr: A scheduler coroutine. Must return None.
        :return: The task object corresponding to the coroutine.
        """
        if self._current_slot is None:
            raise RuntimeError('No thread currently running.')
        task = SchedulerCoroutineTask(cr)
        if task.tick():
            return task
        self._pending_handlers[self._current_slot] = task

    def _sched_tick_intr(self):
        """
        Housekeeping routine that only runs when a new scheduler tick is being generated.

        This simulates the code being executed on real Besta RTOS when the ticker interrupt fires.
        """
        # Do nothing when a scheduler tick is not yet expired.
        if not self._sched_tick_fired:
            return
        self._sched_tick_fired = False

        # TODO change this to do a linked list traversal
        for slot, thr in enumerate(self._slots):
            if thr is None:
                continue

            desc = self.read_thread_descriptor(thr)
            assert desc.slot == slot, 'Slot number inconsistent. Possible corruption.'
            commit_descriptor = False

            # Update sleep counter
            if desc.wait_reason & ThreadWaitReason.SLEEP:
                desc.sleep_counter -= 1
                if desc.sleep_counter <= 0:
                    desc.sleep_counter = 0
                    desc.wait_reason &= ~ThreadWaitReason.SLEEP
                commit_descriptor = True

            if desc.wait_reason == ThreadWaitReason.NONE:
                self._masks.unmask(slot)
                #desc.populate_unk_0x1c()
                commit_descriptor = True

            if commit_descriptor:
                self.write_thread_descriptor(thr, desc)

        # Perform a context switch if needed.
        self.switch()

    def tick(self) -> None:
        """
        Attempt to run the scheduler until a jiffy has passed or a request has been raised from the guest.

        Not to be confused with a scheduler tick i.e. the periodical timer interrupt seen on real devices that fires
        every jiffy, triggers context switching, thus enables preemptive scheduling. In fact, this method may
        return during an actual scheduler tick for other reasons, namely syscall and HLE callback requests.

        This method should be periodically called in the main loop **before** the top level syscall/HLE callback
        handler.
        """
        if self._current_slot is None and not any(self._pending_handlers):
            self._yield_reason = YieldReason.NO_THREAD
            return

        self._yield_reason = YieldReason.NONE

        # Run housekeeping
        self._sched_tick_intr()

        # _current_slot might change during syscall (specifically after unregister() was called) so cache this result
        # for later.
        idling = self._current_slot is None

        # Determine remaining time
        remaining_time = self.JIFFY_TARGET_US - (time.monotonic_ns() - self._sched_tick_starts_at) // 1000

        if remaining_time > 0:
            if idling:
                # No tasks to run. Idling until timeout.
                time.sleep(remaining_time / 1_000_000)
            elif self._current_slot in self._pending_handlers:
                # Attempt to run a previous pending request handler
                req_done = self._pending_handlers[self._current_slot].tick()
                if req_done:
                    del self._pending_handlers[self._current_slot]
                self._yield_reason = YieldReason.REQUEST_HANDLER_EVENT
            else:
                # Run emulator for up to the determined time remaining.
                self._uc.emu_start(self._uc.reg_read(UC_ARM_REG_PC), 0x100000000, timeout=remaining_time)

        # Check reason of yield. If it's timeout (idling, syscall taking too long or emulator times out), start a new
        # scheduler tick
        # Note that Unicorn sometimes sets UC_QUERY_TIMEOUT when it's borderline timing out, so the timeout here
        # needs to coexist with e.g. syscall.
        if idling or remaining_time <= 0 or self._uc.query(UC_QUERY_TIMEOUT) == 1:
            self._yield_reason |= YieldReason.TIMEOUT
            self._sched_tick_fired = True
            self._sched_tick_starts_at = time.monotonic_ns()
