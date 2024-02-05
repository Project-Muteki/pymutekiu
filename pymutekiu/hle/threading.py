import enum
import functools
from typing import TYPE_CHECKING, Optional, Sequence

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

    _STRUCT = struct.Struct('<iIIiiIIhHhh4bI2I32s')

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
        Unmask a specific slot (clear the bit) in the table.
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
        Mask a specific slot (set the bit) in the table.
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

    def first_unmasked(self) -> int:
        """
        Query and return the first unmasked slot (offset of the first cleared bit).
        :return: First unmasked slot.
        """
        first_y = self._first_unmasked_table[self._y]
        first_x = self._first_unmasked_table[self._x[first_y]]
        return (first_y << self._xshift) | first_x


class YieldReason(enum.Enum):
    """
    Reason of thread yield.
    """
    TIMEOUT = enum.auto()
    "Scheduler timeout. A reschedule will happen automatically."
    REQUEST_SYSCALL = enum.auto()
    "Syscall request. The handler will then decide whether to continue execution or to reschedule."
    REQUEST_HLE_FUNC = enum.auto()
    "HLE function call. The handler will then decide whether to continue execution or to reschedule."


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
    _sched_tick_starts_at: int
    _reschedule: bool
    _current_slot: Optional[int]
    _slots: list[Optional[int]]
    _masks: MaskTable
    _desc_head: Optional[int]
    _desc_tail: Optional[int]
    _yield_reason: Optional[YieldReason]
    _yield_request_num: Optional[int]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self._uc = uc
        self._states = states

        self._stack_page_allocator = utils.MemPageTracker(self.STACK_LIMIT)

        self._sched_tick_starts_at = 0
        self._reschedule = True

        self._current_slot = None
        self._slots = [None] * self.THREAD_TABLE_SIZE
        self._masks = MaskTable()

        self._desc_head = None
        self._desc_tail = None

        self._yield_reason = None
        self._yield_request_num = None

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
                   slot: Optional[int] = None) -> int:
        """
        Create a new thread descriptor on the guest heap.
        :param func: Thread entrypoint function.
        :param user_data: User data passed to the thread entrypoint, or NULL if unset.
        :param stack_size: Stack size in bytes. Must be page-aligned.
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

        return thr_ptr

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
        Directly get the pointer saved in a slot. This is mostly for debugging and in most cases it's not needed.
        :param slot: Slot number.
        :return: Guest pointer to the thread descriptor, or None if the slot is not set.
        """
        return self._slots[slot]

    def set_slot(self, slot: int, thr: Optional[int]) -> None:
        """
        Directly set a slot. This is mostly for debugging and in most cases it's not needed.

        Unlike register(), this will not synchronize the slot number saved on the descriptor nor change the mask.
        :param slot: Slot number.
        :param thr: Guest pointer to a thread descriptor.
        """
        self._slots[slot] = thr

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
        desc = self.read_thread_descriptor(thr)
        if self._slots[desc.slot] is not None:
            raise RuntimeError('Slot already in use.')
        self._slots[desc.slot] = thr
        if unmask:
            self._masks.unmask(desc.slot)

    def unregister(self, slot: int):
        """
        Unregister a thread already registered with the scheduler by slot number.
        :param slot: Slot number
        """
        self._masks.mask(slot)
        self._slots[slot] = None

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
        :param slot: Switch to this context.
        :return: Whether a context switch was actually performed or not.
        """
        if slot is None:
            slot = self._masks.first_unmasked()

        if self._slots[slot] is None:
            raise ValueError(f'Slot {slot} is empty.')

        # If the current thread is the same as the target, skip.
        if self._current_slot == slot:
            return False

        if self._current_slot is not None:
            self.save_context()
        self.load_context(slot)

        return True

    def yield_from_svc(self):
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

        self._yield_reason = YieldReason.REQUEST_SYSCALL
        self._yield_request_num = syscall_no
        self._uc.emu_stop()

    def signal_reschedule(self):
        """
        Generate a new scheduler tick by resetting the scheduler tick timestamp.
        """
        self._sched_tick_starts_at = time.monotonic_ns()
        self._reschedule = True

    def request_sleep_from_syscall(self, jiffies: int):
        """
        Sets the sleep counter and reset the scheduler tick start timestamp. Returns immediately when requesting 0
        jiffy.

        This method should be called in a syscall handler.
        :param jiffies: Number of jiffies to sleep.
        """
        if jiffies == 0:
            return

        # Mask the current thread and update the sleep counter
        self._masks.mask(self._current_slot)
        desc = self.read_thread_descriptor(self.current_thread)
        desc.wait_reason |= ThreadWaitReason.SLEEP
        desc.sleep_counter = jiffies
        self.write_thread_descriptor(self.current_thread, desc)

        # Signal the scheduler to start a new scheduler tick.
        # Actual rescheduling will happen on the next scheduler tick since we process syscalls after the yield and
        # before the next tick.
        self.signal_reschedule()

    def _before_tick(self):
        """
        Housekeeping method that runs immediately when Scheduler.tick() was called.
        """
        # Do nothing when a scheduler tick is not yet expired.
        if not self._reschedule:
            return
        self._reschedule = False

        # TODO change this to do a linked list traversal
        for slot, thr in enumerate(self._slots):
            if thr is None:
                continue

            desc = self.read_thread_descriptor(thr)
            assert desc.slot == slot, 'Slot number inconsistent. Possible corruption.'

            # Update sleep counter
            if desc.wait_reason & ThreadWaitReason.SLEEP:
                desc.sleep_counter -= 1
                if desc.sleep_counter <= 0:
                    desc.sleep_counter = 0
                    desc.wait_reason &= ~ThreadWaitReason.SLEEP
                self.write_thread_descriptor(thr, desc)

            if desc.wait_reason == ThreadWaitReason.NONE:
                self._masks.unmask(slot)

    def tick(self) -> None:
        """
        Attempt to run the scheduler for a single jiffy. May return during an actual scheduler tick i.e. before the
        jiffy expires.

        This method should be periodically called in the main loop before calling the syscall handler.
        """
        # Run housekeeping
        self._before_tick()

        # Perform a context switch if needed.
        self.switch()

        # Determine remaining time
        remaining_time = self.JIFFY_TARGET_US - (time.monotonic_ns() - self._sched_tick_starts_at) // 1000

        if remaining_time > 0:
            # Run emulator for up to the determined time remaining
            self._yield_reason = None
            self._uc.emu_start(self._uc.reg_read(UC_ARM_REG_PC), 0, timeout=remaining_time)

        # Check reason of yield. If it's timeout, update tick start timestamp and run another
        if remaining_time <= 0 and self._uc.query(UC_QUERY_TIMEOUT) == 1:
            self._yield_reason = YieldReason.TIMEOUT
            self.signal_reschedule()
