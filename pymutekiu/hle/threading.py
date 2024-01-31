import enum
import functools
from typing import TYPE_CHECKING, Optional, cast

import logging
import struct
import time
import math

from dataclasses import dataclass, astuple, Field

from unicorn import (
    Uc,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_QUERY_TIMEOUT,
)
from unicorn.arm_const import (
    UC_ARM_REG_APSR,
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
    slot_low3b_bit: int = 0b111
    "Lower 3 bit bitmask of slot number."
    slot_high3b_bit: int = 0b111
    "Higher 3 bit bitmask of slot number."
    event: int = 0
    "Pointer to event descriptor that belongs to the event the thread is currently waiting for."
    prev: int = 0
    "Previous thread descriptor."
    next: int = 0
    "Next thread descriptor."
    unk_0x34: bytes = b'\x00' * 0x20
    "Unknown and seems to be uninitialized."

    _STRUCT = struct.Struct('<iIIiiIIhHhh4bI2I20s')

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
    apsr: int
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
        UC_ARM_REG_APSR,
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
            apsr=0x13,
            r0=user_data, r1=0, r2=0, r3=0, r4=0, r5=0, r6=0,
            r7=0, r8=0, r9=0, r10=0, r11=0, r12=0,
            lr=on_exit, pc=func,
        )

    def to_emulator_context(self, uc: 'Uc | UcContext'):
        for reg, val in zip(self._CONTEXT_SEQ, astuple(self)):
            uc.reg_write(reg, val)

    def to_bytes(self):
        return self._STRUCT.pack(*astuple(self))


@functools.lru_cache()
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
    Parametric uC-OS2 mask table implementation.

    Note that while this supports x and y size > 8 therefore allowing more than 64 active threads, doing so will break
    the threading ABI.
    """

    def __init__(self, xsize: int = 8, ysize: int = 8):
        bcs_size = 2 ** max(xsize, ysize)
        self._first_unmasked_table = tuple(_bcs(n) for n in bcs_size)

        self._xshift = math.ceil(math.log2(xsize))
        self._yshift = math.ceil(math.log2(ysize))
        self._xmask = (1 << self._xshift) - 1
        self._ymask = (1 << self._yshift) - 1

        self._y = 0
        self._x = bytearray(xsize)

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

        self._y |= 1 << y
        self._x[y] |= 1 << x

        return x, y

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

        self._x[y] &= ~(1 << x)
        if self._x[y] == 0:
            self._y &= ~(1 << y)

        return x, y

    def first_unmasked(self) -> int:
        """
        Query and return the first unmasked slot (offset of the first cleared bit).
        :return: First unmasked slot.
        """
        first_y = self._first_unmasked_table[self._y]
        first_x = self._first_unmasked_table[self._x[first_y]]
        return (first_y << self._xshift) | first_x


class YieldReason(enum.Enum):
    TIMEOUT = enum.auto()
    SYSCALL = enum.auto()
    WAIT = enum.auto()


class Scheduler:
    """
    The thread scheduler and handler class.

    This is very similar to what uC/OS-II scheduler would do since Besta RTOS uses a modified uC/OS-II kernel.
    """
    JIFFY_TARGET_US = 1000

    STACK_BASE = 0xff000000
    STACK_LIMIT = 8*1024*1024
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
    _is_new_sched_tick: bool
    _current_slot: Optional[int]
    _slots: list[Optional[int]]
    _masks: MaskTable
    _yield_reason: Optional[YieldReason]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self._uc = uc
        self._states = states

        self._stack_page_allocator = utils.MemPageTracker(self.STACK_LIMIT)

        self._sched_tick_starts_at = 0
        self._is_new_sched_tick = True

        self._current_slot = None
        self._slots = [None] * self.THREAD_TABLE_SIZE
        self._masks = MaskTable()

        self._yield_reason = None

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
            raise RuntimeError('No empty slot available.')
        return slot_found

    def new_thread(self,
                   func: int,
                   user_data: Optional[int] = None,
                   stack_size: int = 0x8000,
                   slot: Optional[int] = None):
        if stack_size % 4096 != 0:
            _logger.warning('Stack size is not a multiple of minimum page size.')
            stack_size = utils.align(stack_size, 4096)

        # Find/check the slot.
        if slot is None:
            slot = self.find_empty_normal_slot()

        # Allocate thread stack on target memory
        # Add extra 1 page as guard page. This page will be unmapped and will only be seen by the allocator.
        page_offset = self._stack_page_allocator.add(stack_size + 4096)
        stack_bottom = self.STACK_BASE - page_offset
        stack_top = stack_bottom - stack_size
        _logger.debug('Mapping stack memory pages @ %#010x, size %#x', stack_top, stack_size)
        self._uc.mem_map(stack_top, stack_size, UC_PROT_READ | UC_PROT_WRITE)

        # Save initial CPU context to stack
        context_offset = stack_bottom - CPUContext.sizeof()
        # TODO define a magic exit for thread that calls OSExitThread and use it here
        context = CPUContext.for_new_thread(func, user_data, 0)
        self._uc.mem_write(context_offset, context.to_bytes())

        # Allocate the thread descriptor on target heap.
        thr_ptr = self._states.heap.malloc(ThreadDescriptor.sizeof())
        desc = ThreadDescriptor(
            thread_func_ptr=func,
            stack=stack_top,
            sp=stack_bottom,
            #prev=..., next=...,
        )
        desc.set_slot(slot)
        self._uc.mem_write(thr_ptr, desc.to_bytes())

        # TODO keep at least head and tail of all threads created

    def read_thread_descriptor(self, addr: int) -> ThreadDescriptor:
        return ThreadDescriptor.from_bytes(self._uc.mem_read(addr, ThreadDescriptor.sizeof()))

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
        desc = self.read_thread_descriptor(self._slots[self._current_slot])
        desc.kerrno = errno

    def get_errno(self) -> int:
        """
        Get errno from current thread.
        :return: Error code
        """
        desc = self.read_thread_descriptor(self._slots[self._current_slot])
        return desc.kerrno

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
            # Save context to current thread
            desc_from = self.read_thread_descriptor(self._slots[self._current_slot])
            ctx = CPUContext.from_emulator_context(self._uc)
            sp = self._uc.reg_read(UC_ARM_REG_SP) - CPUContext.sizeof()
            self._uc.mem_write(sp, ctx.to_bytes())
            desc_from.sp = sp

        # Context switch to the target thread
        desc_to = self.read_thread_descriptor(self._slots[slot])
        ctx = CPUContext.from_bytes(self._uc.mem_read(desc_to.sp, CPUContext.sizeof()))
        ctx.to_emulator_context(self._uc)

        return True

    def yield_from_svc(self):
        """
        Trigger a yield due to incoming SVC call.
        """
        self._yield_reason = YieldReason.SYSCALL
        self._uc.emu_stop()

    def new_scheduler_tick(self):
        """
        Generate a new scheduler tick by resetting the scheduler tick timestamp.
        """
        self._sched_tick_starts_at = time.monotonic_ns()
        self._is_new_sched_tick = True

    def request_sleep(self, jiffies: int):
        """
        Sets the sleep counter and reset the scheduler tick start timestamp.
        Returns immediately when requesting 0 jiffy.
        :param jiffies: Number of jiffies to sleep.
        """
        if jiffies == 0:
            return

        # Mask the current thread and update the sleep counter
        self._masks.mask(self._current_slot)
        desc = self.read_thread_descriptor(self._slots[self._current_slot])
        desc.sleep_counter = jiffies
        self.new_scheduler_tick()

        self._yield_reason = YieldReason.WAIT

        # Rescheduling will happen on the next scheduler tick since we process syscalls after the yield and before the
        # next tick.

    def _before_tick(self):
        """
        Housekeeping method that runs immediately when Scheduler.tick() was called.
        """
        # Do nothing when a scheduler tick is not yet expired.
        if self._is_new_sched_tick:
            return
        self._is_new_sched_tick = False

        # TODO change this to do a linked list traversal
        for slot, thr in enumerate(self._slots):
            if thr is None:
                continue

            desc = self.read_thread_descriptor(thr)
            assert desc.slot == slot, 'Slot number inconsistent. Possible corruption.'

            if desc.sleep_counter > 0:
                desc.sleep_counter -= 1
            # TODO do we need to check further than just wait reason for some threads that are waiting?
            if desc.sleep_counter == 0 and desc.wait_reason == 0:
                self._masks.unmask(slot)

    def tick(self) -> None:
        """
        Attempt to run the scheduler for a single jiffy. May return during an actual scheduler tick i.e. before the
        jiffy expires.

        This method should be called in the main loop before the syscall handler.
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
            self.new_scheduler_tick()
