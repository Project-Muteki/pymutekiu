from typing import TYPE_CHECKING, Optional, cast

import logging
import struct
import time
import heapq
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


class Scheduler:
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
    _jiffy_starts_at: int
    _next_slot: int
    _slots: list[Optional[int]]
    _queue: list[int]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._stack_page_allocator = utils.MemPageTracker(self.STACK_LIMIT)
        self._jiffy_starts_at = 0
        self._slots = [None] * self.THREAD_TABLE_SIZE
        self._queue = []

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

    def yield_from_sleep(self, jiffies: int):
        """
        Sets the sleep counter and request a yield from current thread immediately.
        Returns immediately when requesting 0 jiffy.
        :param jiffies: Number of jiffies to sleep.
        """
        #TODO
        #desc = ThreadDescriptor.from_bytes(self._uc.mem_read(thr, ThreadDescriptor.sizeof()))
        ...

    def set_errno(self, errno: int):
        """
        Set errno on current thread.
        :param errno: Error code.
        """
        # TODO
        ...

    def get_errno(self) -> int:
        # TODO
        ...

    def find_empty_normal_slot(self) -> int:
        slot_found: Optional[int] = None
        for slot in self.SLOT_NORMAL_PRIO:
            if self._slots[slot] is None:
                slot_found = slot
                break
        if slot_found is None:
            raise RuntimeError('No empty slot available.')
        return slot_found

    def schedule(self, thr: int):
        desc = ThreadDescriptor.from_bytes(self._uc.mem_read(thr, ThreadDescriptor.sizeof()))
        if self._slots[desc.slot] is not None:
            raise RuntimeError('Slot already in use.')
        self._slots[desc.slot] = thr

    def unschedule(self, slot: int):
        self._slots[slot] = None

    def yield_from_svc(self):
        """
        Trigger a yield due to incoming SVC call.
        """
        # TODO
        self._uc.emu_stop()

    def next_thread(self):
        """
        Switch to next thread ready to run.
        """
        # TODO
        ...

    def tick(self) -> None:
        """
        Attempt to run the scheduler for a single jiffy. May return before the jiffy expires.
        """
        # TODO
        # Determine timeout
        timeout = (time.monotonic_ns() - self._jiffy_starts_at) // 1000
        if timeout > 0:
            self._uc.emu_start(..., 0, timeout=1000)
        # Check reason of yield. If it's timeout, update jiffy time
        if timeout <= 0 or self._uc.query(UC_QUERY_TIMEOUT) == 1:
            self._jiffy_starts_at = time.monotonic_ns()
