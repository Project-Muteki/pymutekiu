import ctypes
from typing import (
    Optional,
    Any,
)

import pathlib
import dataclasses
import logging

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_PROT_NONE,
    UC_PROT_ALL,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
)

from unicorn.arm_const import (
    UC_ARM_REG_PC,
    UC_ARM_REG_LR,
    UC_ARM_REG_SP,
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
    UC_CPU_ARM_926,
)
from pefile import PE

from . import utils
from .hle.states import OSStates
from .hle.syscall import SyscallHandler


_logger = logging.getLogger('emulator')

@dataclasses.dataclass
class LoadedSection:
    '''
    Represent a section of a loaded module within the emulated memory space.
    '''
    name: str
    addr: int
    size: int
    perm: int


@dataclasses.dataclass
class LoadedModule:
    '''
    Represent a loaded module within the emulated memory space.
    '''
    name: str
    addr: int
    size: int
    sections: list[LoadedSection]


class Process:
    _uc: Uc
    _states: OSStates
    _main_stack_size: int
    _heap_size: int

    STACK_BASE = 0xff000000
    MAGIC_EXIT = 0xfffffffc
    MAGIC_EXIT_THREAD = 0xfffffff8

    def __init__(self, main_stack_size=0x8000, heap_size=0x2000000):
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self._states = OSStates(self._uc)

        if main_stack_size % 4096 != 0:
            _logger.warning('Main stack size is not a multiple of minimum page size.')
            main_stack_size = utils.align(main_stack_size, 4096)
        if heap_size % 4096 != 0:
            _logger.warning('Heap size is not a multiple of minimum page size.')
            heap_size = utils.align(heap_size, 4096)
        self._main_stack_size = main_stack_size
        self._heap_size = heap_size

        self._syscall_handler = SyscallHandler(self._uc, self._states)

    def _trace_code(self, _uc: Uc, addr: int, size: int, _user_data: Any):
        _logger.debug('insn @ %#010x width %#x', addr, size)

    def _panic(self, *arg):
        _logger.error('PC: %#010x', self._uc.reg_read(UC_ARM_REG_PC))
        _logger.error('R0: %#010x, R1: %#010x, R2: %#010x, R3: %#010x',
                      self._uc.reg_read(UC_ARM_REG_R0),
                      self._uc.reg_read(UC_ARM_REG_R1),
                      self._uc.reg_read(UC_ARM_REG_R2),
                      self._uc.reg_read(UC_ARM_REG_R3))
        _logger.error('R4: %#010x, R5: %#010x, R6: %#010x, R7: %#010x',
                      self._uc.reg_read(UC_ARM_REG_R4),
                      self._uc.reg_read(UC_ARM_REG_R5),
                      self._uc.reg_read(UC_ARM_REG_R6),
                      self._uc.reg_read(UC_ARM_REG_R7))
        _logger.error('R8: %#010x, R9: %#010x, R10: %#010x, R11: %#010x',
                      self._uc.reg_read(UC_ARM_REG_R8),
                      self._uc.reg_read(UC_ARM_REG_R9),
                      self._uc.reg_read(UC_ARM_REG_R10),
                      self._uc.reg_read(UC_ARM_REG_R11))
        _logger.error('R12: %#010x, SP: %#010x, LR: %#010x',
                      self._uc.reg_read(UC_ARM_REG_R12),
                      self._uc.reg_read(UC_ARM_REG_SP),
                      self._uc.reg_read(UC_ARM_REG_LR))

        _logger.exception('PANIC: Emulator crashed')
        self._uc.emu_stop()

    def _on_intr(self, _uc: Uc, vec: int, _user_data: Any):
        # TODO generate a yield event
        if vec == 2: # SVC
            #self._states.sched.yield_from_svc()
            self._uc.emu_stop()

    def _emulator_loop(self):
        ...

    def load(self, image_file: str | pathlib.Path) -> None:
        self._states.loader.load(image_file)

    def run(self):
        # TODO set up stack and heap with threading and heap plugins
        self._uc.mem_map(0xff000000 - self._main_stack_size, self._main_stack_size, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.mem_map(self._states.loader.main_module.mem_range[1], self._heap_size, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.reg_write(UC_ARM_REG_LR, self.MAGIC_EXIT)
        self._uc.reg_write(UC_ARM_REG_SP, self.STACK_BASE)

        # TODO setup exception handler
        #self._uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._panic)
        #self._uc.hook_add(UC_HOOK_MEM_FETCH_PROT, self._panic)
        #self._uc.hook_add(UC_HOOK_CODE, self._trace_code)
        #self._uc.hook_add(UC_HOOK_INTR, self._on_intr)

        for region_start, region_end, perm in self._uc.mem_regions():
            _logger.debug('%#010x-%#010x %s', region_start, region_end, utils.uc_perm_to_str(perm))

        self._uc.emu_start(self._states.loader.entry_point, self.MAGIC_EXIT)
