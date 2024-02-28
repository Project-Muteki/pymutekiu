from typing import (
    Optional,
    Any,
    TYPE_CHECKING,
)

import pathlib
import logging

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_HOOK_INTR,
    UC_HOOK_CODE,
    UC_PROT_EXEC,
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

from .utils import align, uc_perm_to_str
from .hle.states import OSStates
from .hle.threading import YieldReason
from .hle.syscall import SyscallHandler
from .hle.function import HLEFunctionHandler
from .hle.function.magic import Magic as MagicFunctionHandler

if TYPE_CHECKING:
    from argparse import Namespace


_logger = logging.getLogger('emulator')


class Process:
    _uc: Uc
    _states: OSStates

    # TODO can we somehow provide these through the dynamic linking interface on the module?
    MAGIC_BASE = 0x100000000 - 0x1000
    MAGIC_THREAD_EXIT = MAGIC_BASE

    def __init__(self,
                 main_applet_path: str | pathlib.Path,
                 config: 'Namespace'):
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self._states = OSStates(self._uc, main_applet_path, config)

        self._syscall_handler = SyscallHandler(self._uc, self._states)
        self._hle_func_handler = HLEFunctionHandler(self._uc, self._states)

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

    def _on_intr(self, _uc: Uc, vec: int, _user_data: Any) -> None:
        if vec == 2:  # SVC
            self._states.sched.yield_from_svc()
        else:
            _logger.error('Unhandled CPU exception type %d', vec)

    def _on_code_magic_func(self, _uc: Uc, addr: int, _size: int, _user_data: Any) -> None:
        self._states.sched.yield_from_hle_func(addr)

    def _emulator_loop(self):
        while True:
            self._states.sched.tick()
            if self._states.sched.yield_reason & YieldReason.REQUEST_SYSCALL:
                cr = self._syscall_handler.process_requests(self._states.sched.yield_request_num)
                if cr is not None:
                    task = self._states.sched.run_coroutine(cr)
                    # Propagate exception from coroutines that immediately end
                    # TODO do we log and continue instead of breaking the loop at least for some of them?
                    if task.done():
                        task.result()
            if self._states.sched.yield_reason & YieldReason.REQUEST_HLE_FUNC:
                cr = self._hle_func_handler.process_requests(self._states.sched.yield_request_num)
                if cr is not None:
                    task = self._states.sched.run_coroutine(cr)
                    # Propagate exception from coroutines that immediately end
                    # TODO do we log and continue instead of breaking the loop at least for some of them?
                    if task.done():
                        task.result()
            if self._states.sched.yield_reason & YieldReason.NO_THREAD:
                _logger.debug('Applet exited. Quitting...')
                break

            # TODO add handler for HLE callbacks

    def load(self, image_file: str | pathlib.Path) -> None:
        self._states.loader.load(image_file)

    def run(self):
        # Create main thread
        self._states.sched.new_thread(
            self._states.loader.entry_point,
            stack_size=self._states.config.stack_size,
        )

        # Setup magic functions
        self._uc.mem_map(self.MAGIC_BASE, 4096, UC_PROT_EXEC)
        # Register magic exit module with the HLE function handler
        magic_func_handler = MagicFunctionHandler(self._uc, self._states, self.MAGIC_BASE)
        self._hle_func_handler.register_guest_module(magic_func_handler)

        # TODO setup exception handler
        #self._uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._panic)
        #self._uc.hook_add(UC_HOOK_MEM_FETCH_PROT, self._panic)
        #self._uc.hook_add(UC_HOOK_CODE, self._trace_code)
        self._uc.hook_add(UC_HOOK_INTR, self._on_intr)
        self._uc.hook_add(UC_HOOK_CODE, self._on_code_magic_func,
                          begin=self.MAGIC_BASE,
                          end=self.MAGIC_BASE + align(magic_func_handler.sizeof(), 4096))

        for region_start, region_end, perm in self._uc.mem_regions():
            _logger.debug('%#010x-%#010x %s', region_start, region_end, uc_perm_to_str(perm))

        self._emulator_loop()
