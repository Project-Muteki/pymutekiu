from typing import cast
import math
import unittest
import unittest.mock as mock
import os
import struct

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_QUERY_TIMEOUT,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_INTR,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNMAPPED,
)
from unicorn.arm_const import (
    UC_CPU_ARM_926,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_SP,
)

from keystone import (
    Ks,
    KS_ARCH_ARM,
    KS_MODE_ARM,
)

from pymutekiu.utils import align

_RUN_EXPERIMENTS = os.getenv('RUN_EXPERIMENTS', 'no') == 'yes'


@unittest.skipUnless(_RUN_EXPERIMENTS, 'Skipping experiments. Use the environment variable RUN_EXPERIMENTS to '
                                       'activate.')
class Experiments(unittest.TestCase):
    """
    Various experiments on Unicorn states after hooks.
    """
    def setUp(self):
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self._ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

    def test_hle_func_sets_lr(self):
        """
        FETCH_PROT should be triggered after the call instruction and everything should be properly set.
        """
        def on_fetch_prot(uc: Uc, type_: int, addr: int, size: int, value: int, _user_data) -> bool:
            print('on_fetch_prot', type_, hex(addr), hex(size), hex(value))
            uc.emu_stop()
            return False

        code_page = 0x10000000
        guard_page = 0x10001000
        code, _ninst = self._ks.asm(
            'mov r0, 0x10;'
            'mov r1, 0x11;'
            'ldr r4, [pc, 4];'
            'blx r4;'
            'b 0x10000010',
            code_page,
            as_bytes=True,
        )

        self._uc.hook_add(UC_HOOK_MEM_FETCH_PROT, on_fetch_prot)
        self._uc.mem_map(code_page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_map(guard_page, 4096, UC_PROT_NONE)

        self._uc.mem_write(code_page, code)
        self._uc.mem_write(code_page + 0x14, guard_page.to_bytes(4, 'little'))
        old_cpsr = self._uc.reg_read(UC_ARM_REG_CPSR)

        # Trying to do the thing listed under https://github.com/unicorn-engine/unicorn/issues/1137 but failing.
        # Apparently it does raise an exception when on_fetch_prot returns False. Ignore that specific exception.
        with self.assertRaises(UcError) as cm:
            self._uc.emu_start(code_page, 0)

        # The following should pass despite Unicorn documentation states that exception may clobber states and
        # recovering from it is unsafe.
        self.assertEqual(cm.exception.errno, UC_ERR_FETCH_PROT, 'Unknown exception.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R0), 0x10, 'r0 not properly set.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R1), 0x11, 'r1 not properly set.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_LR), code_page + 0x10, 'lr not properly set.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_PC), guard_page, 'pc not properly set.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_CPSR), old_cpsr, 'cpsr clobbered.')
        print(f'cpsr: {self._uc.reg_read(UC_ARM_REG_CPSR):032b}')

    def test_svc(self):
        """
        on_intr should be able to stop the emulation when an SVC happens and the registers should be set to expected
        values after emulator stopped.
        """
        def on_intr(uc: Uc, intno: int, _user_data) -> None:
            print('qemu int type:', intno)
            uc.emu_stop()

        code_page = 0x10000000
        code, _ninst = self._ks.asm(
            'svc 0xcafe;'
            'b 0x10000004',
            code_page,
            as_bytes=True,
        )
        self._uc.hook_add(UC_HOOK_INTR, on_intr)

        self._uc.mem_map(code_page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_write(code_page, code)
        self._uc.emu_start(code_page, 0)

        self.assertEqual(self._uc.reg_read(UC_ARM_REG_PC) - 4, code_page, 'pc not properly set.')

    def test_0x1c_shenanigans(self):
        """
        unk_0x1c shenanigans in OSResumeThread.
        """
        code_page = 0x10000000
        code, ninst = self._ks.asm(
            'rsb r1, r1, 0x40;'
            'asr r2, r1, 0x1f;'
            'add r1, r1, r2, lsr #28;'
            'mov r2, 1;'
            'add r1, r2, r1, asr #4',
            code_page,
            as_bytes=True,
        )

        self._uc.mem_map(code_page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_write(code_page, code)

        result = []
        for i in range(65536):
            self._uc.reg_write(UC_ARM_REG_R1, i)
            self._uc.emu_start(code_page, 0, count=ninst)
            ret = self._uc.reg_read(UC_ARM_REG_R1)
            result.append(int.from_bytes(ret.to_bytes(4, 'little'), 'little', signed=True))
        self.assertListEqual(result, [(64 - i) // 16 + 1 if i < 64 else (64 - i + 15) // 16 + 1 for i in range(65536)])

    @unittest.skip('This is very slow and will fail. Putting here solely for documentation purposes.')
    def test_svc_stop_intermittent_failure(self):
        """
        Try to trigger the failure in pymutekiu#5.
        """
        actual_syscall_no = None
        def on_intr(uc: Uc, intno: int, _user_data) -> None:
            nonlocal actual_syscall_no
            if intno == 2:
                svc_offset = self._uc.reg_read(UC_ARM_REG_PC) - 4
                syscall_no = int.from_bytes(self._uc.mem_read(svc_offset, 4), 'little') & 0xffffff

                # Recover from syscall state to prepare for returning
                sp = self._uc.reg_read(UC_ARM_REG_SP)
                lr = int.from_bytes(self._uc.mem_read(sp, 4), 'little')
                r0 = int.from_bytes(self._uc.mem_read(sp + 4, 4), 'little')
                self._uc.reg_write(UC_ARM_REG_SP, sp + 8)
                self._uc.reg_write(UC_ARM_REG_LR, lr)
                self._uc.reg_write(UC_ARM_REG_R0, r0)

                actual_syscall_no = syscall_no
                self._uc.emu_stop()

        code_page = 0x10000000
        stack_page = 0x20000000

        asm = ';'.join(f'push {{r0}};push {{lr}};svc {i + 0x10000:#x}' for i in range(65536))

        code, ninst = self._ks.asm(
            asm,
            code_page,
            as_bytes=True,
        )

        self._uc.mem_map(code_page, align(len(code), 4096), UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_map(stack_page, 4096, UC_PROT_READ | UC_PROT_WRITE)

        self._uc.mem_write(code_page, code)
        self._uc.hook_add(UC_HOOK_INTR, on_intr)

        self._uc.reg_write(UC_ARM_REG_PC, code_page)
        self._uc.reg_write(UC_ARM_REG_SP, stack_page + 4096)
        for expected_syscall_no in range(0x10000, 0x10000+65536):
            while True:
                self._uc.emu_start(self._uc.reg_read(UC_ARM_REG_PC), 0, count=ninst, timeout=100)
                print(self._uc.query(UC_QUERY_TIMEOUT))
                if self._uc.query(UC_QUERY_TIMEOUT) == 1:
                    continue
                break

            self.assertEqual(actual_syscall_no, expected_syscall_no)

    def test_return_to_null(self):
        code_page = 0x10000000

        code, ninst = self._ks.asm(
            'bx lr',
            code_page,
            as_bytes=True,
        )

        self._uc.mem_map(code_page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_write(code_page, code)

        self._uc.reg_write(UC_ARM_REG_LR, 0)
        with self.assertRaises(UcError) as cm:
            self._uc.emu_start(self._uc.reg_read(UC_ARM_REG_PC), 0x100000000)
        self.assertEqual(cm.exception.errno, UC_ERR_FETCH_UNMAPPED)