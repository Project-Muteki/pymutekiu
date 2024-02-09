from typing import cast
import unittest
import unittest.mock as mock
import struct

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_PROT_READ,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_INTR,
    UC_ERR_FETCH_PROT,
)
from unicorn.arm_const import (
    UC_CPU_ARM_926,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
)

from keystone import (
    Ks,
    KS_ARCH_ARM,
    KS_MODE_ARM,
)


@unittest.skip('Skipping experiments.')
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
