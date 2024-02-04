from typing import cast
import unittest
import unittest.mock as mock
import struct

from unicorn import (
    Uc,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_MEM_READ,
    UC_MEM_WRITE,
)
from unicorn.arm_const import (
    UC_CPU_ARM_926,
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

from pymutekiu.hle.threading import ThreadDescriptor, CPUContext, MaskTable, Scheduler


class ThreadDescriptorTest(unittest.TestCase):
    """
    ThreadDescriptor
    """
    _THREAD_DESCRIPTOR_42 = bytes.fromhex(
        '00 01 00 00  00 00 00 00  00 00 00 00  00 00 00 00'  # 0x00
        '00 00 00 00  00 00 00 80  00 00 00 00  00 00 00 00'  # 0x10
        '00 00 2a 00  02 05 04 20  00 00 00 00  00 00 00 00'  # 0x20
        '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'  # 0x30
        '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'  # 0x40
        '00 00 00 00'                                         # 0x50
    )

    def test_sizeof(self):
        """
        Should return the correct size.
        """
        self.assertEqual(ThreadDescriptor.sizeof(), 84)

    def test_from_bytes(self):
        """
        Should successfully parse a simple thread descriptor.
        """
        thr = ThreadDescriptor.from_bytes(self._THREAD_DESCRIPTOR_42)
        self.assertEqual(thr.magic, 0x100)
        self.assertEqual(thr.unk_0x14, 0x80000000)
        self.assertEqual(thr.slot, 42)

    def test_to_bytes(self):
        thr = ThreadDescriptor()
        thr.set_slot(42)
        bytes_ = thr.to_bytes()
        self.assertEqual(bytes_, self._THREAD_DESCRIPTOR_42)

    def test_set_slot(self):
        desc = ThreadDescriptor()
        desc.set_slot(25)
        self.assertEqual(desc.slot, 25)
        self.assertEqual(desc.slot_high3b_bit, 1 << 3)
        self.assertEqual(desc.slot_low3b_bit, 1 << 1)
        self.assertEqual(desc.slot_high3b, 3)
        self.assertEqual(desc.slot_low3b, 1)


class CPUContextTest(unittest.TestCase):
    """
    CPUContext
    """
    _TEST: dict[str, int] = {
        'cpsr': 0x13,
        'r0': 0x0,
        'r1': 0x1,
        'r2': 0x2,
        'r3': 0x3,
        'r4': 0x4,
        'r5': 0x5,
        'r6': 0x6,
        'r7': 0x7,
        'r8': 0x8,
        'r9': 0x9,
        'r10': 0xa,
        'r11': 0xb,
        'r12': 0xc,
        'lr': 0x10000000,
        'pc': 0x20000000,
    }
    _REG_MAP: dict[str, int] = {
        'cpsr': UC_ARM_REG_CPSR,
        'r0': UC_ARM_REG_R0,
        'r1': UC_ARM_REG_R1,
        'r2': UC_ARM_REG_R2,
        'r3': UC_ARM_REG_R3,
        'r4': UC_ARM_REG_R4,
        'r5': UC_ARM_REG_R5,
        'r6': UC_ARM_REG_R6,
        'r7': UC_ARM_REG_R7,
        'r8': UC_ARM_REG_R8,
        'r9': UC_ARM_REG_R9,
        'r10': UC_ARM_REG_R10,
        'r11': UC_ARM_REG_R11,
        'r12': UC_ARM_REG_R12,
        'lr': UC_ARM_REG_LR,
        'pc': UC_ARM_REG_PC,
    }

    def test_sizeof(self):
        """
        Should return the correct size of the CPU context block.
        """
        self.assertEqual(CPUContext.sizeof(), 64)

    def test_from_emulator_context(self):
        """
        Should correctly extract the CPU context from an emulator context.
        """
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        for reg, val in self._TEST.items():
            uc.reg_write(self._REG_MAP[reg], val)
        ctx = CPUContext.from_emulator_context(uc)
        for reg, val in self._TEST.items():
            self.assertEqual(getattr(ctx, reg), val, f'{reg} differs')

    def test_from_bytes(self):
        """
        Should correctly extract the CPU context from a context block.
        """
        ctx = CPUContext.from_bytes(struct.pack('<16I', *self._TEST.values()))
        for reg, val in self._TEST.items():
            self.assertEqual(getattr(ctx, reg), val, f'{reg} differs')

    def test_to_emulator_context(self):
        """
        Should correctly restore the CPU context to an emulator context.
        """
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        ctx = CPUContext(**self._TEST)
        ctx.to_emulator_context(uc)
        for reg, ucreg in self._REG_MAP.items():
            self.assertEqual(uc.reg_read(ucreg), self._TEST[reg], f'{reg} differs')

    def test_to_bytes(self):
        """
        Should correctly serialize a CPU context block.
        """
        ctx = CPUContext(**self._TEST)
        self.assertEqual(ctx.to_bytes(), struct.pack('<16I', *self._TEST.values()))


class MaskTableTest(unittest.TestCase):
    """
    MaskTable
    """
    def setUp(self):
        self._masks = MaskTable()

    def test_unmask(self):
        """
        Should unmask a slot.
        """
        self._masks.unmask(42)
        self.assertTrue(self._masks.get(42))

    def test_mask(self):
        """
        Should mask a slot.
        """
        self._masks.unmask(42)
        self._masks.mask(42)
        self.assertFalse(self._masks.get(42))

    def test_first_unmasked(self):
        """
        Should always return the first unmasked value.
        """
        # Randomly generated sequence
        unmask_seq = (30, 31, 0, 23, 58, 46, 25, 38, 47, 8)

        for slot in unmask_seq:
            self._masks.unmask(slot)

        for slot in sorted(unmask_seq):
            self.assertEqual(self._masks.first_unmasked(), slot)
            self._masks.mask(slot)

    def test_all_masked(self):
        """
        Should return 0 when all values are masked.
        """
        self.assertEqual(self._masks.first_unmasked(), 0)


class SchedulerTestWithoutMock(unittest.TestCase):
    """
    Scheduler - Without any active mock objects.
    """
    def test_find_empty_normal_slot(self):
        """
        Should return 8 when the slots are empty.
        """
        sched = Scheduler(mock.MagicMock(), mock.MagicMock())
        self.assertEqual(sched.find_empty_normal_slot(), 8)


class SchedulerTestWithMock(unittest.TestCase):
    """
    Scheduler - With partially mocked Unicorn.
    """
    def setUp(self):
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)

        # Stub some functions
        self._uc.emu_start = mock.MagicMock()
        self._uc.emu_stop = mock.MagicMock()
        self._mock_states = mock.MagicMock()
        self._mock_states.heap = mock.MagicMock()
        self._mock_states.heap.malloc = mock.MagicMock()
        self._mock_states.heap.malloc.return_value = 0x10000000
        self._uc.mem_map(0x10000000, 4096)

    def test_new_thread(self):
        expected_stack_bottom = 0xff000000
        expected_stack_top = expected_stack_bottom - 0x8000
        expected_stack_guard_top = expected_stack_top - 4096

        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        # Thread should be allocated on the allocated memory address.
        self.assertEqual(thr, 0x10000000)

        desc = ThreadDescriptor.from_bytes(self._uc.mem_read(thr, ThreadDescriptor.sizeof()))

        # Check thread descriptor values.
        self.assertEqual(desc.sp, expected_stack_bottom - CPUContext.sizeof())
        self.assertEqual(desc.thread_func_ptr, 0xcafe0000)
        self.assertEqual(desc.stack, expected_stack_top)

        # Check memory map (double inclusive)
        mem_map = tuple(self._uc.mem_regions())
        self.assertIn(
            (expected_stack_top, expected_stack_bottom - 1, UC_PROT_READ | UC_PROT_WRITE), mem_map,
            'Stack not allocated.',
        )
        self.assertIn(
            (expected_stack_guard_top, expected_stack_top - 1, UC_PROT_NONE), mem_map,
            'Stack guard page not allocated.',
        )
