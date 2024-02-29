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

from pymutekiu.hle.threading import ThreadDescriptor, CPUContext, MaskTable, Scheduler, YieldReason, ThreadWaitReason
from pymutekiu.hle.heap import Heap
from pymutekiu.hle.errno import GuestOSError, ErrnoNamespace, ErrnoCauseUser


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
        Should return None when all values are masked.
        """
        self.assertIsNone(self._masks.first_unmasked())


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
    Scheduler - With partially mocked Unicorn and mocked heap.
    """
    def setUp(self):
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)

        # Stub some functions
        # Unicorn
        self._uc.emu_start = mock.MagicMock()
        self._uc.emu_stop = mock.MagicMock()

        # OSStates
        self._mock_states = mock.MagicMock()
        self._mock_states.heap = mock.MagicMock()
        self._mock_states.heap.malloc = mock.MagicMock()
        self._mock_states.heap.malloc.return_value = 0x10000000
        self._mock_states.heap.free = mock.MagicMock()

        # Fake heap alloc
        self._uc.mem_map(0x10000000, 4096)

    def test_new_thread(self):
        """
        Should create a new thread with all default optional parameters.
        """
        expected_stack_bottom = 0xff000000
        expected_stack_top = expected_stack_bottom - 0x8000
        expected_stack_guard_top = expected_stack_top - 4096

        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        # Thread should be allocated on the allocated memory address with the correct size.
        self.assertEqual(thr, 0x10000000)
        cast(mock.MagicMock, self._mock_states.heap.malloc).assert_called_once_with(ThreadDescriptor.sizeof())

        desc = ThreadDescriptor.from_bytes(self._uc.mem_read(thr, ThreadDescriptor.sizeof()))

        # Check thread descriptor values.
        self.assertEqual(desc.sp, expected_stack_bottom - CPUContext.sizeof())
        self.assertEqual(desc.thread_func_ptr, 0xcafe0000)
        self.assertEqual(desc.stack, expected_stack_top)

        # Check memory map (double inclusive)
        mem_map = tuple(self._uc.mem_regions())
        self.assertEqual(len(mem_map), 3, 'Unexpected # of memory maps.')
        self.assertIn(
            (expected_stack_top, expected_stack_bottom - 1, UC_PROT_READ | UC_PROT_WRITE), mem_map,
            'Stack not allocated.',
        )
        self.assertIn(
            (expected_stack_guard_top, expected_stack_top - 1, UC_PROT_NONE), mem_map,
            'Stack guard page not allocated.',
        )

    def test_move_thread_to_slot(self):
        """
        Should move the thread to a new slot.
        """
        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        sched.move_thread_to_slot(thr, 15)

        self.assertEqual(sched.get_slot(15), thr, 'Thread slot not properly set.')
        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.slot, 15, 'Thread descriptor not updated.')

    def test_delete_thread(self):
        """
        Should delete a previously allocated thread.
        """
        expected_stack_bottom = 0xff000000
        expected_stack_top = expected_stack_bottom - 0x8000
        expected_stack_guard_top = expected_stack_top - 4096

        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        sched.delete_thread(thr)

        cast(mock.MagicMock, self._mock_states.heap.free).assert_called_once_with(0x10000000)

        # Check memory map (double inclusive)
        mem_map = tuple(self._uc.mem_regions())
        self.assertEqual(len(mem_map), 1, 'Unexpected # of memory maps.')
        self.assertNotIn(
            (expected_stack_top, expected_stack_bottom - 1, UC_PROT_READ | UC_PROT_WRITE), mem_map,
            'Stack not deallocated.',
        )
        self.assertNotIn(
            (expected_stack_guard_top, expected_stack_top - 1, UC_PROT_NONE), mem_map,
            'Stack guard page not deallocated.',
        )

    def test_switch_init(self):
        """
        Should switch to the initial thread.
        """
        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        self.assertEqual(sched.current_thread, thr)

    def test_get_set_errno(self):
        """
        Should be able to set the errno value on teh descriptor and read it back.
        """
        sched = Scheduler(self._uc, self._mock_states)
        thr = sched.new_thread(0xcafe0000)
        sched.set_errno(0x11223344)
        self.assertEqual(sched.get_errno(), 0x11223344)

    def test_yield_from_svc(self):
        """
        Should reconfigure the emulator state from a syscall to a normal function call and stop the emulation.
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Values
        sp = 0x20000000 + 4096
        sp_before_syscall = sp - 8
        lr = 0x10000000
        r0 = 0x12345678
        r1 = 0xdeadbeef
        r2 = 0xdeaddead
        r3 = 0xbeefbeef

        # Setup extra states
        self._uc.mem_map(0x20000000, 4096)
        self._uc.mem_write(sp_before_syscall, lr.to_bytes(4, 'little'))
        self._uc.mem_write(sp_before_syscall + 4, r0.to_bytes(4, 'little'))
        self._uc.reg_write(UC_ARM_REG_R0, 0x0)
        self._uc.reg_write(UC_ARM_REG_R1, r1)
        self._uc.reg_write(UC_ARM_REG_R2, r2)
        self._uc.reg_write(UC_ARM_REG_R3, r3)
        self._uc.reg_write(UC_ARM_REG_LR, 0x0)
        self._uc.reg_write(UC_ARM_REG_SP, sp_before_syscall)

        # Set SVC instruction for use by the handler
        self._uc.reg_write(UC_ARM_REG_PC, 0x10000004)
        self._uc.mem_write(0x10000000, bytes.fromhex('000001ef'))  # svc 0x10000

        sched.yield_from_svc()

        cast(mock.MagicMock, self._uc.emu_stop).assert_called_once()
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R0), r0, 'r0 not properly restored.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R1), r1, 'r1 clobbered.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R2), r2, 'r2 clobbered.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_R3), r3, 'r3 clobbered.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_LR), lr, 'lr not properly restored.')
        self.assertEqual(self._uc.reg_read(UC_ARM_REG_SP), sp, 'unexpected sp value.')
        self.assertEqual(sched.yield_reason, YieldReason.REQUEST_SYSCALL, 'Wrong yield reason.')
        self.assertEqual(sched.yield_request_num, 0x10000, 'Wrong request number.')

    def test_coroutine_runner_eager_exec(self):
        """
        Should immediately start running the coroutine after registering it with run_coroutine().
        """
        sched = Scheduler(self._uc, self._mock_states)

        called = False

        async def cr():
            nonlocal called
            called = True

        # Scheduler tick start time is initialized to 0
        thr = sched.new_thread(0xcafe0000)
        sched.run_coroutine(cr())

        self.assertTrue(called, 'Couroutine not immediately called.')

    def test_sleep(self):
        """
        Should immediately start resolve syscall coroutines.
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Scheduler tick start time is initialized to 0
        thr = sched.new_thread(0xcafe0000)
        sched.run_coroutine(sched.sleep(1))

        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.SLEEP, 'Wrong wait reason.')
        self.assertEqual(desc.sleep_counter, 1, 'Unexpected sleep counter value.')

    @mock.patch('time.monotonic_ns')
    def test_coroutine_resolution(self, timer_mock: mock.MagicMock):
        """
        Should immediately start resolve syscall coroutines.
        :param timer_mock: Mock timer.
        """
        timer_mock.return_value = 0

        sched = Scheduler(self._uc, self._mock_states)

        async def cr():
            await sched.sleep(1)

        # Scheduler tick start time is initialized to 0
        thr = sched.new_thread(0xcafe0000)
        sched.run_coroutine(cr())

        # Trigger the ticker interrupt emulation routine
        timer_mock.return_value = 1_000_000
        sched.tick()
        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.NONE, 'Wrong wait reason.')
        self.assertEqual(desc.sleep_counter, 0, 'Unexpected sleep counter value.')

    def test_request_sleep(self):
        """
        Should put the thread to sleep.
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Create the current thread
        thr = sched.new_thread(0xcafe0000)

        sched.request_sleep(100)
        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.SLEEP, 'Wrong wait reason.')
        self.assertEqual(desc.sleep_counter, 100, 'Unexpected sleep counter value.')

    def test_request_wakeup(self):
        """
        Should wake up the thread.
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Create the current thread
        thr = sched.new_thread(0xcafe0000)

        sched.request_sleep(100)
        sched.request_wakeup(thr)

        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.NONE, 'Wrong wait reason.')
        self.assertEqual(desc.sleep_counter, 0, 'Unexpected sleep counter value.')

    def test_request_suspend(self):
        """
        Should suspend the thread (set the SUSPEND flag and unschedule).
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Create the current thread
        thr = sched.new_thread(0xcafe0000)

        sched.request_suspend(thr)

        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.SUSPEND, 'Wrong wait reason.')
        self.assertIsNone(sched.current_slot, 'Thread not unscheduled.')

    def test_request_resume(self):
        """
        Should resume the thread (clear the SUSPEND flag and reschedule).
        """
        sched = Scheduler(self._uc, self._mock_states)

        # Create the current thread
        thr = sched.new_thread(0xcafe0000)

        sched.request_suspend(thr)
        sched.request_resume(thr)

        desc = sched.read_thread_descriptor(thr)
        self.assertEqual(desc.wait_reason, ThreadWaitReason.NONE, 'Wrong wait reason.')
        self.assertEqual(sched.current_slot, desc.slot, 'Thread not scheduled.')


class SchedulerWithRealHeap(unittest.TestCase):
    """
    Scheduler - With partially mocked Unicorn and real heap.
    """
    def setUp(self):
        self._heap_base = 0x10000000
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)

        # Stub some functions
        # Unicorn
        self._uc.emu_start = mock.MagicMock()
        self._uc.emu_stop = mock.MagicMock()

        # OSStates
        self._mock_states = mock.MagicMock()
        self._mock_states.loader.main_module.mem_range = [0, self._heap_base]
        self._mock_states.heap = Heap(self._uc, self._mock_states, 4096, 4096)

    def test_new_thread_multiple(self):
        expected_stack_bottom_1 = 0xff000000
        expected_stack_top_1 = expected_stack_bottom_1 - 0x8000
        expected_stack_guard_top_1 = expected_stack_top_1 - 4096

        expected_stack_bottom_2 = expected_stack_guard_top_1
        expected_stack_top_2 = expected_stack_bottom_2 - 0x10000
        expected_stack_guard_top_2 = expected_stack_top_2 - 4096

        sched = Scheduler(self._uc, self._mock_states)
        thr1 = sched.new_thread(0xcafe0000)
        thr2 = sched.new_thread(0xdecafe00, user_data=0xdeadcafe, stack_size=0x10000)

        desc1 = ThreadDescriptor.from_bytes(self._uc.mem_read(thr1, ThreadDescriptor.sizeof()))
        desc2 = ThreadDescriptor.from_bytes(self._uc.mem_read(thr2, ThreadDescriptor.sizeof()))
        ctx1 = CPUContext.from_bytes(self._uc.mem_read(desc1.sp, CPUContext.sizeof()))
        ctx2 = CPUContext.from_bytes(self._uc.mem_read(desc2.sp, CPUContext.sizeof()))

        # Check thread descriptor values.
        self.assertEqual(desc1.sp, expected_stack_bottom_1 - CPUContext.sizeof())
        self.assertEqual(desc1.thread_func_ptr, 0xcafe0000)
        self.assertEqual(desc1.stack, expected_stack_top_1)
        self.assertEqual(desc2.sp, expected_stack_bottom_2 - CPUContext.sizeof())
        self.assertEqual(desc2.thread_func_ptr, 0xdecafe00)
        self.assertEqual(desc2.stack, expected_stack_top_2)

        self.assertEqual(ctx1.pc, 0xcafe0000, 'Function address not passed to thread descriptor 1 CPU context.')
        self.assertEqual(ctx1.r0, 0x0, 'User data not passed to thread descriptor 1 CPU context.')
        self.assertEqual(ctx2.pc, 0xdecafe00, 'Function address not passed to thread descriptor 2 CPU context.')
        self.assertEqual(ctx2.r0, 0xdeadcafe, 'User data not passed to thread descriptor 2 CPU context.')

        # Check memory map (double inclusive)
        mem_map = tuple(self._uc.mem_regions())
        self.assertEqual(len(mem_map), 5, 'Unexpected # of memory maps.')
        self.assertIn(
            (expected_stack_top_1, expected_stack_bottom_1 - 1, UC_PROT_READ | UC_PROT_WRITE), mem_map,
            'Stack 1 not allocated.',
        )
        self.assertIn(
            (expected_stack_guard_top_1, expected_stack_top_1 - 1, UC_PROT_NONE), mem_map,
            'Stack guard page 1 not allocated.',
        )
        self.assertIn(
            (expected_stack_top_2, expected_stack_bottom_2 - 1, UC_PROT_READ | UC_PROT_WRITE), mem_map,
            'Stack 2 not allocated.',
        )
        self.assertIn(
            (expected_stack_guard_top_2, expected_stack_top_2 - 1, UC_PROT_NONE), mem_map,
            'Stack guard page 2 not allocated.',
        )

    def test_exception_move_to_occupied_slot(self):
        """
        Should raise an exception when moving to a slot that's occupied without changing the slots.
        """
        sched = Scheduler(self._uc, self._mock_states)
        thr1 = sched.new_thread(0xcafe0000)
        thr2 = sched.new_thread(0xdecafe00)
        with self.assertRaises(GuestOSError) as cm:
            sched.move_thread_to_slot(thr1, 9)

        self.assertEqual(cm.exception.namespace, ErrnoNamespace.USER, 'Wrong errno namespace.')
        self.assertEqual(cm.exception.cause, ErrnoCauseUser.THREADING_SLOT_IN_USE, 'Wrong errno cause.')
        self.assertEqual(sched.get_slot(8), thr1, 'Thread 1 moved.')
        self.assertEqual(sched.get_slot(9), thr2, 'Thread 2 moved.')
        desc1 = sched.read_thread_descriptor(thr1)
        desc2 = sched.read_thread_descriptor(thr2)
        self.assertEqual(desc1.slot, 8, 'Thread descriptor 1 updated unexpectedly.')
        self.assertEqual(desc2.slot, 9, 'Thread descriptor 2 updated unexpectedly.')