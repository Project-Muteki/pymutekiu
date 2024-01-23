from typing import cast
import unittest
import unittest.mock as mock
import struct

from unicorn import (
    Uc,
    UC_ARCH_ARM,
    UC_MODE_ARM,
)
from unicorn.arm_const import (
    UC_CPU_ARM_926
)

from .common import MockUnicornRegAccessor, MockUnicornMemoryAccessor

from pymutekiu.hle.heap import Heap


class HeapAllocFree(unittest.TestCase):
    def setUp(self):
        self._heap_base = 0x10000000
        self._heap_end = self._heap_base + 4096
        self._heap_tail = self._heap_end - 8

        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self._mock_states = mock.MagicMock()
        # Define the region before heap as "main module" and keep them unmapped.
        self._mock_states.loader.main_module.mem_range = [0, self._heap_base]

        self._heap = Heap(self._uc, self._mock_states, 4096, 4096)

    def test_heap_formatted_state(self):
        """
        Should have the correct initial state.
        """
        memchunk_head = self._uc.mem_read(self._heap_base, 8)
        memchunk_tail = self._uc.mem_read(self._heap_tail, 8)
        self.assertEqual(bytes(memchunk_head), struct.pack('<2I', 0, self._heap_tail))
        self.assertEqual(bytes(memchunk_tail), struct.pack('<2I', self._heap_base, 0))

    def test_heap_malloc(self):
        """
        Should successfully allocate the memory while maintaining the consistency of memory chunks.
        """
        gptr = self._heap.malloc(128)
        memchunk_middle_addr = gptr + 128
        memchunk_head = self._uc.mem_read(self._heap_base, 8)
        memchunk_middle = self._uc.mem_read(gptr + 128, 8)
        memchunk_tail = self._uc.mem_read(self._heap_tail, 8)
        self.assertEqual(gptr, self._heap_base + 8)
        self.assertEqual(
            bytes(memchunk_head), struct.pack('<2I', 0, memchunk_middle_addr | 1),
            msg='Inconsistent head.',
        )
        self.assertEqual(
            bytes(memchunk_middle), struct.pack('<2I', self._heap_base, self._heap_tail),
            msg='Inconsistent middle.',
        )
        self.assertEqual(
            bytes(memchunk_tail), struct.pack('<2I', memchunk_middle_addr, 0),
            msg='Inconsistent tail.',
        )

    def test_heap_free(self):
        """
        Should free previously allocated memory while maintaining the consistency of memory chunks.
        """
        gptr = self._heap.malloc(128)
        self._heap.free(gptr)
        memchunk_head = self._uc.mem_read(self._heap_base, 8)
        memchunk_tail = self._uc.mem_read(self._heap_tail, 8)
        self.assertEqual(
            bytes(memchunk_head), struct.pack('<2I', 0, self._heap_tail),
            msg='Inconsistent head.',
        )
        self.assertEqual(
            bytes(memchunk_tail), struct.pack('<2I', self._heap_base, 0),
            msg='Inconsistent tail.',
        )
