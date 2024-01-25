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
from pymutekiu.hle import errno


class HeapAllocFree(unittest.TestCase):
    """
    Heap - Single page operation.
    """
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

    def test_formatted_state(self):
        """
        Should have the correct initial state.
        """
        memchunk_head = self._uc.mem_read(self._heap_base, 8)
        memchunk_tail = self._uc.mem_read(self._heap_tail, 8)
        self.assertEqual(bytes(memchunk_head), struct.pack('<2I', 0, self._heap_tail))
        self.assertEqual(bytes(memchunk_tail), struct.pack('<2I', self._heap_base, 0))

    def test_malloc(self):
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

    def test_malloc_alignment(self):
        """
        Should align to 4 bytes if the allocation is not 4-byte aligned.
        """
        gptr = self._heap.malloc(10)
        memchunk_new = gptr - 8
        prev, next_occupied = struct.unpack('<2I', self._uc.mem_read(memchunk_new, 8))
        next_ = next_occupied & 0xfffffffe
        self.assertEqual(next_ - gptr, 12)

    def test_free(self):
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

    def test_heap_free_island(self):
        """
        Should create an island when freeing a chunk sandwiched between 2 occupied chunks.
        """
        self._uc.mem_write(
            self._heap_base,
            struct.pack('<2I', 0, (self._heap_base + 0x10) | 1),
        )
        self._uc.mem_write(
            self._heap_base + 0x10,
            struct.pack('<2I', self._heap_base, (self._heap_base + 0x20) | 1),
        )
        self._uc.mem_write(
            self._heap_base + 0x20,
            struct.pack('<2I', self._heap_base + 0x10, self._heap_tail | 1),
        )
        self._uc.mem_write(
            self._heap_tail,
            struct.pack('<2I', self._heap_base + 0x20, 0),
        )

        self._heap.free(self._heap_base + 0x10 + 8)

        memchunks = (
            bytes(self._uc.mem_read(self._heap_base, 8)),
            bytes(self._uc.mem_read(self._heap_base + 0x10, 8)),
            bytes(self._uc.mem_read(self._heap_base + 0x20, 8)),
            bytes(self._uc.mem_read(self._heap_tail, 8)),
        )
        self.assertTupleEqual(
            memchunks, (
                struct.pack('<2I', 0, (self._heap_base + 0x10) | 1),
                struct.pack('<2I', self._heap_base, (self._heap_base + 0x20)),
                struct.pack('<2I', self._heap_base + 0x10, self._heap_tail | 1),
                struct.pack('<2I', self._heap_base + 0x20, 0),
            )
        )

    def test_heap_free_reverse_island(self):
        """
        Should merge the reverse island and its neighbor free chunks into a single free chunk.
        """
        self._uc.mem_write(
            self._heap_base,
            struct.pack('<2I', 0, (self._heap_base + 0x10)),
        )
        self._uc.mem_write(
            self._heap_base + 0x10,
            struct.pack('<2I', self._heap_base, (self._heap_base + 0x20) | 1),
        )
        self._uc.mem_write(
            self._heap_base + 0x20,
            struct.pack('<2I', self._heap_base + 0x10, self._heap_tail),
        )
        self._uc.mem_write(
            self._heap_tail,
            struct.pack('<2I', self._heap_base + 0x20, 0),
        )

        self._heap.free(self._heap_base + 0x10 + 8)

        memchunks = (
            bytes(self._uc.mem_read(self._heap_base, 8)),
            bytes(self._uc.mem_read(self._heap_tail, 8)),
        )
        self.assertTupleEqual(
            memchunks, (
                struct.pack('<2I', 0, self._heap_tail),
                struct.pack('<2I', self._heap_base, 0),
            )
        )

    def test_realloc_shrink(self):
        """
        Should return a new allocation whose chunk size is at least the size after shrinkage.
        """
        gptr = self._heap.malloc(16)
        gptr2 = self._heap.realloc(gptr, 8)

        memchunk_new = gptr2 - 8
        prev, next_occupied = struct.unpack('<2I', self._uc.mem_read(memchunk_new, 8))
        next_ = next_occupied & 0xfffffffe
        self.assertGreaterEqual(next_ - gptr2, 8)

    def test_realloc_grow(self):
        """
        Should return a new allocation whose chunk size is at least the size after growth.
        """
        gptr = self._heap.malloc(16)
        gptr2 = self._heap.realloc(gptr, 24)

        memchunk_new = gptr2 - 8
        prev, next_occupied = struct.unpack('<2I', self._uc.mem_read(memchunk_new, 8))
        next_ = next_occupied & 0xfffffffe
        self.assertGreaterEqual(next_ - gptr2, 24)

    def test_calloc(self):
        """
        Should clear the allocated memory with 0.
        """
        fill_size = (self._heap_tail - (self._heap_base + 8))
        self._uc.mem_write(self._heap_base + 8, b'\xff' * fill_size)

        gptr = self._heap.calloc(16, 1)
        mem = bytes(self._uc.mem_read(gptr, 16))
        self.assertEqual(mem, b'\x00' * 16)

    def test_get_free_space(self):
        """
        Should return the expected free space count for an empty heap.
        """
        # Head header and tail header.
        self.assertEqual(self._heap.get_free_space(), 4096 - 8 - 8)

    def test_get_free_space_alloc_free(self):
        """
        Should return the expected free space count after allocation and free.
        """
        gptr = self._heap.malloc(16)
        # Head header, tail header, middle chunk header and allocated memory.
        self.assertEqual(self._heap.get_free_space(), 4096 - 8 - 8 - 8 - 16)
        self._heap.free(gptr)
        # Head header and tail header.
        self.assertEqual(self._heap.get_free_space(), 4096 - 8 - 8)

    def test_exception_oom(self):
        """
        Should raise an exception when out of memory.
        """
        with self.assertRaises(errno.GuestOSError) as cm:
            self._heap.malloc(8192)
        self.assertEqual(cm.exception.namespace, errno.ErrnoNamespace.KERNEL, 'Wrong errno namespace.')
        self.assertEqual(cm.exception.cause, errno.ErrnoCauseKernel.SYS_OUT_OF_MEMORY, 'Wrong errno cause.')


class HeapMultiPage(unittest.TestCase):
    """
    Heap - Multiple page operation.
    """
    def setUp(self):
        self._heap_base = 0x10000000
        self._heap_end = self._heap_base + 4096
        self._heap_tail = self._heap_end - 8

        self._uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self._uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self._mock_states = mock.MagicMock()
        # Define the region before heap as "main module" and keep them unmapped.
        self._mock_states.loader.main_module.mem_range = [0, self._heap_base]

        self._heap = Heap(self._uc, self._mock_states, 4096, 16384)

    def test_grow(self):
        gptr = self._heap.malloc(4096)
        new_tail = self._heap_tail + 4096

        memchunk_middle_addr = gptr + 4096
        memchunk_head = self._uc.mem_read(self._heap_base, 8)
        memchunk_middle = self._uc.mem_read(gptr + 4096, 8)
        memchunk_tail = self._uc.mem_read(new_tail, 8)

        self.assertEqual(self._heap.free_pages, 8192)
        self.assertEqual(gptr, self._heap_base + 8)
        self.assertEqual(
            bytes(memchunk_head), struct.pack('<2I', 0, memchunk_middle_addr | 1),
            msg='Inconsistent head.',
        )
        self.assertEqual(
            bytes(memchunk_middle), struct.pack('<2I', self._heap_base, new_tail),
            msg='Inconsistent middle.',
        )
        self.assertEqual(
            bytes(memchunk_tail), struct.pack('<2I', memchunk_middle_addr, 0),
            msg='Inconsistent tail.',
        )
