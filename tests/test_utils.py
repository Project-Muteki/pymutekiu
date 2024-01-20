from typing import cast
import unittest
import unittest.mock as mock

from .common import MockUnicornRegAccessor, MockUnicornMemoryAccessor

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
)

import pymutekiu.utils as utils


class MemPageTrackerSimple(unittest.TestCase):
    """
    MemPageTracker - simple allocation
    """
    def setUp(self):
        self._instance = utils.MemPageTracker(64)
        self._instance.add(4)

    def test_add(self):
        """Should add an entry successfully."""
        addr = self._instance.add(4)
        self.assertEqual(addr, 4)
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4), (4, 8)))

    def test_remove(self):
        """Should remove an entry successfully."""
        self._instance.remove(0)
        self.assertTupleEqual(tuple(self._instance.walk()), tuple())

    def test_exception_on_full(self):
        """Should raise an exception when allocating more than free space."""
        with self.assertRaises(ValueError) as cm:
            self._instance.add(64)
        self.assertEqual(cm.exception.args[0], 'No space left for new allocation.')
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4),), 'Memory layout should not be changed on error.')

    def test_exception_on_removing_nonexisting_chunk(self):
        """Should raise an exception when removing nonexisting chunk."""
        with self.assertRaises(ValueError) as cm:
            self._instance.remove(42)
        self.assertEqual(cm.exception.args[0], 'Chunk 42 does not exist.')
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4),), 'Memory layout should not be changed on error.')


class MemPageTrackerComplex(unittest.TestCase):
    """
    MemPageTracker - complex allocation
    """
    def setUp(self):
        self._instance = utils.MemPageTracker(64)
        # ((0,4), (4, 12), (12, 16))
        self._alloc = (self._instance.add(4), self._instance.add(8), self._instance.add(4), self._instance.add(4))

    def test_remove_middle(self):
        self._instance.remove(self._alloc[1])
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4), (12, 16), (16, 20)))

    def test_reclaim(self):
        """Should reclaim the first free chunk that size-wise matches exactly."""
        target = self._alloc[1]
        self._instance.remove(target)
        result = self._instance.add(8)
        self.assertEqual(result, target)
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4), (4, 12), (12, 16), (16, 20)))

    def test_splice(self):
        """Should splice the first free chunk when possible."""
        target = self._alloc[1]
        self._instance.remove(target)
        result = self._instance.add(4)
        self.assertEqual(result, target)
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 4), (4, 8), (12, 16), (16, 20)))

    def test_join_and_splice(self):
        """Should join all free adjacent chunks when freeing a chunk and correctly splice."""
        self._instance.remove(self._alloc[0])
        self._instance.remove(self._alloc[2])
        self._instance.remove(self._alloc[1])
        self.assertEqual(self._instance.add(6), 0)
        self.assertTupleEqual(tuple(self._instance.walk()), ((0, 6), (16, 20)))


class OABIArgReaderSingleType(unittest.TestCase):
    """
    OABIArgReader - With single type arguments.
    """
    def setUp(self):
        self._mock_unicorn = mock.MagicMock()
        self._sp = 0x1234
        self._regs = {
            UC_ARM_REG_R0: 0,
            UC_ARM_REG_R1: 1,
            UC_ARM_REG_R2: 2,
            UC_ARM_REG_R3: 3,
            UC_ARM_REG_SP: self._sp,
        }
        self._stack = b'\xff\xff\xff\xff\xfe\xff\xff\xff'

        self._mock_unicorn.reg_read.side_effect = MockUnicornRegAccessor(self, self._regs)
        self._mock_unicorn.mem_read.side_effect = MockUnicornMemoryAccessor(self, self._stack, self._sp)

    def test_parse(self):
        """
        Should correctly parse fixed format.
        """
        reader = utils.OABIArgReader(self._mock_unicorn, ['uint'] * 6)

        self.assertSequenceEqual(reader.fixed_args, [0, 1, 2, 3, 0xffffffff, 0xfffffffe])

    def test_read_variadic(self):
        """
        Should fetch the first and second variadic argument.
        """
        reader = utils.OABIArgReader(self._mock_unicorn, ['uint', '...'])
        variadic_args = reader.read_variadic('uint'), reader.read_variadic('uint')

        self.assertSequenceEqual(reader.fixed_args, [0])
        self.assertSequenceEqual(variadic_args, [1, 2])

    def test_reset_variadic(self):
        """
        Should reset the variadic reader state after calling reset_variadic().
        """
        reader = utils.OABIArgReader(self._mock_unicorn, ['uint', '...'])
        variadic_arg1 = reader.read_variadic('uint')
        reader.reset_variadic()
        variadic_arg2 = reader.read_variadic('uint')

        self.assertEqual(variadic_arg1, 1)
        self.assertEqual(variadic_arg1, variadic_arg2)

    def test_read_variadic_list(self):
        """
        Should correctly parse variadic format.
        """
        reader = utils.OABIArgReader(self._mock_unicorn, ['uint', '...'])
        variadic_args = reader.read_variadic_list(['uint'] * 5)

        self.assertSequenceEqual(reader.fixed_args, [0])
        self.assertSequenceEqual(variadic_args, [1, 2, 3, 0xffffffff, 0xfffffffe])

    def test_exception_bad_variadic_format(self):
        """
        Should raise an exception when variadic ellipsis is not only appearing at the end of the format list.
        """
        with self.assertRaises(ValueError) as cm:
            utils.OABIArgReader(self._mock_unicorn, ['uint', '...', 'uint'])
        self.assertEqual(cm.exception.args[0], 'Variadic must be specified at the end of the format.')

    def test_exception_bad_format(self):
        """
        Should raise an exception when there's a bad type in the format list.
        """
        with self.assertRaises(ValueError) as cm:
            utils.OABIArgReader(self._mock_unicorn, ['blah'])
        self.assertEqual(cm.exception.args[0], "Unknown argument type 'blah' for argument 0.")


class MiscFunctions(unittest.TestCase):
    def test_align_aligned(self):
        self.assertEqual(utils.align(4096, 4096), 4096)

    def test_align_unaligned(self):
        self.assertEqual(utils.align(4097, 4096), 8192)

    def test_lalign_aligned(self):
        self.assertEqual(utils.lalign(4096, 4096), 4096)

    def test_lalign_unaligned(self):
        self.assertEqual(utils.lalign(4097, 4096), 4096)


class GuestTypeReader(unittest.TestCase):
    """
    guest_type_from_bytes
    """
    def test_int(self):
        """
        Should handle signed int type.
        """
