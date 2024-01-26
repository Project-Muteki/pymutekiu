import dataclasses
from typing import (
    Sequence,
    Literal,
    Optional,
    TypeVar,
    Generic,
    TYPE_CHECKING,
)
from collections.abc import Iterator

import struct
import enum

from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)
from unicorn import Uc

ArgumentType = Literal[
    'void', 'pointer',
    'int8', 'int16', 'int32', 'int64',
    'uint8', 'uint16', 'uint32', 'uint64',
    'bool', 'char', 'byte', 'short', 'int', 'long', 'longlong',
    'uchar', 'ubyte', 'ushort', 'uint', 'ulong', 'ulonglong',
    'float', 'double',
]
VariadicArgumentType = Literal['...']

ArgumentFormat = Sequence[ArgumentType | VariadicArgumentType]
GuestScalarValue = Optional[int | float | bool]
Argument = GuestScalarValue

PermString = Literal['---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx']

ARM_ARG_REGISTERS = (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
)

ARG_SIZES: dict[ArgumentType, int] = {
    'void': 1, 'pointer': 1,
    'int8': 1, 'int16': 1, 'int32': 1, 'int64': 2,
    'uint8': 1, 'uint16': 1, 'uint32': 1, 'uint64': 2,
    'bool': 1, 'char': 1, 'byte': 1, 'short': 1, 'int': 1, 'long': 1, 'longlong': 2,
    'uchar': 1, 'ubyte': 1, 'ushort': 1, 'uint': 1, 'ulong': 1, 'ulonglong': 2,
    'float': 1, 'double': 2,
}

VALID_ARGUMENT_TYPES: set[ArgumentType] = {
    'void', 'pointer',
    'int8', 'int16', 'int32', 'int64',
    'uint8', 'uint16', 'uint32', 'uint64',
    'bool', 'char', 'byte', 'short', 'int', 'long', 'longlong',
    'uchar', 'ubyte', 'ushort', 'uint', 'ulong', 'ulonglong',
    'float', 'double',
}

INT_TYPES: set[ArgumentType] = {
    'int8', 'int16', 'int32', 'int64',
    'char', 'byte', 'short', 'int', 'long', 'longlong',
}

UINT_TYPES: set[ArgumentType] = {
    'pointer',
    'uint8', 'uint16', 'uint32', 'uint64',
    'uchar', 'ubyte', 'ushort', 'uint', 'ulong', 'ulonglong',
}

FLOAT_READER = struct.Struct('<f')
DOUBLE_READER = struct.Struct('<d')


class MemPageTracker:
    @dataclasses.dataclass
    class MemPageChunk:
        start: int
        end: int
        occupied: bool

        @property
        def size(self):
            return self.end - self.start

    _limit: int
    _map: dict[int, 'MemPageTracker.MemPageChunk']
    _head: Optional['MemPageTracker.MemPageChunk']
    _tail: Optional['MemPageTracker.MemPageChunk']

    def __init__(self, limit: int):
        self._limit = limit
        self._map = {}
        self._map_tail = {}
        self._head = None
        self._tail = None

    def walk(self) -> Iterator[tuple[int, int]]:
        """
        Iterate over chunks currently allocated.
        :return: An iterator of a 2-tuple with each chunk's start and end address.
        """
        chunk = self._head
        while chunk is not None:
            if chunk.occupied:
                yield chunk.start, chunk.end
            chunk = self._map.get(chunk.end)

    def add(self, pages: int) -> int:
        """
        Allocate pages.
        :param pages: Number of pages to allocate.
        :return: Relative address of the pages.
        """
        if pages > self._limit:
            raise ValueError('No space left for new allocation.')

        if self._head is None:
            assert len(self._map) == len(self._map_tail) == 0
            new_head = self.MemPageChunk(0, pages, True)
            self._map[new_head.start] = self._map_tail[new_head.end] = new_head
            self._head = self._tail = new_head
            return new_head.start

        chunk = self._head
        allocated_chunk: Optional['MemPageTracker.MemPageChunk'] = None

        while chunk is not None:
            if not chunk.occupied:
                if chunk.size == pages:
                    # exact match
                    chunk.occupied = True
                    allocated_chunk = chunk
                    break
                elif chunk.size > pages:
                    # splicing the chunk
                    allocated_chunk = self.MemPageChunk(chunk.start, chunk.start + pages, True)
                    leftover_chunk = self.MemPageChunk(chunk.start + pages, chunk.end, False)
                    self._map[allocated_chunk.start] = self._map_tail[allocated_chunk.end] = allocated_chunk
                    self._map[leftover_chunk.start] = self._map_tail[leftover_chunk.end] = leftover_chunk

                    # If splicing the head/tail chunk, update the new head/tail
                    if chunk.start == self._head.start:
                        self._head = allocated_chunk
                    if chunk.start == self._tail.start:
                        self._tail = leftover_chunk
                    break
            else:
                chunk = self._map.get(chunk.end)

        # end of chunk
        if allocated_chunk is None:
            chunk = self._tail
            if pages > (self._limit - self._tail.end):
                raise ValueError('No space left for new allocation.')
            allocated_chunk = self.MemPageChunk(chunk.end, chunk.end + pages, True)
            self._map[allocated_chunk.start] = self._map_tail[allocated_chunk.end] = allocated_chunk
            self._tail = allocated_chunk

        return allocated_chunk.start

    def remove(self, addr: int):
        """
        Remove allocation.
        :param addr: Relative address of the allocation.
        """
        if addr not in self._map:
            raise ValueError(f'Chunk {addr} does not exist.')

        chunk = self._map[addr]
        chunk.occupied = False
        chunk_prev = self._map_tail.get(chunk.start)
        chunk_next = self._map.get(chunk.end)
        new_start, new_end = chunk.start, chunk.end

        if chunk_prev is not None and not chunk_prev.occupied:
            # Merge previous unoccupied chunk
            new_start = chunk_prev.start
            del self._map[chunk_prev.start]
            del self._map_tail[chunk_prev.end]
        if chunk_next is not None and not chunk_next.occupied:
            # Merge next unoccupied chunk
            new_end = chunk_next.end
            del self._map[chunk_next.start]
            del self._map_tail[chunk_next.end]

        if (new_start, new_end) != (chunk.start, chunk.end):
            # Write merged chunk to index
            del self._map[chunk.start]
            del self._map_tail[chunk.end]
            chunk = self.MemPageChunk(new_start, new_end, False)
            self._map[chunk.start] = self._map_tail[chunk.end] = chunk

        # Update head/tail index if needed
        if chunk.start == self._head.start and chunk != self._head:
            self._head = chunk
        if chunk.end == self._tail.end and chunk != self._tail:
            self._tail = chunk


def align(pos: int, blksize: int) -> int:
    """
    Align memory address to the right side.
    :param pos: Memory address.
    :param blksize: Memory block size.
    :return: pos if pos is already aligned to blksize, pos+blksize otherwise.
    """
    return (pos // blksize * blksize) + (blksize if pos % blksize != 0 else 0)


def lalign(pos: int, blksize: int) -> int:
    """
    Align memory address to the left side.
    :param pos: Memory address.
    :param blksize: Memory block size.
    :return: pos truncated to align to blksize.
    """
    return pos // blksize * blksize


def uc_perm_to_str(perm: int) -> PermString:
    return ('---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx')[perm]


def guest_type_from_bytes(type_: ArgumentType, bytes_: bytes | bytearray | memoryview) -> GuestScalarValue:
    """
    Convert guest memory values to Python values. Pointers are treated the same as integers.

    Note: Since this function is normally used with something that checks type, it does not mask nor raise an error on
    integer values with mismatching size. That is, for example, passing int32 to type_ and 8 bytes to bytes_ will cause
    this function to return a Python int that's up to 64-bits long.
    :param type_: Guest type.
    :param bytes_: Bytes read from guest memory.
    :return: An integer, floating point number or boolean value representing bytes_ with the type type_, or None when
    type_ is 'void' or invalid.
    """
    if type_ in INT_TYPES:
        return int.from_bytes(bytes_, 'little', signed=True)
    elif type_ in UINT_TYPES:
        return int.from_bytes(bytes_, 'little')
    elif type_ == 'bool':
        return bool(int.from_bytes(bytes_, 'little'))
    elif type_ == 'float':
        return FLOAT_READER.unpack(bytes_)[0]
    elif type_ == 'double':
        return DOUBLE_READER.unpack(bytes_)[0]


def guest_type_to_bytes(type_: ArgumentType, value: float | bool | None) -> bytes | None:
    """
    Convert Python values to guest memory values. Pointers are treated the same as integers.
    :param type_: Guest type.
    :param value: Python value appropriate for the specified guest type.
    :return: Guest memory value in bytes.
    """
    if type_ in INT_TYPES:
        return value.to_bytes(4 * ARG_SIZES[type_], 'little', signed=True)
    elif type_ in UINT_TYPES or type_ == 'bool':
        return value.to_bytes(4 * ARG_SIZES[type_], 'little')
    elif type_ == 'float':
        return FLOAT_READER.pack(value)
    elif type_ == 'double':
        return DOUBLE_READER.pack(value)


def guest_type_to_regs(type_: ArgumentType, value: float | bool | None) -> tuple[int, ...]:
    """
    Convert Python values to guest register values. Pointers are treated the same as integers.
    :param type_: Guest type.
    :param value: Python value appropriate for the specified guest type.
    :return: A tuple of register values in natural order.
    """
    if type_ in INT_TYPES or type_ in UINT_TYPES or type_ == 'bool':
        assert isinstance(value, int)
        if ARG_SIZES[type_] == 1:
            return (value & 0xffffffff,)
        elif ARG_SIZES[type_] == 2:
            return value & 0xffffffff, (value >> 32) & 0xffffffff
    elif type_ == 'float':
        return (int.from_bytes(FLOAT_READER.pack(value), 'little'),)
    elif type_ == 'double':
        value_reg = int.from_bytes(FLOAT_READER.pack(value), 'little')
        return value_reg & 0xffffffff, (value_reg >> 32) & 0xffffffff


class OABIArgReader:
    """
    Parse Arm OABI call arguments.
    """
    _uc: Uc
    _fmt: ArgumentFormat
    _stack_base: int
    _candidate_id: int
    _variadic_base: Optional[int]
    _fixed_args: Optional[tuple[Argument]]

    def __init__(self, uc: Uc, fmt: ArgumentFormat):
        """
        Create the object and parse fixed arguments.
        :param uc: Unicorn context.
        :param fmt: Format list for fixed arguments. Ellipsis ('...') can be used once at the end of the list to enable
        support for variadic arguments.
        """
        if '...' in fmt:
            fmt_no_variadic = fmt[:-1]
            if '...' in fmt_no_variadic:
                raise ValueError('Variadic must be specified at the end of the format.')
            self._variadic_base = 0
        else:
            fmt_no_variadic = fmt
            self._variadic_base = None

        self._uc = uc
        self._fmt = fmt_no_variadic
        self._stack_base = uc.reg_read(UC_ARM_REG_SP)
        self._candidate_id = 0
        self._fixed_args = None

        self._parse_fixed_args()

    def _read_arg(self, arg_type: ArgumentType) -> Argument:
        if arg_type not in VALID_ARGUMENT_TYPES:
            raise ValueError(f'Unknown argument type {repr(arg_type)}.')
        arg_size = ARG_SIZES[arg_type]
        candidates = bytearray()
        while arg_size > 0:
            if self._candidate_id < 4:
                ncrn = ARM_ARG_REGISTERS[self._candidate_id]
                candidates.extend(self._uc.reg_read(ncrn).to_bytes(4, 'little'))
            else:
                nsaa = self._stack_base + 4 * (self._candidate_id - 4)
                candidates.extend(self._uc.mem_read(nsaa, 4))
            arg_size -= 1
            self._candidate_id += 1
        return guest_type_from_bytes(arg_type, candidates)

    def _read_arg_list(self, fmt: ArgumentFormat) -> list[Argument]:
        result: list[Argument] = []
        for i, arg_type in enumerate(fmt):
            try:
                result.append(self._read_arg(arg_type))
            except ValueError as e:
                if e.args[0].startswith('Unknown argument type '):
                    raise ValueError(f'Unknown argument type {repr(arg_type)} for argument {i}.') from e
                else:
                    raise e
        return result

    def _parse_fixed_args(self):
        self._fixed_args = tuple(self._read_arg_list(self._fmt))
        if self._variadic_base is not None:
            self._variadic_base = self._candidate_id

    @property
    def has_variadic(self) -> bool:
        return self._variadic_base is not None

    @property
    def fixed_args(self) -> tuple[Argument]:
        """
        Obtain fixed arguments.
        :return: Fixed arguments.
        """
        assert self._fixed_args is not None
        return self._fixed_args

    def read_variadic(self, arg_type: ArgumentType) -> Argument:
        """
        Read a single variadic argument.
        :param arg_type: Type of the argument.
        :return: The variadic argument.
        """
        return self._read_arg(arg_type)

    def read_variadic_list(self, fmt: ArgumentFormat) -> tuple[Argument]:
        """
        Read a list of variadic arguments.
        :param fmt: Format list for variadic arguments.
        :return: The variadic arguments.
        """
        return tuple(self._read_arg_list(fmt))

    def reset_variadic(self) -> None:
        """
        Resets the variadic reader.
        """
        if not self.has_variadic:
            raise TypeError('Reader does not support variadic arguments.')
        self._candidate_id = self._variadic_base


def parse_oabi_args(fmt: ArgumentFormat, uc: Uc) -> list[Argument]:
    """
    Parse OABI arguments into a dictionary of numbers. Pointers will be stored as integer addresses that can be passed
    to Uc.read_mem() calls.
    APCS reference can be found here:
    https://developer.arm.com/documentation/dui0041/c/ARM-Procedure-Call-Standard/About-the-ARM-Procedure-Call-Standard
    :param fmt: Argument formats list.
    :param uc: Emulator context.
    :return: A dictionary containing parsed results.
    """
    # TODO verify that it's working on values that are split between core register and stack
    parsed_args: list[Argument] = []

    stack_base = uc.reg_read(UC_ARM_REG_SP)
    candidate_id = 0
    for i, arg_type in enumerate(fmt):
        if arg_type not in VALID_ARGUMENT_TYPES:
            raise ValueError(f'Unknown argument type {repr(arg_type)} for argument {i}.')
        arg_size = ARG_SIZES[arg_type]
        candidates = bytearray()
        while arg_size > 0:
            if candidate_id < 4:
                ncrn = ARM_ARG_REGISTERS[candidate_id]
                candidates.extend(uc.reg_read(ncrn).to_bytes(4, 'little'))
            else:
                nsaa = stack_base + 4 * (candidate_id - 4)
                candidates.extend(uc.mem_read(nsaa, 4))
            arg_size -= 1
            candidate_id += 1
        parsed_args.append(guest_type_from_bytes(arg_type, candidates))

    return parsed_args
