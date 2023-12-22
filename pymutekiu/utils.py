import dataclasses
from typing import (
    Sequence,
    Literal,
    Optional,
    TYPE_CHECKING,
)

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
ArgumentFormat = Sequence[ArgumentType]

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

    def add(self, pages: int) -> int:
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
                    allocated_chunk = self.MemPageChunk(chunk.start, pages, True)
                    new_chunk = self.MemPageChunk(chunk.start + pages, chunk.end, True)
                    self._map[allocated_chunk.start] = self._map_tail[allocated_chunk.end] = allocated_chunk
                    self._map[new_chunk.start] = self._map_tail[new_chunk.end] = new_chunk
                    # If splicing the tail chunk, update the new tail
                    if chunk.start == self._tail.start:
                        self._tail = new_chunk
                    break
            else:
                chunk = self._map.get(chunk.end)

        # end of chunk
        if allocated_chunk is None:
            if pages > (self._limit - self._tail.end):
                raise ValueError('No space left for new allocation.')
            allocated_chunk = self.MemPageChunk(chunk.end, chunk.end + pages, True)
            self._map[allocated_chunk.start] = self._map_tail[allocated_chunk.end] = allocated_chunk
            self._tail = allocated_chunk

        return allocated_chunk.start

    def remove(self, addr: int):
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
    return (pos // blksize * blksize) + (blksize if pos % blksize != 0 else 0)


def lalign(pos: int, blksize: int) -> int:
    return pos // blksize * blksize


def lpadding(pos: int, blksize: int) -> int:
    return pos - (pos // blksize * blksize)


def uc_perm_to_str(perm: int) -> PermString:
    return ('---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx')[perm]


def guest_type_from_bytes(type_: ArgumentType, bytes_: bytes | bytearray | memoryview) -> float | bool | None:
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
    if type_ in INT_TYPES:
        return value.to_bytes(4 * ARG_SIZES[type_], 'little', signed=True)
    elif type_ in UINT_TYPES or type_ == 'bool':
        return value.to_bytes(4 * ARG_SIZES[type_], 'little')
    elif type_ == 'float':
        return FLOAT_READER.pack(value)
    elif type_ == 'double':
        return DOUBLE_READER.pack(value)


def guest_type_to_regs(type_: ArgumentType, value: float | bool | None) -> tuple[int, ...]:
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


def parse_oabi_args(fmt: ArgumentFormat, uc: Uc) -> list[Optional[float]]:
    '''
    Parse OABI arguments into a dictionary of numbers. Pointers will be stored as integer addresses that can be passed
    to Uc.read_mem() calls.
    :param fmt: Argument formats list.
    :param uc: Emulator context.
    :return: A dictionary containing parsed results.
    '''
    # TODO verify that it's working on values that are split between core register and stack
    parsed_args: list[Optional[float]] = []

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
        parsed_args.append(guest_type_from_bytes(arg_type, candidates))

    return parsed_args
