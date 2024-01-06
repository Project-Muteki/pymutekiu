from typing import TYPE_CHECKING, Optional, cast, NamedTuple
from collections.abc import Iterator
from weakref import ProxyType

import logging
import struct

from unicorn import (
    Uc,
    UC_PROT_READ,
    UC_PROT_WRITE,
)

from .. import utils
from .errno import GuestOSError, ErrnoNamespace, ErrnoCauseKernel

if TYPE_CHECKING:
    from .states import OSStates

_logger = logging.getLogger('heap')

MemChunk = struct.Struct('<2I')


class Heap:
    """
    HLE guest heap implementation.
    """
    _uc: Uc
    _states: ProxyType['OSStates']
    _min_alloc_unit: int
    _max_alloc: int
    _trace: bool

    _heap_base: int
    _heap_end: int

    class _ParsedHeader(NamedTuple):
        """
        Parsed memory chunk header.
        """
        this_chunk: int
        prev_chunk: int
        next_chunk: int
        size: int
        occupied: bool

        @classmethod
        def from_offset_bytes(cls, offset: int, bytes_: bytes | bytearray | memoryview) -> 'Heap._ParsedHeader':
            """
            Create object from offset and raw header on guest memory.
            :param offset: Offset of this chunk. Used for calculating size.
            :param bytes_: Raw header data read from guest memory. Must be exactly 8 bytes long.
            :return: Created object.
            """
            prev_chunk, next_tail = cast(tuple[int, int], MemChunk.unpack(bytes_))
            occupied = bool(next_tail & 1)
            next_chunk = next_tail & (~1)
            size = next_chunk - offset
            return cls(offset, prev_chunk, next_chunk, size, occupied)

        def to_bytes(self,
                     new_prev_chunk: Optional[int] = None,
                     new_next_chunk: Optional[int] = None,
                     new_occupied: Optional[bool] = None) -> bytes:
            """
            Convert an object to bytes ready to be written to the guest memory. Optionally replace certain fields
            before writing.
            :param new_prev_chunk: New pointer for previous chunk.
            :param new_next_chunk: New pointer for next chunk.
            :param new_occupied: New state for whether this chunk is occupied or not.
            :return: The memory chunk header in raw format.
            """
            prev_chunk = new_prev_chunk if new_prev_chunk is not None else self.prev_chunk
            next_chunk = new_next_chunk if new_next_chunk is not None else self.next_chunk
            occupied = new_occupied if new_occupied is not None else self.occupied

            return MemChunk.pack(prev_chunk, next_chunk | occupied)

    def __init__(self, uc: Uc, states: ProxyType['OSStates'], min_alloc_unit: int, max_alloc: int, trace: bool = False):
        self._uc = uc
        self._states = states
        self._min_alloc_unit = min_alloc_unit
        self._max_alloc = max_alloc
        self._trace = trace

        self._heap_base = self._states.loader.main_module.mem_range[1]
        self._heap_end = self._heap_base
        self._heap_tail = 0

        self._grow()

    def _grow(self) -> None:
        """
        Map extra memory pages onto the heap.
        """
        self._uc.mem_map(self._heap_end, self._min_alloc_unit, UC_PROT_READ | UC_PROT_WRITE)
        # TODO actually grow the heap by rewriting the chunk tail (using self._heap_tail)
        new_heap_end = self._heap_end + self._min_alloc_unit
        new_heap_tail = self._heap_end - 8
        ...

        self._heap_end = new_heap_end
        self._heap_tail = new_heap_tail

    def _enumerate_chunk(self, continue_from: Optional[int] = None) -> Iterator['Heap._ParsedHeader']:
        """
        Iterate over and parse the memory chunks allocated on the heap.
        :param continue_from: Start from this offset instead of the beginning.
        :return: An iterator of parsed headers.
        """
        current_chunk_offset = continue_from if continue_from is not None else self._heap_base
        while True:
            header = self._read_and_parse_chunk(current_chunk_offset)
            if header.next_chunk == 0:
                break
            yield header
            current_chunk_offset = header.next_chunk

    def _read_and_parse_chunk(self, addr: int) -> 'Heap._ParsedHeader':
        """
        Read and parse a single memory chunk at guest memory address addr.
        :param addr: A guest pointer pointing to a memory chunk header.
        :return: Parsed header object.
        """
        return self._ParsedHeader.from_offset_bytes(
            addr,
            self._uc.mem_read(addr, 8),
        )

    def malloc(self, size: int) -> int:
        """
        Allocate memory on guest heap.
        :param size: Size of memory.
        :return: Guest pointer to allocated memory.
        """
        actual_size = utils.align(size, 4)
        for chunk in self._enumerate_chunk():
            if chunk.occupied:
                continue

            if chunk.size >= actual_size:
                leftover_chunk_offset = chunk.this_chunk + actual_size
                other_chunk = self._read_and_parse_chunk(chunk.next_chunk)

                # Update the chunk that got spliced. Next chunk will now be the newly created chunk made of leftover
                # space. Previous chunk stay unchanged.
                self._uc.mem_write(chunk.this_chunk, chunk.to_bytes(
                    new_next_chunk=leftover_chunk_offset,
                    new_occupied=True,
                ))
                # For the newly created chunk, previous chunk is the original chunk that got
                # spliced. Next chunk is unchanged (i.e. still the other chunk).
                self._uc.mem_write(leftover_chunk_offset, chunk.to_bytes(
                    new_prev_chunk=chunk.this_chunk,
                ))
                # Link the other chunk to the newly created chunk.
                self._uc.mem_write(other_chunk.this_chunk, other_chunk.to_bytes(
                    new_prev_chunk=leftover_chunk_offset,
                ))

                # Account for header
                return chunk.this_chunk + 8

        # TODO handle heap growth
        _logger.error('Heap out of memory.')
        raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.SYS_OUT_OF_MEMORY)

    def calloc(self, size: int, nmemb: int) -> int:
        """
        Allocate and clear memory on guest heap.
        :param size: Size of each member.
        :param nmemb: Size of memory in number of members.
        :return: Guest pointer to allocated memory.
        """
        if size * nmemb >= 1 << 32:
            _logger.error('Integer overflow detected in calloc().')
            raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.SYS_OUT_OF_MEMORY)

        addr = self.malloc(size * nmemb)
        self._uc.mem_write(addr, b'\x00' * size * nmemb)
        return addr

    def realloc(self, addr: int, size: int) -> int:
        """
        Allocate new memory and copy over data.
        :param addr: Address to allocated guest memory.
        :param size: Size of new ly allocated guest memory.
        :return: The new guest pointer.
        """
        orig_data: bytes

        if addr != 0:
            chunk_addr = addr - 8
            header = self._read_and_parse_chunk(chunk_addr)
            orig_data_size = min(header.size, size)
            orig_data = self._uc.mem_read(addr, orig_data_size)
        else:
            orig_data = b''

        new_data = self.malloc(size)
        self._uc.mem_write(new_data, orig_data)
        self.free(addr)

        return new_data

    def free(self, addr: int) -> None:
        """
        Free a previously allocated guest memory.
        :param addr: Guest pointer to allocated memory
        """
        chunk_addr = addr - 8
        header = self._read_and_parse_chunk(chunk_addr)
        self._uc.mem_write(chunk_addr, header.to_bytes(new_occupied=False))
