from typing import TYPE_CHECKING, Optional, cast, NamedTuple
from collections.abc import Iterator

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
    _states: 'OSStates'
    _min_alloc_unit: int
    _max_alloc: int
    _trace: bool

    _heap_base: int
    _heap_end: int
    _heap_tail: int

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

    def __init__(self, uc: Uc, states: 'OSStates', min_alloc_unit: int, max_alloc: int, trace: bool = False):
        if min_alloc_unit % 4096 != 0:
            _logger.warning("Minimum allocation unit is not aligned to page size. Padding to the nearest page.")
            min_alloc_unit = utils.align(min_alloc_unit, 4096)
        if max_alloc % 4096 != 0:
            _logger.warning("Maximum allocation size is not aligned to page size. Padding to the nearest page.")
            min_alloc_unit = utils.align(min_alloc_unit, 4096)

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
        if self._max_alloc <= self.committed_pages:
            _logger.error('Heap out of memory.')
            raise GuestOSError(ErrnoNamespace.KERNEL, ErrnoCauseKernel.SYS_OUT_OF_MEMORY)

        alloc_unit = min(self._min_alloc_unit, self.free_pages)

        self._uc.mem_map(self._heap_end, alloc_unit, UC_PROT_READ | UC_PROT_WRITE)

        new_heap_end = self._heap_end + alloc_unit
        new_heap_tail = new_heap_end - 8

        if self._heap_tail == 0:
            # Unformatted heap, format it.
            self._uc.mem_write(self._heap_base, struct.pack('<2I', 0, new_heap_tail))
            self._uc.mem_write(new_heap_tail, struct.pack('<2I', self._heap_base, 0))
        else:
            # Update last real chunk and relocate the heap tail
            tail_chunk = self._read_and_parse_chunk(self._heap_tail)
            last_real_chunk = self._read_and_parse_chunk(tail_chunk.prev_chunk)

            self._uc.mem_write(last_real_chunk.this_chunk, last_real_chunk.to_bytes(new_next_chunk=new_heap_tail))
            self._uc.mem_write(new_heap_tail, tail_chunk.to_bytes())

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

    def _find_chunk(self, size: int) -> Iterator[Optional[int]]:
        """
        Keep retrying to find a free chunk indefinitely.
        :param size: Size requested.
        :return: An iterator that yields None when no allocation possible, or the address of the allocated chunk.
        """
        assert size % 4 == 0, 'Size must be multiple of 4.'
        chunk = None
        while True:
            prev_tail = chunk.this_chunk if chunk is not None else None
            for chunk in self._enumerate_chunk(prev_tail):
                if chunk.occupied:
                    continue

                if chunk.size >= size:
                    leftover_chunk_offset = chunk.this_chunk + 8 + size
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
                    yield chunk.this_chunk + 8
            yield None

    @property
    def committed_pages(self) -> int:
        """
        Number of committed pages.
        :return: Number of committed pages.
        """
        return self._heap_end - self._heap_base

    @property
    def free_pages(self) -> int:
        """
        Number of uncommitted pages.
        :return: Number of uncommitted pages.
        """
        return self._max_alloc - (self._heap_end - self._heap_base)

    def get_free_space(self) -> int:
        """
        Calculate unoccupied memory space.

        This simply adds the size of all the unoccupied memory chunks (minus the header overhead) to estimate how much
        memory is potentially allocatable on the heap. Note that if the heap is heavily fragmented, allocation may fail
        even when the amount of free space reported here is more than the amount requested.
        :return: Free space in bytes.
        """
        return sum(c.size - 8 for c in self._enumerate_chunk() if not c.occupied) + self.free_pages

    def malloc(self, size: int) -> int:
        """
        Allocate memory on guest heap.
        :param size: Size of memory.
        :return: Guest pointer to allocated memory.
        """
        actual_size = utils.align(size, 4)
        for allocated in self._find_chunk(actual_size):
            if allocated is None:
                # Not enough pages committed. Try to commit more pages before trying again.
                self._grow()
            else:
                # Allocated.
                return allocated
        raise RuntimeError('_find_chunk terminates unexpectedly.')

    def calloc(self, nmemb: int, size: int) -> int:
        """
        Allocate and clear memory on guest heap.
        :param nmemb: Size of memory in number of members.
        :param size: Size of each member.
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
            orig_data = bytes(self._uc.mem_read(addr, orig_data_size))
        else:
            orig_data = b''

        new_data = self.malloc(size)
        self._uc.mem_write(new_data, orig_data)
        self.free(addr)

        return new_data

    def free(self, addr: int) -> None:
        """
        Free a previously allocated guest memory and merge adjacent free chunks.
        :param addr: Guest pointer to allocated memory
        """
        chunk_addr = addr - 8
        header = self._read_and_parse_chunk(chunk_addr)
        prev_chunk = self._read_and_parse_chunk(header.prev_chunk) if header.prev_chunk != 0 else None
        next_chunk = self._read_and_parse_chunk(header.next_chunk) if header.next_chunk != 0 else None

        new_prev_chunk = header.prev_chunk
        new_chunk = header.this_chunk
        new_next_chunk = header.next_chunk
        chunk_layout_changed = False

        if prev_chunk is not None and not prev_chunk.occupied:
            # We need to overwrite previous chunk instead since it will be consumed
            new_chunk = prev_chunk.this_chunk
            chunk_layout_changed = True
            # Previous chunk of the will-be current chunk is the previous chunk of the previous chunk
            # (merging previous chunk into current chunk)
            new_prev_chunk = prev_chunk.prev_chunk
        if next_chunk is not None and not next_chunk.occupied:
            # Next chunk of the will-be current chunk will be the next chunk of the next chunk
            # (merging next chunk into current chunk)
            new_next_chunk = next_chunk.next_chunk
            chunk_layout_changed = True
        self._uc.mem_write(new_chunk, header.to_bytes(
            new_prev_chunk=new_prev_chunk,
            new_next_chunk=new_next_chunk,
            new_occupied=False,
        ))
        if chunk_layout_changed:
            # Fix link on the next chunk
            next_chunk = self._read_and_parse_chunk(new_next_chunk)
            self._uc.mem_write(new_next_chunk, next_chunk.to_bytes(
                new_prev_chunk=new_chunk,
            ))
