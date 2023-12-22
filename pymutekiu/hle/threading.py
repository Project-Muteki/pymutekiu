from typing import TYPE_CHECKING, Optional
from weakref import ProxyType

import logging

from unicorn import (
    Uc,
    UC_PROT_READ,
    UC_PROT_WRITE,
)

from .. import utils

if TYPE_CHECKING:
    from .states import OSStates

_logger = logging.getLogger('threading')


class Scheduler:
    STACK_BASE = 0xff000000
    STACK_LIMIT = 8*1024*1024

    def __init__(self, uc: Uc, states: ProxyType['OSStates']):
        self._uc = uc
        self._states = states
        self._flags = 0
        self._stack_page_allocator = utils.MemPageTracker(self.STACK_LIMIT)

    def new_thread(self, func: int, user_data: Optional[int] = None, stack_size: int = 0x8000):
        if stack_size % 4096 != 0:
            _logger.warning('Stack size is not a multiple of minimum page size.')
            stack_size = utils.align(stack_size, 4096)

        # Allocate thread stack on target memory
        # Add extra 1 page as guard page. This page will be unmapped and will only be seen by the allocator.
        page_offset = self._stack_page_allocator.add(stack_size + 4096)
        stack_bottom = self.STACK_BASE - page_offset
        stack_top = stack_bottom - stack_size
        _logger.debug('Mapping stack memory pages @ %#010x, size %#x', stack_top, stack_size)
        self._uc.mem_map(stack_top, stack_size, UC_PROT_READ | UC_PROT_WRITE)

        # Allocate the thread descriptor on target heap.
        #thr = self._states.heap.malloc(...)
        # TODO make a thread descriptor viewer object here
        #self._uc.mem_write(thr, ...)

    def yield_from_svc(self):
        self._uc.emu_stop()

    def tick(self):
        #self._uc.emu_start(..., 0, timeout=10000)
        ...
