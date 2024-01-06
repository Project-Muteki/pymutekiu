from typing import TYPE_CHECKING

import weakref

from . import (
    threading,
    loader,
    heap,
)

from unicorn import Uc


class OSStates:
    _uc: Uc
    sched: threading.Scheduler
    loader: loader.Loader
    heap: heap.Heap

    def __init__(self, uc: Uc):
        self._uc = uc
        self.sched = threading.Scheduler(self._uc, weakref.proxy(self))
        self.loader = loader.Loader(self._uc, weakref.proxy(self))
        # TODO allow user to change optional configs
        self.heap = heap.Heap(self._uc, weakref.proxy(self), 2*1024*1024, 32*1024*1024)
