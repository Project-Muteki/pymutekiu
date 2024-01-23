from typing import TYPE_CHECKING, cast

import weakref

from .threading import Scheduler
from .loader import Loader
from .heap import Heap

if TYPE_CHECKING:
    from unicorn import Uc


class OSStates:
    _uc: 'Uc'
    sched: Scheduler
    loader: Loader
    heap: Heap

    def __init__(self, uc: 'Uc'):
        self._uc = uc
        # HACK: Cast away the ProxyType here. weakref.ProxyType[OSStates] for these components currently are typed
        # simply as OSStates because typing spec does not yet allow object wrapping.
        self.sched = Scheduler(self._uc, cast('OSStates', weakref.proxy(self)))
        self.loader = Loader(self._uc, cast('OSStates', weakref.proxy(self)))
        # TODO allow user to change optional configs
        self.heap = Heap(self._uc, cast('OSStates', weakref.proxy(self)), 2*1024*1024, 32*1024*1024)
