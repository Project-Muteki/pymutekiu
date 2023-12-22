from typing import TYPE_CHECKING

import weakref

from . import (
    threading,
    loader,
)

from unicorn import Uc


class OSStates:
    _uc: Uc
    sched: threading.Scheduler
    loader: loader.Loader

    def __init__(self, uc: Uc):
        self._uc = uc
        self.sched = threading.Scheduler(self._uc, weakref.proxy(self))
        self.loader = loader.Loader(self._uc, weakref.proxy(self))
