from typing import TYPE_CHECKING, cast

import weakref

from .threading import Scheduler
from .loader import Loader
from .heap import Heap
from .ui.event import EventBroker, InputTracker

import pygame

if TYPE_CHECKING:
    from unicorn import Uc
    from pathlib import Path
    from argparse import Namespace


class OSStates:
    """
    Operating system state tracker class. Keeps track on loaded code and runtime states like scheduler and memory
    allocation. It also provides access to states for its children.
    """
    _uc: 'Uc'
    config: 'Namespace'

    sched: Scheduler
    loader: Loader
    heap: Heap
    ui_event: EventBroker

    def __init__(self, uc: 'Uc', main_applet_path: 'str | Path', config: 'Namespace'):
        """
        Initialize the object and its children.
        :param uc: Unicorn context.
        :param main_applet_path: Main applet executable. It will be loaded to the corresponding memory address
        **without** relocation and be used to determine memory layout and emulator entry point.
        """
        self._uc = uc
        self.config = config

        # HACK: Cast away the ProxyType here. weakref.ProxyType[OSStates] for these components currently are typed
        # simply as OSStates because typing spec does not yet allow object wrapping.
        self.sched = Scheduler(self._uc, cast('OSStates', weakref.proxy(self)))
        self.loader = Loader(self._uc, cast('OSStates', weakref.proxy(self)))
        # Load main applet. Must be done before heap initialization.
        self.loader.load(main_applet_path)
        self.heap = Heap(
            self._uc,
            cast('OSStates', weakref.proxy(self)),
            config.min_heap_unit,
            config.max_heap_size,
            config.heap_trace,
        )

        pygame.init()
        pygame.display.set_mode(config.lcd_resolution)

        self.ui_event = EventBroker(self._uc, cast('OSStates', weakref.proxy(self)))
        self.ui_input_tracker = InputTracker(self._uc, cast('OSStates', weakref.proxy(self)))
