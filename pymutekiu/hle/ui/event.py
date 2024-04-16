from typing import (
    Callable,
    TypeVar,
    Optional,
    Self,
    cast,
    TYPE_CHECKING,
)

import dataclasses
import inspect
import logging
import time

from collections import deque
from enum import IntEnum, auto
from itertools import batched

if TYPE_CHECKING:
    from unicorn import Uc
    from ..states import OSStates


class EventType(IntEnum):
    CLEARED = 0
    TOUCH_BEGIN = 1
    TOUCH_MOVE = 2
    TOUCH_END = 8
    KEY = 16


@dataclasses.dataclass
class Event:
    recipient: int = 0
    type_: int = 0
    value: int = 0
    ptr_0xc: int = 0
    ptr_0x10: int = 0
    ptr_0x14: int = 0

    @classmethod
    def new_key_event(cls, key0: int, key1: Optional[int] = None) -> Self:
        result = cls(type_=EventType.KEY)
        result.set_value_as_vec2((key0, key1))
        return result

    def set_value_as_vec2(self, values: tuple[Optional[int], Optional[int]]) -> None:
        if values[0] is None and values[1] is None:
            return
        elif values[0] is None:
            self.value &= 0x0000ffff
            self.value |= (values[1] & 0xffff) << 16
        elif values[1] is None:
            self.value &= 0xffff0000
            self.value |= (values[0] & 0xffff)
        else:
            self.value = ((values[1] << 16) | values[0]) & 0xffffffff


class EventBroker:
    _uc: 'Uc'
    _states: 'OSStates'
    _queue: deque[Event]

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._queue = deque()

    def enqueue(self, event: Event) -> None:
        self._queue.append(event)

    def enqueue_key_event(self, key0: int, key1: Optional[int] = None) -> None:
        self.enqueue(Event.new_key_event(key0, key1))


class InputTracker:
    _uc: 'Uc'
    _states: 'OSStates'
    shift: bool
    caps: bool
    long_press_delay: float
    long_press_repeat_rate: float
    _current_holding_keys: dict[int, float]
    _last_update: float

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states

        self.shift = False
        self.caps = False
        self.long_press_delay = 1.25
        self.long_press_repeat_rate = 0.075
        self._current_holding_keys = {}
        self._last_update = time.monotonic()

    def on_pygame_keyup(self, pygame_keycode):
        ...

    def on_pygame_keydown(self, pygame_keycode):
        ...

    def tick(self):
        current_time = time.monotonic()
        elapsed_time = current_time - self._last_update
        self._last_update = current_time

        next_holding = {}
        next_key_events = []
        for k, v in self._current_holding_keys.items():
            v -= elapsed_time
            if v <= 0:
                next_key_events.append(k)
                v = self.long_press_repeat_rate
            next_holding[k] = v
        self._current_holding_keys.update(next_holding)

        for event_double in batched(next_key_events, 2):
            self._states.ui_event.enqueue_key_event(*event_double)
