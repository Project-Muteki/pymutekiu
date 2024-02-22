from typing import (
    Callable,
    TypeVar,
    Optional,
    cast,
    TYPE_CHECKING,
)

import dataclasses
import inspect
import logging

from ...utils import (
    ArgumentFormat,
    ArgumentType,
    GuestCallback,
)

if TYPE_CHECKING:
    from unicorn import Uc
    from ..states import OSStates
    from ...utils import RespondToCoroutine, GuestFunction


_logger = logging.getLogger('syscall')


@dataclasses.dataclass
class SyscallDefinition:
    num: int
    ret: ArgumentType
    args: ArgumentFormat

    def __call__(self, f: 'GuestFunction') -> 'GuestFunction':
        setattr(f, 'syscalldef', self)
        return f


syscalldef = SyscallDefinition


class SyscallModule:
    _uc: 'Uc'
    _states: 'OSStates'
    _table: dict[int, GuestCallback]

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._table = {}
        for name, handler in inspect.getmembers(self, lambda x: inspect.ismethod(x) and hasattr(x, 'syscalldef')):
            sdef = cast(SyscallDefinition, getattr(handler, 'syscalldef'))
            self._table[sdef.num] = GuestCallback(
                callback=cast('GuestFunction', handler),
                return_type=sdef.ret,
                arg_types=sdef.args,
            )

    @property
    def available_keys(self) -> set[int]:
        return set(self._table)

    def process(self, key: int) -> 'Optional[RespondToCoroutine]':
        callback = self._table.get(key)
        if callback is None:
            return
        return callback.respond_to(self._uc)
