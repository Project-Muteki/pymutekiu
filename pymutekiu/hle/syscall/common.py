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
    """
    GuestModule-compatible syscall handler.

    Handler methods created using the decorator by @syscalldef(...) will be automatically indexed by the constructor and
    converted to a GuestCallback.
    """
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
        """All keys supported by this module."""
        return set(self._table)

    def process(self, key: int) -> 'Optional[RespondToCoroutine]':
        """
        Look up a certain request by key and create a coroutine for the found handler.
        :param key: Key that corresponds to the handler.
        :return: A GuestCallback coroutine object instantiated from the handler, or None if the handler does not exist.
        """
        callback = self._table.get(key)
        if callback is None:
            return None
        return callback.respond_to(self._uc)
