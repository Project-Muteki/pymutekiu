from typing import (
    Callable,
    TypeVar,
    ClassVar,
    Optional,
    cast,
    TYPE_CHECKING,
)

from dataclasses import dataclass, field
import copy
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


_logger = logging.getLogger('hlefunc')


@dataclass
class HLEFunctionDefinition:
    _order_hint_counter: ClassVar[int] = 0

    ret: ArgumentType
    args: ArgumentFormat
    name: Optional[str] = None
    ordinal: Optional[int] = None
    order_hint: int = field(default=0, init=False)

    def __post_init__(self):
        self.order_hint = self._order_hint_counter
        self._order_hint_counter += 1

    def __call__(self, f: 'GuestFunction') -> 'GuestFunction':
        setattr(f, 'fcndef', self)
        return f


fcndef = HLEFunctionDefinition


class HLEFunctionModule:
    """
    GuestModule-compatible HLE function call handler.

    Handler methods created using the decorator by `@fcndef(...)` will be automatically indexed by the constructor and
    converted to a GuestCallback.
    """
    _uc: 'Uc'
    _states: 'OSStates'
    _table: dict[int, GuestCallback]
    "GuestCallback index with mapped address as the key."
    _names: dict[str, int]
    "Mapped address index with callback export names as the key."
    _ordinals: dict[int, int]
    "Mapped address index with callback export ordinals as the key."
    _entries: dict[int, HLEFunctionDefinition]
    "Index of HLEFunctionDefinition of the callbacks with mapped address as the key."
    _base: int
    "Module base address."

    def __init__(self, uc: 'Uc', states: 'OSStates', base: int):
        self._uc = uc
        self._states = states
        self._table = {}
        self._names = {}
        self._ordinals = {}
        self._entries = {}
        self._base = base

        all_handlers: list[tuple[HLEFunctionDefinition, GuestCallback]] = []
        for name, handler in inspect.getmembers(self, lambda x: inspect.ismethod(x) and hasattr(x, 'fcndef')):
            sdef = cast(HLEFunctionDefinition, getattr(handler, 'fcndef'))
            cb = GuestCallback(
                callback=cast('GuestFunction', handler),
                return_type=sdef.ret,
                arg_types=sdef.args,
            )
            all_handlers.append((sdef, cb))

        default_ordinal = 0
        for sdef, cb in sorted(all_handlers, key=lambda item: item[0].order_hint):
            if sdef.ordinal is None:
                ordinal = default_ordinal
            else:
                ordinal = default_ordinal = sdef.ordinal
            default_ordinal += 1

            handler_address = base + ordinal * 4
            if handler_address in self._table:
                raise TypeError(f'Ordinal conflict between callback '
                                f'{repr(cb.__name__)} and {repr(self._table[handler_address].__name__)} '
                                f'(both have ordinal #{ordinal}).')

            # Index callback and metadata based on address the handler has been mapped to.
            self._table[handler_address] = cb
            self._entries[handler_address] = copy.deepcopy(sdef)
            self._entries[handler_address].ordinal = ordinal

            # Index the handler address based on ordinal and optionally export names, so we can link them later.
            if sdef.name is not None:
                self._names[sdef.name] = handler_address
            self._ordinals[ordinal] = handler_address

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
            return
        return callback.respond_to(self._uc)

    @property
    def base(self) -> int:
        return self._base

    def sizeof(self) -> int:
        return (max(self._ordinals) + 1) * 4

    def export(self, *, name: Optional[str] = None, ordinal: Optional[int] = None) -> int:
        if name is None and ordinal is None:
            raise ValueError('One of name or ordinal must be specified.')

        # Look up by both
        result_by_name: Optional[int] = None
        result_by_ordinal: Optional[int] = None
        if ordinal is not None:
            result_by_ordinal = self._ordinals.get(ordinal)
        if name is not None:
            result_by_name = self._names.get(name)

        # Decide which value to return.
        if result_by_name is not None and result_by_ordinal is not None:
            if result_by_name != result_by_ordinal:
                raise LookupError('Conflicting lookup results between name and ordinal.')
            return result_by_name
        if result_by_name is not None:
            return result_by_name
        if result_by_ordinal is not None:
            return result_by_ordinal
        raise LookupError('Entry not found. Cannot export.')

    def get_definition(self, req_key: int) -> HLEFunctionDefinition:
        return self._entries[req_key]
