from typing import (
    Type,
    TYPE_CHECKING,
)

import logging

from ...utils import GuestRequestHandler
from ...data import SYSCALL_NAMES
from .common import SyscallModule

from .memory import Memory
from .threading import Threading

if TYPE_CHECKING:
    from unicorn import Uc
    from ..states import OSStates


_logger = logging.getLogger('syscall')


class SyscallHandler(GuestRequestHandler[int]):
    ENABLED_MODULES: tuple[Type[SyscallModule]] = tuple([
       Memory,
       Threading,
    ])

    def __init__(self, uc: 'Uc', states: 'OSStates'):
        super().__init__(uc, states)
        for module_class in self.ENABLED_MODULES:
            self.register_guest_module(module_class(uc, states))

    def request_key_to_str(self, req_key: int) -> str:
        syscall_name = SYSCALL_NAMES.get(req_key, f'{req_key:#x}')
        return f'<syscall {syscall_name}>'
