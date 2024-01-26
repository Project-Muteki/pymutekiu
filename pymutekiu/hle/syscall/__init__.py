import dataclasses
from typing import (
    Any,
    NamedTuple,
    Callable,
    TypeVar,
    Optional,
    cast,
    TYPE_CHECKING,
)

import logging
import inspect

from ...utils import (
    ArgumentFormat,
    ArgumentType,
    parse_oabi_args,
    guest_type_to_regs,
    OABIArgReader,
)
from ..errno import GuestOSError

if TYPE_CHECKING:
    from ..states import OSStates


from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
)
from unicorn import Uc
import wrapt

_logger = logging.getLogger('syscall')


class SyscallCallback(NamedTuple):
    num: int
    name: str
    callback: Callable[..., float | None]
    return_type: ArgumentType
    arg_types: ArgumentFormat


_CB = SyscallCallback


_T = TypeVar('_T', bound=Callable[..., Optional[float]])


@dataclasses.dataclass
class SyscallDefinition:
    num: int
    ret: ArgumentType
    args: ArgumentFormat

    def __call__(self, f: _T) -> _T:
        setattr(f, 'syscalldef', self)
        return f


syscalldef = SyscallDefinition


class SyscallSubHandler:
    uc: Uc
    states: 'OSStates'
    table: dict[int, SyscallCallback]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self.uc = uc
        self.states = states
        self.table = {}
        for name, handler in inspect.getmembers(self, lambda x: inspect.ismethod(x) and hasattr(x, 'syscalldef')):
            sdef = cast(SyscallDefinition, getattr(handler, 'syscalldef'))
            self.table[sdef.num] = SyscallCallback(
                num=sdef.num,
                name=name,
                callback=cast(Callable[..., Optional[float]], handler),
                return_type=sdef.ret,
                arg_types=sdef.args,
            )

    @property
    def allowed_syscalls(self) -> set[int]:
        return set(self.table)

    def process_svc(self):
        svc_offset = self.uc.reg_read(UC_ARM_REG_PC) - 4
        syscall_no = int.from_bytes(self.uc.mem_read(svc_offset, 4), 'little') & 0xffffff

        # Recover from syscall state to prepare for returning
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        lr = int.from_bytes(self.uc.mem_read(sp, 4), 'little')
        r0 = int.from_bytes(self.uc.mem_read(sp + 4, 4), 'little')
        self.uc.reg_write(UC_ARM_REG_R0, r0)
        # We want the HLE syscall to still see everything, so set lr here instead of directly setting pc
        self.uc.reg_write(UC_ARM_REG_LR, lr)
        self.uc.reg_write(UC_ARM_REG_SP, sp + 8)

        syscall_callback = self.table.get(syscall_no)
        if syscall_callback is None:
            _logger.error('Unhandled syscall %#x.', syscall_no)
            # Set pc to prevent crashing. It's probably gonna crash later due to wrong return values but at least we got
            # it logged.
            self.uc.reg_write(UC_ARM_REG_PC, lr)
            return

        reader = OABIArgReader(self.uc, syscall_callback.arg_types)
        if not reader.has_variadic:
            syscall_ret = syscall_callback.callback(*reader.fixed_args)
        else:
            syscall_ret = syscall_callback.callback(*reader.fixed_args, reader)

        # HLE syscall finished. It's now safe to set pc.
        self.uc.reg_write(UC_ARM_REG_PC, lr)
        if syscall_callback.return_type == 'void':
            return

        # Convert and write return value.
        # TODO handle composite type.
        syscall_ret_regs = guest_type_to_regs(syscall_callback.return_type, syscall_ret)

        self.uc.reg_write(UC_ARM_REG_R0, syscall_ret_regs[0])
        if len(syscall_ret_regs) >= 2:
            self.uc.reg_write(UC_ARM_REG_R1, syscall_ret_regs[1])
        if len(syscall_ret_regs) > 2:
            _logger.warning('syscall_ret_regs has leftover. This should not have happened.')


class SyscallHandler:
    _uc: Uc
    _states: 'OSStates'
    _syscall_table: dict[int, SyscallCallback]

    def __init__(self, uc: Uc, states: 'OSStates'):
        self._uc = uc
        self._states = states
        self._syscall_table = {
            0x10000: _CB(self._OSCreateThread, 'pointer', ['pointer', 'pointer', 'uint32', 'bool']),
            0x10119: _CB(self._GetCurrentPathA, 'pointer', []),
        }

    def process_svc(self):
        svc_offset = self._uc.reg_read(UC_ARM_REG_PC) - 4
        syscall_no = int.from_bytes(self._uc.mem_read(svc_offset, 4), 'little') & 0xffffff

        # Recover from syscall state to prepare for returning
        sp = self._uc.reg_read(UC_ARM_REG_SP)
        lr = int.from_bytes(self._uc.mem_read(sp, 4), 'little')
        r0 = int.from_bytes(self._uc.mem_read(sp + 4, 4), 'little')
        self._uc.reg_write(UC_ARM_REG_R0, r0)
        # We want the HLE syscall to still see everything, so set lr here instead of directly setting pc
        self._uc.reg_write(UC_ARM_REG_LR, lr)
        self._uc.reg_write(UC_ARM_REG_SP, sp + 8)

        syscall_callback = self._syscall_table.get(syscall_no)
        if syscall_callback is None:
            _logger.error('Unhandled syscall %#x.', syscall_no)
            # Set pc to prevent crashing. It's probably gonna crash later but at least we got it logged.
            self._uc.reg_write(UC_ARM_REG_PC, lr)
            return

        syscall_ret = syscall_callback.callback(*parse_oabi_args(syscall_callback.arg_types, self._uc))

        # HLE syscall finished. It's now safe to set pc.
        self._uc.reg_write(UC_ARM_REG_PC, lr)
        if syscall_callback.return_type == 'void':
            return

        # Convert and write return value.
        # TODO handle composite type.
        syscall_ret_regs = guest_type_to_regs(syscall_callback.return_type, syscall_ret)

        self._uc.reg_write(UC_ARM_REG_R0, syscall_ret_regs[0])
        if len(syscall_ret_regs) >= 2:
            self._uc.reg_write(UC_ARM_REG_R1, syscall_ret_regs[1])
        if len(syscall_ret_regs) > 2:
            _logger.warning('syscall_ret_regs has leftover. This should not have happened.')


    def _OSCreateThread(self, func: int, user_data: int, stack_size: int, defer_start: bool) -> int:
        try:
            thr = self._states.sched.new_thread(func, user_data, stack_size)
            if not defer_start:
                self._states.sched.schedule(thr)
        except GuestOSError as err:
            self._states.sched.set_errno(err.errno)
            return 0
        return thr

    def _GetCurrentPathA(self) -> int:
        return 0
