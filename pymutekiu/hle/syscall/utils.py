from typing import TYPE_CHECKING
import logging

from .common import syscalldef, SyscallModule
from ..errno import GuestOSError, ErrnoNamespace, ErrnoCauseUser
from ..sprintf import vsprintf
from ...utils import read_nul_terminated_string

if TYPE_CHECKING:
    from ...utils import OABIArgReader

_logger = logging.getLogger('syscall.utils')


class Utils(SyscallModule):
    @syscalldef(0x102a1, 'void', ['pointer', '...'])
    def on_write_com_debug_msg(self, fmt_p: int, reader: 'OABIArgReader'):
        fmt = read_nul_terminated_string(self._uc, fmt_p)
        _logger.info('WriteComDebugMsg(): %s', vsprintf(fmt.decode('utf-8'), reader))
