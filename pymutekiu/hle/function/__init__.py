import logging

from ...utils import GuestRequestHandler
from .common import HLEFunctionModule


_logger = logging.getLogger('syscall')


class HLEFunctionHandler(GuestRequestHandler[int]):
    def request_key_to_str(self, req_key: int) -> str:
        # TODO this is kind of ugly. Maybe update the GuestRequestHandler spec so we resolve the name from there?
        #  For syscalls we can still override it since syscalls currently have no name or ordinal attached to them.
        #  This will likely stay the same except that entries in syscall modules will likely have empty names (or
        #  better: somehow pulling names from data) and auto-assigned ordinals to keep compatibility.
        #  This also means we will no longer need a "syscall forwarder" handler for sdklib/krnllib importing since
        #  syscall modules can by then be indexed and effectively concatenated by a thin wrapper and such wrapper should
        #  then just work as a normal HLE function handler with almost no extra code or data required.
        module = self._table.get(req_key)
        if isinstance(module, HLEFunctionModule):
            sdef = module.get_definition(req_key)
            export_name = sdef.name if sdef.name is not None else f'#{sdef.ordinal}'
            return f'<hlefunc {type(module).__name__} {export_name}>'
        return f'<hlefunc {req_key:#010x}>'
