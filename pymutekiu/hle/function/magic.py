import logging

from .common import fcndef, HLEFunctionModule

_logger = logging.getLogger('function.magic')


class Magic(HLEFunctionModule):
    """
    Magic functions that are supposed to be mapped at `0xfffff000`.
    """
    @fcndef('int', ['int'], name='__exit')
    def on_magic_exit(self, exit_code: int) -> int:
        thr = self._states.sched.current_thread
        _logger.info('Thread %#010x exiting through magic exit with code %d.', thr, exit_code)
        self._states.sched.delete_thread(thr)
        return 0
