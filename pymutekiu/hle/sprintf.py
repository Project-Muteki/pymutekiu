from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..utils import OABIArgReader


def vsprintf(fmt: str, ap: 'OABIArgReader'):
    start_offset = 0
    while start_offset < len(fmt):
        end_offset = fmt.find('%', start_offset)
        if end_offset == -1:
            end_offset = len(fmt)
        a = fmt[start_offset:end_offset]
