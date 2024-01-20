from typing import TYPE_CHECKING, cast

import weakref

if TYPE_CHECKING:
    from unittest import TestCase


class MockUnicornMemoryAccessor:
    """
    Simple mock side effect for Uc.mem_read()
    """
    _parent: 'TestCase'
    _content: bytes
    _base: int

    def __init__(self, parent: 'TestCase', content: bytes, base: int):
        self._parent = cast('TestCase', weakref.proxy(parent))
        self._content = content
        self._base = base

    def __call__(self, addr: int, size: int) -> bytes:
        offset = addr - self._base
        if offset + size > len(self._content):
            # TODO have a way to handle actual intentional OOB memory access
            self._parent.fail(f'Access of non-mocked memory at address {addr:#x} size {size}.')
        return self._content[offset:offset + size]


class MockUnicornRegAccessor:
    """
    Simple mock side effect for Uc.reg_read()
    """
    _parent: 'TestCase'
    _regs: dict[int, int]

    def __init__(self, parent: 'TestCase', regs: dict[int, int]):
        self._parent = cast('TestCase', weakref.proxy(parent))
        self._regs = regs

    def __call__(self, reg: int) -> int:
        if reg not in self._regs:
            self._parent.fail(f'Access of non-mocked register {reg}. Refer to unicorn module for details.')
        return self._regs[reg]
