from typing import (
    Optional,
    TYPE_CHECKING,
)

from weakref import ProxyType

from dataclasses import dataclass
import logging
import pathlib

from unicorn import (
    Uc,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
)
from pefile import PE

from .. import utils

if TYPE_CHECKING:
    from .states import OSStates

_logger = logging.getLogger('loader')


@dataclass
class LoadedSection:
    '''
    Represent a section of a loaded module within the emulated memory space.
    '''
    name: str
    addr: int
    size: int
    perm: int

    @property
    def perm_hr(self) -> utils.PermString:
        return utils.uc_perm_to_str(self.perm)

    @property
    def mem_range(self) -> tuple[int, int]:
        return self.addr, self.addr + self.size


@dataclass
class LoadedModule:
    '''
    Represent a loaded module within the emulated memory space.
    '''
    name: str
    addr: int
    size: int
    sections: list[LoadedSection]

    @property
    def mem_range(self) -> tuple[int, int]:
        return self.addr, self.addr + self.size


@dataclass
class MainModule:
    module: LoadedModule
    entry_point: int


class Loader:
    SHARED_MODULE_LOAD_BASE = 0x80000000
    _uc: Uc
    _states: ProxyType['OSStates']
    _modules: list[LoadedModule]
    _main_module: Optional[MainModule]
    _shared_module_load_offset: int

    def __init__(self, uc: Uc, _states: ProxyType['OSStates']):
        self._uc = uc
        self._states = _states
        self._modules = []
        self._main_module = None
        self._shared_module_load_offset = self.SHARED_MODULE_LOAD_BASE

    def _load_hle_module(self, name: str, at: Optional[int] = None, push: bool = False):
        ...

    def _load_module(self, image: PE, name: str, at: Optional[int] = None, push: bool = False):
        if image.OPTIONAL_HEADER.SectionAlignment % 4096 != 0:
            raise ValueError('Loaded PE file not aligned to 4k pages.')
        salign = image.OPTIONAL_HEADER.SectionAlignment
        if push:
            # Push module to the memory with the bottom located at _misc_module_load_offset
            # TODO is there a way to calculate this without actually generating all the data?
            backoff = utils.align(len(image.get_memory_mapped_image()), 4096)
            image_base = self._shared_module_load_offset - backoff
            data = image.get_memory_mapped_image(ImageBase=image_base)
        elif at is not None:
            data = image.get_memory_mapped_image(ImageBase=at)
            image_base = at
        else:
            data = image.get_memory_mapped_image()
            image_base = image.OPTIONAL_HEADER.ImageBase

        sections: list[LoadedSection] = []

        for section in image.sections:
            try:
                section_name_str = section.Name.rstrip(b'\x00').decode('ascii')
            except UnicodeDecodeError:
                section_name_str = ''

            addr = image_base + section.VirtualAddress_adj
            perm = UC_PROT_READ if section.IMAGE_SCN_MEM_READ else 0
            perm |= UC_PROT_WRITE if section.IMAGE_SCN_MEM_WRITE else 0
            perm |= UC_PROT_EXEC if section.IMAGE_SCN_MEM_EXECUTE else 0
            if perm == 0:
                continue

            mapped_size = section.next_section_virtual_address - section.section_min_addr \
                if section.next_section_virtual_address is not None \
                else utils.align(section.section_max_addr - section.section_min_addr, salign)
            sections.append(LoadedSection(
                name=section_name_str,
                addr=addr,
                size=mapped_size,
                perm=perm,
            ))

        # Actually map the module
        mem_size = utils.align(len(data), 4096)
        metadata = LoadedModule(name=name, addr=image_base, size=mem_size, sections=sections)

        _logger.debug('mmap for "%s" @ %#010x, memsize %#010x', metadata.name, metadata.addr, mem_size)
        self._uc.mem_map(metadata.addr, mem_size, UC_PROT_NONE)
        self._uc.mem_write(metadata.addr, data)
        for section in metadata.sections:
            _logger.debug('mprotect %#010x bytes @ %#010x as %s', section.size, section.addr,
                          utils.uc_perm_to_str(section.perm))
            self._uc.mem_protect(section.addr, section.size, section.perm)

        if push:
            self._shared_module_load_offset = image_base
        return metadata

    def load(self, image_file: str | pathlib.Path) -> None:
        """
        Load a module to the emulator.
        :param image_file: Non-VFS path to an image file.
        """
        image_file = pathlib.Path(image_file)

        # TODO resolve DLLs

        with PE(name=str(image_file)) as image:
            # Load main executable image
            if image.is_exe and self._main_module is None:
                main_module = self._load_module(image, image_file.name)
                ep = image.OPTIONAL_HEADER.ImageBase + image.OPTIONAL_HEADER.AddressOfEntryPoint
                self._main_module = MainModule(module=main_module, entry_point=ep)
                self._modules.append(main_module)
                _logger.debug('Main executable %s loaded. EP: %#010x', repr(image_file.name), ep)
            else:
                module = self._load_module(image, image_file.name, push=True)
                self._modules.append(module)
                _logger.debug('Extra module %s loaded @ %#010x', repr(image_file.name), module.addr)

    @property
    def entry_point(self) -> int:
        if self._main_module is None:
            raise AttributeError('Entry point not defined. Perhaps you forgot to load top executable?')
        return self._main_module.entry_point

    @property
    def main_module(self) -> LoadedModule:
        if self._main_module is None:
            raise AttributeError('Entry point not defined. Perhaps you forgot to load top executable?')
        return self._main_module.module
