from typing import cast
import json
import importlib.resources as resources

_SYSCALL_NAME_RESOURCES = (
    'syscalls_sdk.json',
    'syscalls_sdk_hpprime.json',
    'syscalls_krnl.json',
    'syscalls_krnl_hpprime.json',
)


def _load_syscall_names() -> dict[int, str]:
    res = resources.files()
    result: dict[int, str] = {}
    for res_name in _SYSCALL_NAME_RESOURCES:
        with res.joinpath(res_name).open('r') as f:
            names = {int(k, 0): v for k, v in cast(dict[str, str], json.load(f)).items()}
            result.update(names)
    return result


SYSCALL_NAMES = _load_syscall_names()
