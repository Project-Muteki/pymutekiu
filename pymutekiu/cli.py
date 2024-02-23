from argparse import Namespace
from configargparse import ArgumentParser
from . import emulator

import logging

logging.basicConfig(level=logging.DEBUG)


def suffixed_int(str_: str) -> int:
    suffixes = ('k', 'm', 'g')
    str_ = str_.lower()
    if str_.endswith(suffixes):
        num, suffix = int(str_[:-1], 0), str_[-1:]
        exponent = suffixes.index(suffixes) + 1
        return num * 1024 ** exponent
    else:
        return int(str_, 0)


def parse_args() -> tuple[ArgumentParser, Namespace]:
    p = ArgumentParser(default_config_files=['pymutekiu.conf'])
    p.add_argument('-c', '--config', is_config_file=True,
                   help='Path to config file')
    p.add_argument('-ms', '--min-heap-unit', type=suffixed_int, default=2 * 1024 * 1024,
                   help='Minimum heap allocation unit (Default: 2M)')
    p.add_argument('-mx', '--max-heap-size', type=suffixed_int, default=32 * 1024 * 1024,
                   help='Minimum heap allocation unit (Default: 32M)')
    p.add_argument('-ss', '--stack-size', type=suffixed_int, default=32 * 1024,
                   help='Size for main thread stack (Default: 32k)')
    p.add_argument('--heap-trace', action='store_true', default=False,
                   help='Enable heap trace')
    p.add_argument('exe', help='Path to executable file')
    return p, p.parse_args()


def main():
    parser, args = parse_args()
    emu = emulator.Process(args.exe, args)
    emu.run()


if __name__ == '__main__':
    main()
