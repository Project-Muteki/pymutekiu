from argparse import ArgumentParser, Namespace
from . import emulator

import logging

logging.basicConfig(level=logging.DEBUG)


def parse_args() -> tuple[ArgumentParser, Namespace]:
    p = ArgumentParser()
    p.add_argument('exe', help='Executable file')
    return p, p.parse_args()


def main():
    parser, args = parse_args()
    emu = emulator.Process(args.exe)
    emu.run()

if __name__ == '__main__':
    main()
