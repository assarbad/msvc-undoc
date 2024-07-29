#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2024 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.1.0"
__compatible__ = ((3, 11), (3, 12),)  # fmt: skip
__doc__ = """
===============================
 Normalize Build Logs
===============================

This project aims to normalize the LOG_BUILD_COMMANDLINES-generated log files in a way that makes them better comparable
"""
import argparse

# import os
import re
import shlex
import sys

from functools import partial  # also cache
from pathlib import Path, PureWindowsPath
from os.path import commonprefix

# from pprint import pformat, pprint
# from typing import Optional

eprint = partial(print, file=sys.stderr)

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(f"This script is only compatible with the following Python versions: {', '.join([f'{z[0]}.{z[1]}' for z in __compatible__])}")  # pragma: no cover


def parse_options() -> argparse.Namespace:
    """\
        Initializes the ArgumentParser and performs the parsing
    """
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="This project aims to normalize the LOG_BUILD_COMMANDLINES-generated log files in a way that makes them better comparable", add_help=False
    )
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    parser.add_argument("--nologo", action="store_const", dest="nologo", const=True, help="Don't show info about this script.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Turn up verbosity to see more details of what is going on.")
    parser.add_argument("inputs", metavar="FILES", nargs="+")
    return parser.parse_args()


def custom_split(inp: str) -> list[str]:
    lexer = shlex.shlex(inp, posix=True)
    lexer.escape = ""  # Disable escape character handling
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(map(lambda x: x[1:-1] if x[0:1] in {"'", '"'} and x[0:1] == x[-1:1] else x, list(lexer)))


def parse_cl(inp: list[str]) -> (argparse.Namespace, list[str]):
    from argparse import ArgumentParser

    cl = ArgumentParser(prog="cl.exe.py", description="Mock parser for cl.exe arguments", add_help=False, prefix_chars="-/", exit_on_error=False)
    cl.add_argument("/I", "-I", dest="includes", type=PureWindowsPath, action="append")
    cl.add_argument("/D", "-D", dest="defines", type=str, action="append")
    cl.add_argument(dest="files", metavar="FILES", action="append", nargs="*")

    known, unknown = cl.parse_known_args(inp)
    return known, unknown


def parse_link(inp: list[str]) -> argparse.Namespace:
    from argparse import ArgumentParser

    link = ArgumentParser(prog="link.exe.py", description="Mock parser for link.exe arguments", add_help=False, prefix_chars="-/", exit_on_error=False)

    return link.parse_args(inp)


def mutate_lines(inplist: list[str]) -> list[str]:
    output = []
    for inp in inplist:
        inp = re.sub(r"^.+?\\link\.exe", r"LINK", inp, 0, re.IGNORECASE)
        args = custom_split(inp)
        if args[0].upper() in {"CL"}:
            prog = args[0].lower()
            known, unknown = parse_cl(args[1:])
            output.append(prog)
            for include in sorted(known.includes):
                output.append(f"\t/I{include}")
            for define in sorted(known.defines):
                output.append(f"\t/D{define}")
            eprint(repr(known.files))
            if isinstance(known.files[0], list):
                eprint("Assuming list of list of strings")
                for tu in sorted(known.files[0]):
                    output.append(f"\t{tu}")
            elif isinstance(known.files[0], str):
                eprint("Assuming list of strings")
                for tu in sorted(known.files):
                    output.append(f"\t{tu}")
            else:
                eprint(f"ERROR: invalid known.files: {repr(known.files)}")
            for option in unknown:  # do _not_ sort!
                output.append(f"\t{option}")
        # elif args[0].upper() in {"LINK"}:
        #     prog = args[0].lower()
        #     known, unknown = parse_link(args[1:])
        #     output.append(prog)
        if args is None:
            eprint(f"Nothing to parse in: {repr(inp)}")
            continue
    return output


def main() -> int:
    """\
        Very simply the main entry point to this script
    """
    for infile in args.inputs:
        inlines = []
        with open(infile, "r") as inp:
            for line in inp.readlines():
                line = line.strip()
                if line not in inlines:
                    inlines.append(line)
        if not inlines:
            eprint(f"No lines were read, so skipping output")
            continue
        newlines = mutate_lines(inlines)
        with open(Path(infile).with_suffix(".normalized.log"), "w") as outp:
            for line in newlines:
                print(line, file=outp)
    return 0


if __name__ == "__main__":
    global args
    args = parse_options()
    try:
        sys.exit(main())
    except SystemExit:
        pass
    except ImportError:
        raise  # re-raise
    except RuntimeError:
        raise  # re-raise
    except Exception:
        eprint(__doc__)
        raise  # re-raise
