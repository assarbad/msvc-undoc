#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2024 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.1.1"
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


def find_dupes(inp: list[str]) -> dict:
    if len(inp) > len(set(inp)):
        count_dict = {}
        for item in inp:
            count_dict[item] = count_dict.get(item, 0) + 1
        return {k: v for k, v in count_dict.items() if v > 2}
    return {}


def parse_cl(inp: list[str]) -> argparse.Namespace:
    from argparse import ArgumentParser

    cl = ArgumentParser(prog="cl.exe.py", description="Mock parser for cl.exe arguments", add_help=False, prefix_chars="-/", exit_on_error=False)
    cl.add_argument("/I", "-I", dest="includes", type=PureWindowsPath, action="append")
    cl.add_argument("/D", "-D", dest="defines", type=str, action="append")
    cl.add_argument(dest="files", metavar="FILES", action="append", nargs="*")

    known, unknown = cl.parse_known_args(inp)
    known.unknown = unknown  # attach to the namespace object

    # Check for dupes (case-insensitive)
    if known.includes:
        known.dupe_includes = find_dupes([str(x).lower() for x in known.includes])
    if known.defines:
        known.dupe_defines = find_dupes([str(x).lower() for x in known.defines])
    if known.unknown:
        known.dupe_unknown = find_dupes([x.lower() for x in known.unknown])
    return known


def parse_link(inp: list[str]) -> argparse.Namespace:
    from argparse import ArgumentParser

    link = ArgumentParser(prog="link.exe.py", description="Mock parser for link.exe arguments", add_help=False, prefix_chars="-/", exit_on_error=False)

    known, unknown = link.parse_known_args(inp)

    known.libraries = [x for x in unknown if x[0] not in {"-", "/"} and x.lower().endswith(".lib")]
    seen = {}
    seen = set(known.libraries)

    unknown = [x for x in unknown if x not in seen]  # Exclude previously seen items
    known.objects = [x for x in unknown if x[0] not in {"-", "/"} and x.lower().endswith(".obj")]
    seen.update(set(known.objects))

    unknown = [x for x in unknown if x not in seen]  # Exclude previously seen items
    known.resources = [x for x in unknown if x[0] not in {"-", "/"} and x.lower().endswith(".res")]
    seen.update(set(known.resources))

    unknown = [x for x in unknown if x not in seen]  # Exclude previously seen items
    known.unknown = unknown  # attach to the namespace object

    return known


# TODO: perhaps refactor this further to get rid of minor path differences (e.g. Debug vs. Release)?
def mutate_lines(inplist: list[str]) -> list[str]:
    output = []
    for inp in inplist:
        inp = re.sub(r"^.+?\\link\.exe", r"LINK", inp, 0, re.IGNORECASE)
        args = custom_split(inp)
        if args[0].upper() in {"CL"}:
            prog = args[0].lower()
            args = parse_cl(args[1:])
            output.append(prog)
            for include in sorted(args.includes, key=lambda x: str(x).lower()):
                output.append(f"\t/I{include}")
            for define in sorted(args.defines, key=lambda x: x.lower()):
                output.append(f"\t/D{define}")
            if isinstance(args.files[0], list):
                for tu in sorted(args.files[0], key=lambda x: x.lower()):
                    output.append(f"\t{tu}")
            elif isinstance(args.files[0], str):
                for tu in sorted(args.files, key=lambda x: x.lower()):
                    output.append(f"\t{tu}")
            else:
                eprint(f"ERROR: invalid args.files: {repr(args.files)}")
            for option in args.unknown:  # do _not_ sort!
                output.append(f"\t{option}")
        elif args[0].upper() in {"LINK"}:
            prog = args[0].lower()
            args = parse_link(args[1:])
            output.append(prog)
            for lib in sorted(args.libraries, key=lambda x: x.lower()):
                output.append(f"\t{lib}")
            for obj in sorted(args.objects, key=lambda x: x.lower()):
                output.append(f"\t{obj}")
            for res in sorted(args.resources, key=lambda x: x.lower()):
                output.append(f"\t{res}")
            for option in args.unknown:  # do _not_ sort!
                output.append(f"\t{option}")
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
                    # special case: e.g. link got called again with automatically modified argument (i.e. invoking itself again)
                    if inlines and inlines[-1] in line:
                        inlines[-1] = line
                    else:
                        inlines.append(line)

        if not inlines:
            eprint("No lines were read, so skipping output")
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
