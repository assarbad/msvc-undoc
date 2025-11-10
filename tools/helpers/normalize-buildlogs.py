#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2024 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.1.2"
__compatible__ = ((3, 11), (3, 12),)  # fmt: skip
__doc__ = """
===============================
 Normalize Build Logs
===============================

This project aims to normalize the LOG_BUILD_COMMANDLINES-generated log files in a way that makes them better comparable
"""
import argparse

import os
import re
import shlex
import sys

from contextlib import redirect_stderr, redirect_stdout
from functools import partial  # also cache
from io import StringIO
from pathlib import Path, PureWindowsPath, WindowsPath

# from pprint import pformat, pprint
from typing import Union

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


def reset_global_lists():
    global common_path_list, common_path
    common_path_list = []
    common_path = None


def detect_common_path() -> bool:
    global common_path_list, common_path
    assert isinstance(common_path_list, list), "common_path_list must be a list of pathlib.Path and str"
    for item in [str(x) for x in common_path_list if Path(x).is_absolute()]:
        eprint(f"{item=}")
    common_path = os.path.commonpath([str(x) for x in common_path_list if Path(x).is_absolute()])
    if common_path:
        eprint(f"DETECTED: {common_path=}")
        return True
    return False


def parse_cl(inp: list[str], collect: bool) -> argparse.Namespace:
    from argparse import ArgumentParser

    ptype = PureWindowsPath if os.name not in {"nt"} else WindowsPath

    cl = ArgumentParser(prog="cl.exe.py", description="Mock parser for cl.exe arguments", add_help=False, prefix_chars="-/", exit_on_error=False)
    cl.add_argument("/I", "-I", dest="includes", type=ptype, action="append")
    cl.add_argument("/D", "-D", dest="defines", type=str, action="append")
    cl.add_argument(dest="files", metavar="FILES", type=ptype, action="append", nargs="*")

    known, unknown = cl.parse_known_args(inp)
    known.unknown = unknown  # attach to the namespace object

    if isinstance(known.files, list) and isinstance(known.files[0], list):
        known.files = known.files[0]  # unwrap outer list

    if ptype in {WindowsPath}:
        known.includes = [x.resolve() for x in known.includes]
        known.files = [x.resolve() for x in known.files]

    if collect:
        global common_path_list
        common_path_list += known.includes
        common_path_list += known.files

    # Check for dupes (case-insensitive)
    if known.includes:
        known.dupe_includes = find_dupes([str(x).lower() for x in known.includes])
    if known.defines:
        known.dupe_defines = find_dupes([str(x).lower() for x in known.defines])
    if known.unknown:
        known.dupe_unknown = find_dupes([x.lower() for x in known.unknown])
    if known.files:
        known.dupe_files = find_dupes([str(x).lower() for x in known.files])
    return known


def parse_link(inp: list[str], collect: bool) -> argparse.Namespace:
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

    if collect:
        global common_path_list
        common_path_list += known.libraries
        common_path_list += known.objects
        common_path_list += known.resources

    return known


def polish_path(inp: Union[str, Path], collect: bool = False) -> str:
    replacements = {  # requires _simple_ strings in the key, as it is used as literal in regexes below
        "Release": "$(Config)",
        "MinSizeRel": "$(Config)",
        "RelWithDebInfo": "$(Config)",
        "Debug": "$(Config)",
        "Checked": "$(Config)",
        "x64": "$(Platform)",
        "Win32": "$(Platform)",
    }
    if isinstance(inp, WindowsPath):
        p = inp.resolve()
    elif isinstance(inp, Path):
        p = inp
    elif isinstance(inp, str):
        p = Path(inp).resolve()
    else:
        assert False, f"We should never ever end up here! {inp=}"
    inp = str(p)
    if collect:
        orig_inp = inp
    for k, v in replacements.items():
        inp = re.sub(r"^%s([/\\])" % (re.escape(k)), r"%s\1" % (v), inp)  # beginning of path
        inp = re.sub(r"([/\\])%s$" % (re.escape(k)), r"\1%s" % (v), inp)  # end of path
        inp = re.sub(r"([/\\])%s([/\\])" % (re.escape(k)), r"\1%s\2" % (v), inp)  # in the middle
    if collect and inp == orig_inp:
        global common_path_list
        common_path_list.append(p)
    return inp


def mutate_lines(inplist: list[str], collect: bool = False) -> list[str]:
    output = []
    for inp in inplist:
        inp = re.sub(r"^.+?\\link\.exe", r"LINK", inp, 0, re.IGNORECASE)
        inp = re.sub(r"^.+?\\lib\.exe", r"LIB", inp, 0, re.IGNORECASE)
        args = custom_split(inp)
        if args[0].upper() in {"CL"}:
            prog = args[0].lower()
            args = parse_cl(args[1:], collect)
            output.append(prog)
            for include in sorted(args.includes, key=lambda x: str(x).lower()):
                output.append(f"\t/I{polish_path(str(include), collect)}")
                if hasattr(args, "dupe_includes") and str(include).lower() in args.dupe_includes:
                    output.append(f"\t# duplicate entry {args.dupe_includes[include.lower()]}")
            for define in sorted(args.defines, key=lambda x: x.lower()):
                output.append(f"\t/D{define}")
                if hasattr(args, "dupe_defines") and define.lower() in args.dupe_defines:
                    output.append(f"\t# duplicate entry {args.dupe_defines[define.lower()]}")
            for tu in sorted(args.files, key=lambda x: str(x).lower()):
                output.append(f"\t{polish_path(tu, collect)}")
                if hasattr(args, "dupe_files") and str(tu).lower() in args.dupe_files:
                    output.append(f"\t# duplicate entry {args.dupe_files[str(tu).lower()]}")
            for option in args.unknown:  # do _not_ sort!
                if option[0:3] in {"/Fo", "/Fd"}:
                    output.append(f"\t{option[0:3]}{polish_path(option[3:], collect)}")
                elif option.lower().startswith("/d1trimfile:"):
                    try:
                        idx = option.index(":")
                        output.append(f"\t{option[0:idx+1]}{polish_path(option[idx+1:], collect)}")
                    except ValueError:
                        output.append(f"\t{option}")
                else:
                    output.append(f"\t{option}")
        elif args[0].upper() in {"LINK", "LIB"}:
            prog = args[0].lower()
            args = parse_link(args[1:], collect)
            output.append(prog)
            for lib in sorted(args.libraries, key=lambda x: x.lower()):
                output.append(f"\t{polish_path(lib, collect)}")
            for obj in sorted(args.objects, key=lambda x: x.lower()):
                output.append(f"\t{polish_path(obj, collect)}")
            for res in sorted(args.resources, key=lambda x: x.lower()):
                output.append(f"\t{polish_path(res, collect)}")
            for option in args.unknown:  # do _not_ sort!
                if option.lower().startswith(
                    (
                        "/out:",
                        "/ilk:",
                        "/pdb:",
                        "/implib:",
                        "/ltcgout:",
                    )
                ):
                    try:
                        idx = option.index(":")
                        output.append(f"\t{option[0:idx+1]}{polish_path(option[idx+1:], collect)}")
                    except ValueError:
                        output.append(f"\t{option}")
                else:
                    output.append(f"\t{option}")
        if args is None and not collect:
            eprint(f"Nothing to parse in: {repr(inp)}")
            continue
    return output


def main() -> int:
    """\
        Very simply the main entry point to this script
    """
    reset_global_lists()
    per_input = {}
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
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            mutate_lines(inlines, True)
        per_input[infile] = mutate_lines(inlines)
    # Summarily detect common path prefix
    have_common_prefix = detect_common_path()
    for infile, newlines in per_input.items():
        with open(Path(infile).with_suffix(".normalized.log"), "w") as outp:
            if have_common_prefix:  # blindly replace
                global common_path
                assert common_path is not None, f"Somehow {common_path=}. It is expected to have a value at this point."
                newlines = [x.replace(common_path, "$(CommonPathPrefix)") for x in newlines]
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
