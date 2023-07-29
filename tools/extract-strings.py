#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.1.0"
__compatible__ = ((3, 11),)
__doc__ = """
=================
 extract-strings
=================

This script is used to extract the strings from the resource DLLs into an `.ini` file
"""
import argparse
import ctypes
import os
import re
import sys

from pathlib import Path
from typing import Optional
from configparser import RawConfigParser
from functools import cache, partial

eprint = partial(print, file=sys.stderr)

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(f"This script is only compatible with the following Python versions: {', '.join([f'{z[0]}.{z[1]}' for z in __compatible__])}")  # pragma: no cover


def parse_options():
    """\
        Initializes the ArgumentParser and ConfigParser and performs the parsing
    """
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Extract the strings from the resource DLLs")
    parser.add_argument("-d", "--dir", action="store", type=Path, help="Directory where to find '*ui.dll' files for MSVC")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Turn up verbosity to see more details of what is going on.")
    return parser.parse_args()


def get_rsrc_string(hmod: int, strid: int, bufsize: int = 0x1000) -> Optional[str]:
    result = ctypes.c_int(0)
    buf = ctypes.create_unicode_buffer(bufsize)
    result = LoadStringW(hmod, strid, ctypes.byref(buf), bufsize - 1)
    if result in {0}:
        return None
    wstr = ctypes.wstring_at(ctypes.byref(buf), result)  # just in case we hit strings that aren't zero-terminated
    return wstr.rstrip("\x00")


def extract_rsrc_strings(dllpath: Path) -> list:
    hmod = LoadLibraryExW(ctypes.c_wchar_p(str(dllpath)), 0, 0x2)  # LOAD_LIBRARY_AS_DATAFILE
    if hmod in {0, None}:
        eprint(f"ERROR: Failed to load {dllpath}, with last error {ctypes.get_last_error()}")
        return []
    rsrc_strings = []
    for strid in range(0, 0xFFFF):
        wstr = get_rsrc_string(hmod, strid)
        rsrc_strings.append((strid, wstr, ))  # fmt: skip
    if FreeLibrary(hmod) in {0}:  # ERROR_SUCCESS
        eprint(f"WARNING: FreeLibrary() call failed with last error {ctypes.get_last_error()}")
    return rsrc_strings


def main() -> int:
    """\
        Very simply the main entry point to this script
    """
    reslist = RawConfigParser()
    for dllpath in args.dir.rglob("*ui.dll*"):
        eprint(f"INFO: Attempting to extract strings from '{dllpath}'")
        rsrc_strings = extract_rsrc_strings(dllpath)
        scname = f"{dllpath.name}"
        reslist.add_section(scname)
        count = 0
        for strid, wstr in rsrc_strings:
            if wstr:
                count += 1
                reslist.set(scname, f"{strid}", wstr)
        if not count:
            reslist.remove_section(scname)
        else:
            eprint(f"INFO: {dllpath.name} has {count} strings")
    if reslist.sections():
        with open("rsrc_strings.ini", "w", encoding="utf-8", newline="\n") as resfile:
            reslist.write(resfile)
    return 0


if __name__ == "__main__":
    global FreeLibrary
    global LoadLibraryExW
    global LoadStringW
    FreeLibrary = ctypes.windll.kernel32.FreeLibrary
    FreeLibrary.argtypes = [ctypes.c_void_p]
    FreeLibrary.restype = ctypes.c_int32  # 32-bit bool
    LoadLibraryExW = ctypes.windll.kernel32.LoadLibraryExW
    LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    LoadLibraryExW.restype = ctypes.c_void_p
    LoadStringW = ctypes.windll.user32.LoadStringW
    LoadStringW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int32]  # ctypes.c_wchar_p is impractical for arg 3
    LoadStringW.restype = ctypes.c_int32

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
