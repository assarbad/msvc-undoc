#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.1"
__compatible__ = ((3, 11),)
__doc__ = """
=============
 update-docs
=============

    Small script to do update the documentation based on Jinja2 templates.
"""
import argparse

# import os
# import re
import sys
import yaml

# from contextlib import suppress
# from copy import deepcopy
from functools import partial
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# from pprint import pformat, pprint

eprint = partial(print, file=sys.stderr)

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(f"This script is only compatible with the following Python versions: {', '.join([f'{z[0]}.{z[1]}' for z in __compatible__])}")  # pragma: no cover

CONFIG_DEFAULTS = """
[msvc.yaml]
path = %(thisdir)s/../msvc.yaml

[docs]
outdir = %(thisdir)s/..
"""


def parse_options() -> argparse.Namespace:
    """\
        Initializes the ArgumentParser and ConfigParser and performs the parsing
    """
    from argparse import ArgumentParser
    from configparser import ConfigParser
    from textwrap import dedent

    cfgname = Path(__file__).absolute().parent / "msvc-undoc.ini"
    cfg = ConfigParser(defaults={"thisdir": cfgname.parent}, delimiters=("=",))
    cfg.read_string(dedent(CONFIG_DEFAULTS), "<DEFAULTS>")

    parser = ArgumentParser(description="Update docs from templates, based on data from the YAML", add_help=False)
    # Only add the configuration file argument for starters
    parser.add_argument("-c", "--config", "--ini", action="store", default=cfgname, metavar="CFG", type=Path, help=f"The config file; defaults to {cfgname}")
    partial_args = parser.parse_known_args()[0]
    cfg.read(partial_args.config)

    # Remaining command line options
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    parser.add_argument("--nologo", action="store_const", dest="nologo", const=True, help="Don't show info about this script.")
    parser.add_argument("-Y", "--yaml", action="store", default=cfg.get("msvc.yaml", "path"), type=Path, help="YAML file to work with")
    parser.add_argument("-i", "--input", action="store", required=True, type=Path, help="Input Jinja2 template")
    parser.add_argument("-d", "--outdir", "--output-directory", default=cfg.get("docs", "outdir"), action="store", type=Path, help="Input Jinja2 template")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Turn up verbosity to see more details of what is going on.")
    return cfg, parser.parse_args()


def main() -> int:
    """\
        Very simply the main entry point to this script
    """
    inname = args.yaml
    data = None
    with open(inname, "r") as yamlfile:
        data = yaml.safe_load(stream=yamlfile)
    assert "meta" in data, "Missing top-level element 'meta'"
    assert "msvc" in data, "Missing top-level element 'msvc'"
    assert "link" in data["msvc"], "Missing second-level element 'link' inside 'msvc'"
    j2tmpl = args.input.absolute()
    j2ldr = FileSystemLoader(searchpath=j2tmpl.parent)
    j2env = Environment(loader=j2ldr)
    template = j2env.get_template(str(j2tmpl.name))
    with open(args.input.absolute().with_suffix(""), "w") as outfile:
        print(template.render(), file=outfile)
    return 0


if __name__ == "__main__":
    global args
    global cfg
    cfg, args = parse_options()
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
