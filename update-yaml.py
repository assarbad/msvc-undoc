#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.2"
__compatible__ = ((3, 11),)
__doc__ = """
=============
 update-yaml
=============

Small script to do my bidding regarding the YAML-based file containing command line switches
and their properties.
"""
import argparse  # noqa: F401
import os
import re
import sys
import yaml
from contextlib import suppress
from functools import cache
from pathlib import Path
from pprint import pformat, pprint  # noqa: F401

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(
        "This script is only compatible with the following Python versions: %s." % (", ".join(["%d.%d" % (z[0], z[1]) for z in __compatible__]))
    )  # pragma: no cover


def parse_args():
    """ """
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Update YAML with command line switch descriptions")
    parser.add_argument("--nologo", action="store_const", dest="nologo", const=True, help="Don't show info about this script.")
    parser.add_argument("-n", "--dryrun", "--dry-run", action="store_true", help="Won't actually change the YAML file")
    parser.add_argument("-Y", "--yaml", action="store", type=Path, help="YAML file to work with")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Turn up verbosity to see more details of what is going on. Use several v to increase the verbosity level, e.g. '-vvv'.",  # noqa: E501
    )
    return parser.parse_args()


@cache
def read_link_docs(fname):
    docs = {}
    reobj = re.compile(r"^\|\s+?\[`(/[^`]+)`\]\(([^\)]+)\)\s+?\|\s+(.+?)\s+?\|$")
    with open(fname, "r") as docfile:
        lines = [line.strip() for line in docfile.readlines()]
        for line in lines:
            match = reobj.search(line)
            if match:
                realname = match.group(1).lower()
                markdown = match.group(2).strip()
                purpose = match.group(3).strip()
                parts = markdown.rpartition(".")
                if parts[2] in {"md"}:
                    markdown = parts[0]
                assert realname not in docs, f"{realname} already in docs dict!"
                docs[realname] = {}
                docs[realname]["markdown"] = markdown
                docs[realname]["purpose"] = purpose
    assert docs, "docs dict appears to be empty?!"
    return docs


def get_switch_traits(realname):
    fname = Path(__file__).absolute().parent / "cpp-docs/docs/build/reference/linker-options.md"
    docs = read_link_docs(fname)
    return docs[realname] if realname in docs else {}


def process_link_cmd(data):
    assert "cmdline" in data
    cmdline = data["cmdline"]
    both = set()
    newcmdline = {}
    documented = set()
    with open("linkexe_documented.txt", "r") as docs:
        documented = {line.strip() for line in docs.readlines()}
    for switch, values in cmdline.items():
        newcmdline[switch] = {} if values is None else values
        realname = f"/{switch}"
        has_doc = realname in documented
        both.add(realname)
        newcmdline[switch]["realname"] = realname if "realname" not in cmdline[switch] else cmdline[switch]["realname"]
        newcmdline[switch]["documented"] = has_doc if "documented" not in cmdline[switch] else cmdline[switch]["documented"]
        # newcmdline[switch]["researched"] = False if not has_doc and "researched" not in cmdline[switch] else cmdline[switch]["researched"]
        if has_doc:
            traits = get_switch_traits(realname)
            purpose, moniker = None, None
            if traits:
                assert "markdown" in traits, f"The 'markdown' key was missing from {traits=}"
                assert "purpose" in traits, f"The 'purpose' key was missing from {traits=}"
                purpose = traits["purpose"] if "purpose" in traits else ""
                moniker = traits["markdown"] if "markdown" in traits else ""
            if "purpose" not in cmdline[switch]:
                if purpose:
                    newcmdline[switch]["purpose"] = purpose
            else:
                newcmdline[switch]["purpose"] = cmdline[switch]["purpose"]
            if "msdocs-moniker" not in cmdline[switch]:
                if moniker:
                    newcmdline[switch]["msdocs-moniker"] = moniker
            else:
                newcmdline[switch]["msdocs-moniker"] = cmdline[switch]["msdocs-moniker"]
    data["cmdline"] = newcmdline
    print(f"link.exe: {len(both)} switches, {len(documented)} documented, {len(both - documented)} undocumented", file=sys.stderr)
    return data


def main(**kwargs):
    """ """
    inname = kwargs.get("yaml")
    data = None
    with open(inname, "r") as yamlfile:
        data = yaml.safe_load(stream=yamlfile)
    assert "msvc" in data, "Missing top-level element"
    assert "link" in data["msvc"], "Missing top-level element"
    linkcmd = process_link_cmd(data["msvc"]["link"])
    # pprint(linkcmd)
    data["msvc"]["link"] = linkcmd
    outname = inname
    if kwargs.get("dryrun", False):
        outname = inname.with_suffix(f".dryrun{inname.suffix}")
        print(f"DRY RUN: writing into {str(outname)}", file=sys.stderr)
    else:
        with suppress(FileNotFoundError):
            from_name = outname
            to_name = outname.with_suffix(f".backup{outname.suffix}")
            print(f"Backing up original file '{str(from_name)}' to '{str(to_name)}'", file=sys.stderr)
            os.rename(from_name, to_name)
    with open(outname, "w") as yamlout:
        yaml.safe_dump(data, stream=yamlout, explicit_start=True)
    # https://matthewpburruss.com/post/yaml/
    return 0


if __name__ == "__main__":
    args = parse_args()
    try:
        sys.exit(main(**vars(args)))
    except SystemExit:
        pass
    except ImportError:
        raise  # re-raise
    except RuntimeError:
        raise  # re-raise
    except Exception:
        print(__doc__)
        raise  # re-raise
