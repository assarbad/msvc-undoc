#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.3.1"
__compatible__ = ((3, 11),)
__doc__ = """
=============
 update-yaml
=============

Small script to do my bidding regarding the YAML-based file containing command line switches
and their properties.
"""
import argparse
import os
import re
import sys
import yaml
from contextlib import suppress
from copy import deepcopy
from functools import cache, partial
from pathlib import Path
from pprint import pformat, pprint  # noqa: F401
from typing import Optional

eprint = partial(print, file=sys.stderr)

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(
        "This script is only compatible with the following Python versions: %s." % (", ".join(["%d.%d" % (z[0], z[1]) for z in __compatible__]))
    )  # pragma: no cover


def parse_args() -> argparse.Namespace:
    """\
        Initializes the argument parser and performs the parsing
    """
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
def read_link_msdocs(fname: Path) -> dict:
    """\
        Tries to parse a single Markdown file from https://github.com/MicrosoftDocs/cpp-docs.git to extract the link.exe switches and their purpose
    """
    docs = {}
    with suppress(FileNotFoundError):
        with open(fname, "r") as docfile:
            reobj = re.compile(r"^\|\s+?\[`(/.+)`\]\(([^\)]+)\)\s+?\|\s+(.+?)\s+?\|$")
            lines = [line.strip() for line in docfile.readlines()]
            for line in lines:
                match = reobj.search(line)
                if match:
                    realnames = match.group(1).lower()
                    markdown = match.group(2).strip()
                    purpose = match.group(3).strip()
                    parts = markdown.rpartition(".")
                    if parts[2] in {"md"}:
                        markdown = parts[0]
                    if r"`" in realnames or "," in realnames:
                        realnames = realnames.replace("`", "").replace(" ", "")
                        realnames = realnames.split(",")
                    else:
                        realnames = [realnames]
                    for realname in realnames:
                        assert realname not in docs, f"{realname} already in docs dict!"
                        docs[realname] = {}
                        docs[realname]["markdown"] = markdown
                        docs[realname]["purpose"] = purpose
        assert docs, "docs dict appears to be empty?! ... that's rather unexpected"
    return docs


def get_linkexe_switch_traits_msdocs(realname: str) -> dict:
    """\
        Attempts to find a link.exe switch by its real name and locate it in cpp-docs, then extract purpose and the moniker to the online documentation

        The returned hash is either the following, or an empty hash:
            {"markdown": "<a moniker>", "purpose": "<purpose as per msdocs>" }
    """
    # TODO: move that as configurable item into the YAML file
    fname = Path(__file__).absolute().parent / "cpp-docs/docs/build/reference/linker-options.md"
    docs = read_link_msdocs(fname)
    if not docs:
        eprint(f"WARNING: '{realname}' failed to retrieve details from local cpp-docs clone. Respective info won't be updated!")
    return docs[realname] if realname in docs else {}


@cache
def read_uri_geoffchappellcom() -> dict:
    """\
        Given a local mirror of geoffchappell.com, this function tries to extract relative URIs to the documentation of individual switches

        Returns a hash keyed on the real name of the link.exe switch
    """
    # TODO: move that as configurable item into the YAML file
    parentdir = Path(__file__).absolute().parent / "msvc"
    parentdir = parentdir.resolve()
    # TODO: move that as configurable item into the YAML file
    linkdir = parentdir / "link"
    switchre = re.compile(r'<span\s+?class="switch">(/[^<]+?)</span>')
    arefre = re.compile(r'<a\s+?href="([^"]+?)">(/[^<]+?)</a>')
    lines = []
    switches = {}
    for html in linkdir.rglob("*.htm*"):
        with open(html, "r") as htmlfile:
            for line in htmlfile.readlines():
                lines.append(line.strip())
                m = switchre.search(line)
                if m:
                    key = m.group(1).lower().rpartition(":")[0] or m.group(1).lower()
                    if key and key not in switches:
                        switches[key] = None

    for line in lines:
        m = arefre.search(line)
        if m:
            uri = html.parent / m.group(1)
            key = m.group(2).lower().rpartition(":")[0] or m.group(2).lower()
            if key and (key not in switches or switches[key] is None):
                switches[key] = f"gc.link://{uri.resolve().relative_to(linkdir)}"
    return {switch: uri for switch, uri in switches.items() if uri is not None}


@cache
def get_switch_uri_geoffchappellcom(realname: str) -> Optional[str]:
    """\
        Retrieves the URI relative to geoffchappell_baseurl in the YAML
    """
    docs = read_uri_geoffchappellcom()
    if not docs:
        return None
    return docs[realname] if realname in docs else None


def add_msdocs_references(newvalues: dict, realname: str) -> dict:
    """\
        Enriches the passed dict by the official documentation references (and state)
    """
    traits = get_linkexe_switch_traits_msdocs(realname)
    purpose, moniker = None, None
    if traits:
        assert "markdown" in traits, f"The 'markdown' key was missing from {traits=}"
        assert "purpose" in traits, f"The 'purpose' key was missing from {traits=}"
        purpose = traits["purpose"] if "purpose" in traits else ""
        moniker = traits["markdown"] if "markdown" in traits else ""
    if purpose:
        if "purpose" not in newvalues:
            newvalues["purpose"] = purpose
        elif purpose != newvalues["purpose"]:
            eprint(f"updating {realname} purpose")
            newvalues["purpose"] = purpose
    elif "purpose" not in newvalues:
        newvalues["purpose"] = None  # placeholder
    if moniker:
        moniker = f"msdocs.link://{moniker}"
        if "documented" not in newvalues:
            newvalues["documented"] = moniker
        elif moniker != newvalues["documented"]:
            eprint(f"updating {realname} 'documented'")
            newvalues["documented"] = moniker
    elif "documented" not in newvalues:
        newvalues["documented"] = None  # placeholder
    return newvalues


def process_link_cmd(linkdata: dict, metadata: dict) -> dict:
    """\
        Takes as input the 'msvc.link' and 'meta' docs from the already existing msvc.yaml and enriches it
    """
    assert "cmdline" in linkdata
    cmdline = linkdata["cmdline"]
    both = set()
    newcmdln = {}
    documented = set()
    with open("linkexe_documented.txt", "r") as docs:
        documented = {line.strip() for line in docs.readlines() if line.strip()}
    for switch, values in cmdline.items():
        values = values or {}  # normalize into dict
        # Build new dict based on existing one
        newvalues = deepcopy(values or {})
        realname = f"/{switch}" if "realname" not in newvalues else newvalues["realname"]
        both.add(realname)
        if "realname" in newvalues and realname == newvalues["realname"]:
            del newvalues["realname"]
        if "msdocs-moniker" in newvalues:
            del newvalues["msdocs-moniker"]
        newvalues["researched"] = newvalues["researched"] if "researched" in newvalues else False
        geoffchappellcom_url = get_switch_uri_geoffchappellcom(realname)
        newvalues = add_msdocs_references(newvalues, realname)
        if "resources" in newvalues:
            assert isinstance(newvalues["resources"], (list, set, tuple)), "expected a list, set or tuple here"
            if geoffchappellcom_url and geoffchappellcom_url not in newvalues["resources"]:
                newvalues["resources"].append(geoffchappellcom_url)
        elif geoffchappellcom_url:
            newvalues["resources"] = [geoffchappellcom_url]
        else:
            newvalues["resources"] = []  # placeholder
        # Weed out crud and sort the list
        resources = set(newvalues["resources"])
        if None in resources:
            resources.remove(None)
        if geoffchappellcom_url:
            resources.add(geoffchappellcom_url)
        newvalues["resources"] = sorted(resources)
        newcmdln[switch] = newvalues
    linkdata["cmdline"] = newcmdln
    undocumented = both - documented
    eprint(f"link.exe: {len(both)} switches, {len(documented)} documented, {len(undocumented)} undocumented")
    if len(both) != len(documented) + len(undocumented):
        eprint(f"WARNING: {len(both)=} != {len(documented)=} + {len(undocumented)=}")
        remainder = documented - both
        if len(remainder):
            eprint(f"WARNING: {len(remainder)} orphaned items")
            for x in sorted(remainder):
                eprint(f"_D {x}")
        else:
            for x in sorted(both):
                if x in documented and x in undocumented:
                    eprint(f"UD {x}")
                elif x in documented:
                    eprint(f"_D {x}")
                elif x in undocumented:
                    eprint(f"U_ {x}")
                else:
                    eprint(f"__ {x}")
    return linkdata


def main(**kwargs) -> int:
    """\
        Very simply the main entry point to this script
    """
    inname = kwargs.get("yaml")
    data = None
    with open(inname, "r") as yamlfile:
        data = yaml.safe_load(stream=yamlfile)
    assert "meta" in data, "Missing top-level element 'meta'"
    assert "msvc" in data, "Missing top-level element 'msvc'"
    assert "link" in data["msvc"], "Missing second-level element 'link' inside 'msvc'"
    linkcmd = process_link_cmd(data["msvc"]["link"], data)
    data["msvc"]["link"] = linkcmd
    outname = inname
    if kwargs.get("dryrun", False):
        outname = inname.with_suffix(f".dryrun{inname.suffix}")
        eprint(f"DRY RUN: writing into {str(outname)}")
    else:
        with suppress(FileNotFoundError):
            from_name = outname
            to_name = outname.with_suffix(f".backup{outname.suffix}")
            eprint(f"Backing up original file '{str(from_name)}' to '{str(to_name)}'")
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
        eprint(__doc__)
        raise  # re-raise
