#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.3.5"
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
from hashlib import sha256
from pathlib import Path
from pprint import pformat, pprint  # noqa: F401
from typing import Optional

eprint = partial(print, file=sys.stderr)

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(f"This script is only compatible with the following Python versions: {', '.join([f'{z[0]}.{z[1]}' for z in __compatible__])}")  # pragma: no cover

CONFIG_DEFAULTS = """
[msvc.yaml]
path = %(thisdir)s/../msvc.yaml

[help-output]
path = %(thisdir)s/../help-output

[mirrors]
cpp-docs = %(thisdir)s/mirrors/cpp-docs
geoffchappell.com = %(thisdir)s/mirrors/msvc
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

    parser = ArgumentParser(description="Update YAML with command line switch descriptions", add_help=False)
    # Only add the configuration file argument for starters
    parser.add_argument("-c", "--config", "--ini", action="store", default=cfgname, metavar="CFG", type=Path, help=f"The config file; defaults to {cfgname}")
    partial_args = parser.parse_known_args()[0]
    cfg.read(partial_args.config)

    # Remaining command line options
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    parser.add_argument("--nologo", action="store_const", dest="nologo", const=True, help="Don't show info about this script.")
    parser.add_argument("-n", "--dryrun", "--dry-run", action="store_true", help="Won't actually change the YAML file")
    parser.add_argument("-Y", "--yaml", action="store", default=cfg.get("msvc.yaml", "path"), type=Path, help="YAML file to work with")
    parser.add_argument("--msvc", action="store", default=cfg.get("mirrors", "geoffchappell.com"), type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--cppdocs", "--cpp-docs", action="store", default=cfg.get("mirrors", "cpp-docs"), type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--helpoutput", "--help-output", action="store", default=cfg.get("help-output", "path"), type=Path, help=argparse.SUPPRESS)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Turn up verbosity to see more details of what is going on.")
    return cfg, parser.parse_args()


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
    fname = args.cppdocs / "docs/build/reference/linker-options.md"
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
    linkdir = args.msvc / "link"  # e.g. via 'wget -mkEpnp ...'
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
                switches[key] = f"gc.link://{uri.resolve().relative_to(linkdir.resolve())}"
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
        purpose = traits.get("purpose", None)
        moniker = traits.get("markdown", None)
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


@cache
def read_link_helpoutput(hlpoutdir: Path) -> dict:
    lines_from_digest = {}  # digest -> lines
    version_from_digest = {}  # digest -> key
    digest_from_version = {}  # key -> digest
    option_startre = re.compile(r"^\s*?options:", re.IGNORECASE)
    emptyline_re = re.compile(r"^\s*$")
    # Start by reading all of the files into a dict of lists
    for txtfile in hlpoutdir.rglob("link.txt"):
        relpath = txtfile.relative_to(hlpoutdir)
        with open(txtfile, "r") as hlpfile:
            lines = hlpfile.readlines()
            # Let's only consider the information which isn't cluttered by version numbers and stuff
            ctr = 0
            for line in lines:
                m = option_startre.match(line)
                ctr += 1
                if m:
                    break
            # ... and filter out empty lines
            lines = [line.rstrip() for line in lines[ctr:] if not emptyline_re.match(line.strip())]
            # Now compute a digest, so we can identify identical help content
            digest = sha256("\n".join(lines).encode("utf-8")).hexdigest()
            if digest not in lines_from_digest:
                lines_from_digest[digest] = lines
            key = relpath.parts[:3]
            if digest not in version_from_digest:
                version_from_digest[digest] = set()
            version_from_digest[digest].add(key)
            assert key not in digest_from_version, f"this should never happen: {key} must not already be in the dict"
            digest_from_version[key] = digest
    # Show counts just for convenience
    eprint(f"link.exe: {len(lines_from_digest)} distinct help outputs, {len(digest_from_version)} versions")
    # The dict which we'll return
    raw_switches = {}
    switchre = re.compile(r"^\s*?(/\w+)((?::[^\[\{].+|\[.+|:.+)?)$")
    switch_argsre = re.compile(r"^\s*?([^\s/].+[\]\|])$")
    # Go through distinct help outputs and assemble the information
    for digest, versions in version_from_digest.items():
        assert digest in lines_from_digest, f"{digest=} not in lines_from_digest"
        assert digest in version_from_digest, f"{digest=} not in version_from_digest"
        assert versions, f"unexpectedly empty versions set for {digest=}"
        prevmatch = None
        verset = set([v[0] for v in versions])
        hstset = set([v[1] for v in versions])
        tgtset = set([v[2] for v in versions])
        for line in lines_from_digest[digest]:
            m = switchre.match(line)
            if m:
                prevmatch = None  # definitely not a continuation
                (switch, args) = m.groups()
                if args.endswith("|"):
                    prevmatch = m.groups()
                    continue
            elif prevmatch:  # we really only expect continuation lines here
                # eprint(f"Continuing: {prevmatch}")
                m = switch_argsre.match(line)
                if m:
                    args = m.group(1)
                    prevmatch = (prevmatch[0], prevmatch[1] + args,)  # fmt: skip
                    if args.endswith("|"):
                        continue  # ... continued continuation line ... sweet
                (switch, args) = prevmatch
            else:
                assert False, f"NO MATCH FOR: '{line}'"
            assert switch.isupper(), f"unexpectedly we found '{switch}' to not be all uppercase"
            newkey = (switch.lower(), args)  # [0] corresponds to the realname
            if newkey in raw_switches:
                entry = raw_switches[newkey]
                raw_switches[newkey] = (entry[0].union(verset), entry[1].union(hstset), entry[2].union(tgtset),)  # fmt: skip
            else:  # Create the representation that can be consumed by our YAML
                raw_switches[newkey] = (verset, hstset, tgtset,)  # fmt: skip
    switches = {}
    for (switch, args), entry in raw_switches.items():
        assert len(entry) == 3, "expected a tuple of three sets!"
        verlist = sorted(entry[0], key=lambda x: tuple(map(int, x.split("."))), reverse=True)
        hstlist = sorted(entry[1])
        tgtlist = sorted(entry[2])
        if switch in switches:
            print(f"Existing entry for {switch}")
            oldentries = [x for x in switches[switch] if x["raw_args"] == args]
            if oldentries:  # fit the new
                assert len(oldentries) == 1, f"more than a single list item matches {args} in {oldentries}"
                oldentry = oldentries[0]
                switches[switch].remove(oldentry)  # if this throws, so be it ... something is wrong
                # We need the unions ...
                verlist = sorted(entry[0].union(set(oldentry["versions"])), key=lambda x: tuple(map(int, x.split("."))), reverse=True)
                hstlist = sorted(entry[1].union(set(oldentry["hosts"])))
                tgtlist = sorted(entry[2].union(set(oldentry["targets"])))
                newentry = {"raw_args": args, "versions": verlist, "hosts": hstlist, "targets": tgtlist}
            else:  # simply append new item
                newentry = {"raw_args": args, "versions": verlist, "hosts": hstlist, "targets": tgtlist}
            switches[switch].append(newentry)
            switches[switch].sort(key=lambda x: x["raw_args"])
        else:  # first and, so far, only item in the list
            print(f"New entry for {switch}")
            switches[switch] = [{"raw_args": args, "versions": verlist, "hosts": hstlist, "targets": tgtlist}]
    return switches


@cache
def get_linkexe_help_output(realname: str) -> dict:
    """\
        Attempts to find a link.exe switch by its real name and locate it in help output
    """
    switches = read_link_helpoutput(args.helpoutput)
    assert switches, "expected _something_ to come back from parsing help output"
    return switches[realname] if realname in switches else {}


def add_help_output(newvalues: dict, realname: str) -> dict:
    """\
        Enriches the passed dict by the data gleaned from the help output
    """
    switch = get_linkexe_help_output(realname)
    newvalues["args"] = switch  # currently we simply overwrite any pre-existing data
    return newvalues


def process_link_cmd(linkdata: dict) -> dict:
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
        realname = newvalues.get("realname", f"/{switch}")
        both.add(realname)
        if "realname" in newvalues:
            if realname == f"/{switch}":
                del newvalues["realname"]
        if "msdocs-moniker" in newvalues:
            del newvalues["msdocs-moniker"]
        newvalues["researched"] = newvalues.get("researched", False)  # make sure this exists
        geoffchappellcom_url = get_switch_uri_geoffchappellcom(realname)
        newvalues = add_msdocs_references(newvalues, realname)
        newvalues = add_help_output(newvalues, realname)
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


def main() -> int:
    """\
        Very simply the main entry point to this script
    """
    inname = args.yaml
    data = None
    with open(inname, "r") as yamlfile:
        data = yaml.safe_load(stream=yamlfile)
    assert data is not None, f"Failed loading {inname.name}"
    assert "meta" in data, "Missing top-level element 'meta'"
    assert "msvc" in data, "Missing top-level element 'msvc'"
    assert "link" in data["msvc"], "Missing second-level element 'link' inside 'msvc'"
    linkcmd = process_link_cmd(data["msvc"]["link"])
    data["msvc"]["link"] = linkcmd
    outname = inname
    if args.dryrun:
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
