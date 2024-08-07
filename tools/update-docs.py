#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set autoindent smartindent softtabstop=4 tabstop=4 shiftwidth=4 expandtab:
from __future__ import print_function, with_statement, unicode_literals, division, absolute_import

__author__ = "Oliver Schneider"
__copyright__ = "2023 Oliver Schneider (assarbad.net), under the terms of the UNLICENSE"
__version__ = "0.2.3"
__compatible__ = ((3, 11), (3, 12),)  # fmt: skip
__doc__ = """
=============
 update-docs
=============

    Small script to do update the documentation based on Jinja2 templates.
"""
import argparse
import re
import sys
import yaml
from collections import namedtuple
from functools import cache, partial
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

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


CmdLineSwitch = namedtuple("CmdLineSwitch", ["name", "documented", "mentions", "purpose", "researched", "resources", "notes"])
CmdLineSwitchArgs = namedtuple("CmdLineSwitchArgs", ["value"])
Binary = namedtuple("Binary", ["name", "hash", "host", "target", "toolchain", "version"])
BinaryVersion = namedtuple("BinaryVersion", ["file", "product"])


def populate_j2_linkvar(data: dict) -> dict:
    switches = []
    for key, value in data["msvc"]["link"]["cmdline"].items():
        name = value.get("realname", f"/{key}")
        switches.append(
            CmdLineSwitch(
                name,
                value.get("documented", None),
                value.get("mentions", []),
                value.get("purpose", None),
                value.get("researched", False),
                value.get("resources", []),
                value.get("notes", None),
            )
            # notes, args
        )
    binaries = []
    for value in data["msvc"]["link"]["binaries"]:
        for i in {"name", "host", "hash", "target", "toolchain", "version"}:
            assert i in value, f"'{i}' not found in {value=}"
        for i in {"file", "product"}:
            assert i in value["version"], f"'{i}' not found in {value['version']=}"
        # BinaryVersion = namedtuple("BinaryVersion", ["file", "product"])
        binver = BinaryVersion(value["version"]["file"], value["version"]["product"])
        # Binary = namedtuple("Binary", ["name", "hash", "host", "target", "toolchain", "version"])
        binary = Binary(value["name"], value["hash"], value["host"], value["target"], value["toolchain"], binver)
        binaries.append(binary)
    assert len(binaries) == len(data["msvc"]["link"]["binaries"]), "it appears some items were lost on the way?!"
    assert len(switches) == len(data["msvc"]["link"]["cmdline"]), "it appears some items were lost on the way?!"
    switches = sorted(switches, key=lambda x: x.name)
    return {"binaries": binaries, "cmdline": switches, "environment": []}


def update_docs(template: Path, data: dict) -> int:
    j2ldr = FileSystemLoader(searchpath=template.parent)
    meta = data["meta"]
    deferred_url_list = []
    urlre = re.compile(r"(\w+?(?:\.\w+))?://(.+)")

    @cache
    def cache_meta(**meta):
        gc_baseurl, gc_linkuri = meta.get("geoffchappell_baseurl"), meta.get("geoffchappell_linkuri")
        ms_baseurl, ms_cpprefuri = meta.get("msdocs_baseurl"), meta.get("msdocs_cpprefuri")
        assert gc_baseurl and gc_linkuri and ms_baseurl and ms_cpprefuri, "one of the meta arguments was 'empty'"
        return gc_baseurl, gc_linkuri, ms_baseurl, ms_cpprefuri

    @cache
    def resolve_url(url: str, **meta) -> str:
        gc_baseurl, gc_linkuri, ms_baseurl, ms_cpprefuri = cache_meta(**meta)
        match = urlre.fullmatch(url)
        if match:
            partone, parttwo = match.group(1), match.group(2)
            if partone in {"msdocs.link"}:
                return f"{ms_baseurl}/{ms_cpprefuri}/{parttwo}"
            elif partone in {"gc.link"}:
                return f"{gc_baseurl}/{gc_linkuri}/{parttwo}"
            elif partone in {"https", "http"}:
                return url
        elif url.startswith("/"):  # assume this is over at learn.microsoft.com
            return f"{ms_baseurl}/{url}"
        # assert False, f"URL '{url}' is invalid!"
        return url

    def get_doc_or_res_url(cmdline_switch: CmdLineSwitch, **meta) -> str:
        docsurl = None
        if cmdline_switch.documented:
            docsurl = resolve_url(cmdline_switch.documented, **meta)
        elif cmdline_switch.resources:
            gclink = [res for res in cmdline_switch.resources if res.startswith("gc")]
            mslink = [res for res in cmdline_switch.resources if "microsoft.com/" in res]
            tocheck = None
            if len(gclink) == 1:
                tocheck = gclink[0]
            elif mslink:
                tocheck = mslink[0]
            if tocheck:
                docsurl = resolve_url(tocheck, **meta)
        return docsurl if docsurl else ""

    def switchmdfmt(cmdline_switch: CmdLineSwitch) -> str:
        docsurl = get_doc_or_res_url(cmdline_switch, **meta)
        if cmdline_switch.documented:
            docsurl = resolve_url(cmdline_switch.documented, **meta)
            return f"[`{cmdline_switch.name}`]({docsurl})" if docsurl else f"`{cmdline_switch.name}`"
        elif docsurl:
            if args.verbose > 2:
                eprint(f"{cmdline_switch.name=} -> {docsurl} (from resources)")
            return f"**[`{cmdline_switch.name}`]({docsurl})**"
        return f"**`{cmdline_switch.name}`**"

    @cache
    def mdurl(url, text, deferred=True) -> str:
        retval = None
        if deferred:
            idx = len(deferred_url_list)
            retval = f"[{text}][{idx}]"
            deferred_url_list.append(url)
        else:
            retval = f"[{text}]({url})"
        return retval

    mdlinkre = re.compile(r"\[(?P<text>[^\]]+)\]\((?P<url>[^\)]+)\)", re.IGNORECASE)
    xrefre = re.compile("<xref:(?P<xrefname>[^>]+?)>", re.IGNORECASE)
    possible_switchre = re.compile("^`(/[^`/]+?)`$", re.IGNORECASE)

    def description(text, default="", context=None) -> str:
        if not text:
            return default
        _, _, ms_baseurl, _ = cache_meta(**meta)

        def replace_relative_mdurls(matchobj):
            linktext = matchobj.group("text")
            assert linktext, f"linktext not set for {matchobj}"
            linkurl = matchobj.group("url")
            assert linkurl, f"linkurl not set for {matchobj}"
            if args.verbose:
                eprint(f"Found: '{matchobj.group(0)}'")
            m = possible_switchre.match(linktext)
            if m:
                if args.verbose:
                    eprint(f"Lowercasing found switch: '{linktext}' -> '{linktext.lower()}'")
                linktext = linktext.lower()
            if linkurl.startswith("/"):
                linkurl = ms_baseurl + linkurl
                if args.verbose:
                    eprint(f"URL replaced -> {linkurl}")
            elif context and "/" not in linkurl and linkurl.endswith(".md"):
                docsurl = get_doc_or_res_url(context, **meta)
                if docsurl:
                    linkurl = str(Path(docsurl).with_name(linkurl.replace(".md", "")))
                    if args.verbose:
                        eprint(f"URL replaced -> {linkurl}")
            return f"[{linktext}]({linkurl})"

        def replace_xref_with_search(matchobj):
            xrefname = matchobj.group("xrefname")
            assert xrefname, f"xrefname not set for {matchobj}"
            return f"[{xrefname}]({ms_baseurl}/search/?terms={xrefname}&category=Documentation)"

        text = mdlinkre.sub(replace_relative_mdurls, text)
        text = xrefre.sub(replace_xref_with_search, text)
        return text

    def purpose(cmdline_switch, default="") -> str:
        return description(cmdline_switch.purpose, context=cmdline_switch)

    j2env = Environment(loader=j2ldr)
    j2env.filters["description"] = description
    j2env.filters["purpose"] = purpose
    j2env.filters["mdurl"] = mdurl
    j2env.filters["switchmdfmt"] = switchmdfmt
    template_vars = {
        "msdocs_entryurl": data["msvc"]["link"]["meta"]["msdocs_entryurl"],
        "deferred_url_list": deferred_url_list,
        "link": populate_j2_linkvar(data),
        "meta": meta,
    }

    j2tmpl = j2env.get_template(str(template.name))
    outpath = template.with_suffix("")
    outpath = args.outdir / outpath.name
    if args.verbose:
        eprint(f"{outpath=}")
    with open(outpath, "w") as outfile:
        print(j2tmpl.render(**template_vars), file=outfile)
    return 0


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
    return update_docs(args.input.absolute(), data)


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
