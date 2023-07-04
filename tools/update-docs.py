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


CmdLineSwitch = namedtuple("CmdLineSwitch", ["name", "documented", "mentions", "purpose", "researched", "resources"])
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
            )
        )
    binaries = []
    for value in data["msvc"]["link"]["binaries"]:
        for i in {"name", "host", "hash", "target", "toolchain", "version"}:
            assert i in value, f"'{i}' not found in {value=}"
        for i in {"file", "product"}:
            assert i in value["version"], f"'{i}' not found in {value['version']=}"
        binver = BinaryVersion(value["version"]["file"], value["version"]["product"])
        binary = Binary(value["name"], value["host"], value["hash"], value["target"], value["toolchain"], binver)
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
    def cache_meta(**kwargs):
        gc_baseurl, gc_linkuri = kwargs.get("geoffchappell_baseurl"), kwargs.get("geoffchappell_linkuri")
        ms_baseurl, ms_cpprefuri = kwargs.get("msdocs_baseurl"), kwargs.get("msdocs_cpprefuri")
        assert gc_baseurl and gc_linkuri and ms_baseurl and ms_cpprefuri, "one of the kwargs was 'empty'"
        return gc_baseurl, gc_linkuri, ms_baseurl, ms_cpprefuri

    @cache
    def resolve_url(url: str, **kwargs) -> str:
        gc_baseurl, gc_linkuri, ms_baseurl, ms_cpprefuri = cache_meta(**kwargs)
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
        eprint(f"{url}")
        return None

    def switchmdfmt(cmdline_switch: CmdLineSwitch) -> str:
        if cmdline_switch.documented:
            docsurl = resolve_url(cmdline_switch.documented, **meta)
            return f"[`{cmdline_switch.name}`]({docsurl})"
        return f"**`{cmdline_switch.name}`**"

    def mdurl(url, text, deferred=True) -> str:
        retval = None
        if deferred:
            idx = len(deferred_url_list)
            retval = f"[{text}][{idx}]"
            deferred_url_list.append(url)
        else:
            retval = f"[{text}]({url})"
        return retval

    def description(text, default="") -> str:
        if not text:
            return default
        return text

    j2env = Environment(loader=j2ldr)
    j2env.filters["description"] = description
    j2env.filters["mdurl"] = mdurl
    j2env.filters["switchmdfmt"] = switchmdfmt
    template_vars = {
        "msdocs_entryurl": data["msvc"]["link"]["meta"]["msdocs_entryurl"],
        "deferred_url_list": deferred_url_list,
        "link": populate_j2_linkvar(data),
        "meta": meta,
    }

    j2tmpl = j2env.get_template(str(template.name))
    with open(template.with_suffix(""), "w") as outfile:
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
