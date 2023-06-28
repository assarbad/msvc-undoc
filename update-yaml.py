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
 update-yaml
=============

Small script to do my bidding regarding the YAML-based file containing command line switches
and their properties.
"""
import argparse  # noqa: F401
import sys
import yaml
from pprint import pformat, pprint  # noqa: F401

# Checking for compatibility with Python version
if not sys.version_info[:2] in __compatible__:
    sys.exit(
        "This script is only compatible with the following Python versions: %s."
        % (", ".join(["%d.%d" % (z[0], z[1]) for z in __compatible__]))
    )  # pragma: no cover


def parse_args():
    """ """
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Update YAML with command line switch descriptions")
    parser.add_argument(
        "--nologo", action="store_const", dest="nologo", const=True, help="Don't show info about this script."
    )
    parser.add_argument("-n", "--dry-run", "--dryrun", action="store_true", help="Won't actually change the YAML file")
    parser.add_argument("-Y", "--yaml", action="store", help="YAML file to work with")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Turn up verbosity to see more details of what is going on. Use several v to increase the verbosity level, e.g. '-vvv'.",  # noqa: E501
    )
    return parser.parse_args()


def process_link_cmd(data):
    assert "cmdline" in data
    cmdline = data["cmdline"]
    both = set()
    newcmdline = {}
    documented = []
    with open("linkexe_documented.txt", "r") as docs:
        documented = {line.strip() for line in docs.readlines()}
    for switch, values in cmdline.items():
        newcmdline[switch] = {} if values is None else values
        if "realname" not in newcmdline[switch]:
            newcmdline[switch]["realname"] = f"/{switch}"
            realname = newcmdline[switch]["realname"]
            both.add(realname)
            if "documented" not in newcmdline[switch]:
                newcmdline[switch]["documented"] = realname in documented
            if not newcmdline[switch]["documented"]:
                if "researched" not in newcmdline[switch]:
                    newcmdline[switch]["researched"] = False
    data["cmdline"] = newcmdline
    return data

def main(**kwargs):
    """ """
    with open(kwargs.get("yaml"), "r") as yamlfile:
        data = yaml.safe_load(stream=yamlfile)
        assert "msvc" in data, "Missing top-level element"
        assert "link" in data["msvc"], "Missing top-level element"
        linkcmd = process_link_cmd(data["msvc"]["link"])
        pprint(linkcmd)
        data["msvc"]["link"] = linkcmd
        with open("out.yaml", "w") as yamlout:
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
