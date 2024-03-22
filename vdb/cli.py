#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import shutil

import orjson
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from vdb.lib import config, db6 as db_lib, search
from vdb.lib.aqua import AquaSource
from vdb.lib.gha import GitHubSource
from vdb.lib.osv import OSVSource

console = Console()

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)
for _ in ("httpx",):
    logging.getLogger(_).disabled = True

AT_LOGO = r"""
             ___
  /\  ._  ._  | |_  ._ _   _. _|_
 /--\ |_) |_) | | | | (/_ (_|  |_
      |   |
"""


def build_args():
    """
    Constructs command line arguments for the vulnerability-db tool
    """
    parser = argparse.ArgumentParser(
        description="AppThreat's vulnerability database and package search library with a built-in sqlite based storage."
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        default=False,
        dest="clean",
        help="Clear the vulnerability database cache from platform specific user_data_dir.",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        default=False,
        dest="cache",
        help="Cache vulnerability information in platform specific user_data_dir.",
    )
    parser.add_argument(
        "--cache-os",
        action="store_true",
        default=False,
        dest="cache_os",
        help="Cache OS vulnerability information in platform specific user_data_dir.",
    )
    parser.add_argument(
        "--only-osv",
        action="store_true",
        default=False,
        dest="only_osv",
        help="Use only OSV as the source. Use with --cache.",
    )
    parser.add_argument(
        "--only-aqua",
        action="store_true",
        default=False,
        dest="only_aqua",
        help="Use only Aqua vuln-list as the source. Use with --cache.",
    )
    parser.add_argument(
        "--only-ghsa",
        action="store_true",
        default=False,
        dest="only_ghsa",
        help="Use only recent ghsa as the source. Use with --cache.",
    )
    parser.add_argument(
        "--search",
        dest="search",
        help="Search for the package or CVE ID in the database. Use purl, cpe, or colon-separated values.",
    )
    return parser.parse_args()


def print_results(results):
    table = Table(title="VDB Results")
    table.add_column("CVE", justify="left")
    table.add_column("Type")
    table.add_column("Namespace")
    table.add_column("Name")
    table.add_column("Hash")
    table.add_column("Source Data")
    for res in results:
        table.add_row(res.get("cve_id"), res.get("type"),
                      res.get("namespace", ""), res.get("name"),
                      res.get("source_data_hash"),
                      Syntax(orjson.dumps(
                          res.get("source_data").model_dump(mode="json", exclude_none=True),
                          option=orjson.OPT_INDENT_2 | orjson.OPT_APPEND_NEWLINE).decode("utf-8", errors="ignore"), "json", word_wrap=True))
    console.print(table)


def main():
    """Main function"""
    args = build_args()
    print(AT_LOGO)
    if args.clean:
        if os.path.exists(config.DATA_DIR):
            shutil.rmtree(config.DATA_DIR, ignore_errors=True)
    if args.cache or args.cache_os:
        db_lib.get()
        db_lib.clear_all()
        if args.only_osv:
            sources = [OSVSource()]
        elif args.only_aqua:
            sources = [AquaSource()]
        elif args.only_ghsa:
            sources = [GitHubSource()]
        else:
            sources = [OSVSource(), GitHubSource()]
        # AquaSource also includes NVD
        if args.cache_os:
            sources.insert(0, AquaSource())
        for s in sources:
            LOG.info("Refreshing %s", s.__class__.__name__)
            s.refresh()
        cve_data_count, cve_index_count = db_lib.stats()
        console.print("cve_data_count", cve_data_count, "cve_index_count", cve_index_count)
        db_lib.optimize_and_close_all()
    if args.search:
        if args.search.startswith("pkg:"):
            results = search.search_by_purl_like(args.search, with_data=True)
        elif args.search.startswith("CVE-") or args.search.startswith("GHSA-") or args.search.startswith("MAL-"):
            results = search.search_by_cve(args.search, with_data=True)
        elif args.search.startswith("http"):
            results = search.search_by_url(args.search, with_data=True)
        else:
            results = search.search_by_cpe_like(args.search, with_data=True)
        if results:
            print_results(results)
        else:
            console.print("No results found!")


if __name__ == "__main__":
    main()
