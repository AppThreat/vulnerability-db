#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import shutil
import types

from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.table import Table

from vdb.lib import config, db6 as db_lib, search
from vdb.lib.aqua import AquaSource
from vdb.lib.cve_model import CVE
from vdb.lib.gha import GitHubSource
from vdb.lib.osv import OSVSource

ORAS_AVAILABLE = False
# oras is an optional dependency
try:
    from vdb.lib.orasclient import download_image
    ORAS_AVAILABLE = True
except ImportError:
    pass

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
        help="Search for the package or CVE ID in the database. Use purl, cpe, or git http url.",
    )
    parser.add_argument(
        "--list-malware",
        action="store_true",
        default=False,
        dest="list_malware",
        help="List latest malwares with CVE ID beginning with MAL-.",
    )
    parser.add_argument(
        "--bom",
        dest="bom_file",
        help="Search for packages in the CycloneDX BOM file.",
    )
    parser.add_argument(
        "--download-image",
        action="store_true",
        default=False,
        dest="download_image",
        help="Downloaded pre-created vdb image to platform specific user_data_dir.",
    )
    return parser.parse_args()


def add_table_row(table: Table, res: dict, added_row_keys: dict):
    # matched_by is the purl or cpe string
    row_key = f"""{res["matched_by"]}|{res.get("source_data_hash")}"""
    # Filter duplicate rows from getting printed
    if added_row_keys.get(row_key):
        return
    source_data: CVE = res.get("source_data")
    description = ""
    if (
        source_data.root.containers.cna
        and source_data.root.containers.cna.descriptions
        and source_data.root.containers.cna.descriptions.root
    ):
        description = (
            source_data.root.containers.cna.descriptions.root[0]
            .value.replace("\\n", "\n")
            .replace("\\t", "  ")
        )
    table.add_row(
        res.get("cve_id"),
        res.get("matched_by"),
        Markdown(description, justify="left", hyperlinks=True),
    )
    added_row_keys[row_key] = True


def print_results(results):
    added_row_keys = {}
    table = Table(title="VDB Results", show_lines=True)
    table.add_column("CVE", justify="left")
    table.add_column("Locator")
    table.add_column("Description")
    if isinstance(results, types.GeneratorType):
        with Live(
            table, console=console, refresh_per_second=4, vertical_overflow="visible"
        ):
            for result_gen in results:
                if isinstance(result_gen, dict):
                    add_table_row(table, result_gen, added_row_keys)
                if isinstance(result_gen, types.GeneratorType):
                    for res in result_gen:
                        add_table_row(table, res, added_row_keys)
    elif isinstance(results, list):
        for res in results:
            add_table_row(table, res, added_row_keys)
        console.print(table)


def main():
    """Main function"""
    args = build_args()
    print(AT_LOGO)
    if args.clean:
        if os.path.exists(config.DATA_DIR):
            shutil.rmtree(config.DATA_DIR, ignore_errors=True)
    if args.download_image:
        if ORAS_AVAILABLE:
            LOG.info("Downloading vdb image from %s to %s", config.VDB_DATABASE_URL, config.DATA_DIR)
            download_image(config.VDB_DATABASE_URL, config.DATA_DIR)
        else:
            console.print("Oras library is not available. Install using pip install appthreat-vulnerability-db[oras] and then re-run this command.")
    elif args.cache or args.cache_os:
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
        console.print(
            "cve_data_count", cve_data_count, "cve_index_count", cve_index_count
        )
        db_lib.optimize_and_close_all()
    if args.search:
        results = search.search_by_any(args.search, with_data=True)
        if results:
            print_results(results)
        else:
            console.print("No results found!")
    elif args.bom_file:
        if os.path.exists(args.bom_file):
            results_generator = search.search_by_cdx_bom(args.bom_file, with_data=True)
            print_results(results_generator)
    elif args.list_malware:
        results_generator = search.latest_malware(with_data=True)
        print_results(results_generator)


if __name__ == "__main__":
    main()
