#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
from datetime import datetime, timezone
import json
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
NEWLINE = "\n"

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
        description="AppThreat's vulnerability database and package search library with a sqlite storage."
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
        help="Search for the package or vulnerability ID (CVE, GHSA, ALSA, DSA, etc.) in the database. Use purl, cpe, or git http url.",
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
        help="Downloaded pre-created vdb image to platform specific user_data_dir. Application vulnerabilities only.",
    )
    parser.add_argument(
        "--download-full-image",
        action="store_true",
        default=False,
        dest="download_full_image",
        help="Downloaded pre-created vdb image to platform specific user_data_dir. All vulnerabilities including OS.",
    )
    parser.add_argument(
        "--print-vdb-metadata",
        action="store_true",
        default=False,
        dest="print_vdb_metadata",
        help="Display metadata about the current vdb in user_data_dir.",
    )
    return parser.parse_args()


def add_table_row(table: Table, res: dict, added_row_keys: dict):
    # matched_by is the purl or cpe string
    row_key = f"""{res["matched_by"]}|{res.get("source_data_hash")}"""
    # Filter duplicate rows from getting printed
    if added_row_keys.get(row_key):
        return
    source_data: CVE = res.get("source_data")
    descriptions = []
    cna_container = source_data.root.containers.cna
    affected_functions = set()
    affected_modules = set()
    if cna_container and cna_container.descriptions and cna_container.descriptions.root:
        for adesc in cna_container.descriptions.root:
            description = (
                "\n".join(
                    [
                        base64.b64decode(sm.value).decode("utf-8")
                        for sm in adesc.supportingMedia
                    ]
                )
                if adesc.supportingMedia
                else adesc.value
            )
            description = description.replace("\\n", "\n").replace("\\t", "  ")
            descriptions.append(description)
    if cna_container.affected and cna_container.affected.root:
        for each_affected in cna_container.affected.root:
            if each_affected.programRoutines:
                affected_functions |= {r.name for r in each_affected.programRoutines}
            if each_affected.modules:
                affected_modules |= {m.root for m in each_affected.modules}
    affected_functions = list(affected_functions)
    affected_modules = list(affected_modules)
    affects = ""
    if affected_functions:
        affects = f"## Functions\n- {(NEWLINE + '- ').join(affected_functions)}"
    if affected_modules:
        affects = f"{affects}\n## Modules\n- {(NEWLINE + '- ').join(affected_modules)}"
    table.add_row(
        res.get("cve_id"),
        res.get("matched_by"),
        Markdown("\n".join(descriptions), justify="left", hyperlinks=True),
        Markdown(affects, justify="left"),
    )
    added_row_keys[row_key] = True


def print_results(results):
    added_row_keys = {}
    table = Table(title="VDB Results", show_lines=True)
    table.add_column("CVE", justify="left", max_width=20)
    table.add_column("Locator")
    table.add_column("Description")
    table.add_column("Affected Symbols", max_width=50)
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


def create_db_file_metadata(sources, cve_data_count, cve_index_count):
    """Method to create the vdb file metadata"""
    metadata = {
        "created_utc": datetime.now(tz=timezone.utc).isoformat(
            timespec="seconds"
        ),
        "cve_data_count": cve_data_count,
        "cve_index_count": cve_index_count,
        "sources": [s.__class__.__name__ for s in sources],
    }
    include_list = []
    ignore_list = []
    # Collect injected metadata from environment variables
    for name, value in os.environ.items():
        if value is None:
            continue
        if name.startswith("VDB_METADATA_"):
            if value in ("true", "1"):
                value = True
            elif value in ("false", "0"):
                value = False
            metadata[name.replace("VDB_METADATA_", "").lower()] = value
        elif name.startswith("VDB_IGNORE_") and value in ("true", "1"):
            ignore_list.append(name.replace("VDB_IGNORE_", "").lower())
        elif name.startswith("VDB_EXCLUDE_") and value in ("true", "1"):
            ignore_list.append(name.replace("VDB_EXCLUDE_", "").lower())
        elif name.startswith("VDB_INCLUDE_") and value in ("true", "1"):
            include_list.append(name.replace("VDB_INCLUDE_", "").lower())
    if include_list:
        metadata["include_list"] = include_list
    if ignore_list:
        metadata["ignore_list"] = ignore_list
    if os.getenv("NVD_START_YEAR"):
        metadata["start_year"] = os.getenv("NVD_START_YEAR")
    if os.getenv("GITHUB_PAGE_COUNT"):
        metadata["github_page_count"] = os.getenv("GITHUB_PAGE_COUNT")
    return metadata


def print_db_file_metadata(metadata_file):
    if not os.path.exists(metadata_file):
        return
    with open(metadata_file, encoding="utf-8") as fp:
        db_meta = json.load(fp)
        table = Table(title="VDB Summary", show_lines=True, caption=f"Metadata file: {metadata_file}")
        table.add_column("Property")
        table.add_column("Value")
        for k, v in db_meta.items():
            table.add_row(k, str(v))
        console.print(table)


def main():
    """Main function"""
    args = build_args()
    print(AT_LOGO)
    if args.clean:
        if os.path.exists(config.DATA_DIR):
            shutil.rmtree(config.DATA_DIR, ignore_errors=True)
        if not os.path.exists(config.DATA_DIR):
            LOG.info("VDB cache cleaned successfully.")
        else:
            LOG.info("VDB cache at %s not cleaned successfully.", config.DATA_DIR)
    if args.print_vdb_metadata:
        print_db_file_metadata(config.VDB_METADATA_FILE)
    if args.download_image or args.download_full_image:
        db_url = config.VDB_DATABASE_URL if args.download_full_image else config.VDB_APP_ONLY_DATABASE_URL
        if ORAS_AVAILABLE:
            LOG.info(
                "Downloading vdb image from %s to %s",
                db_url,
                config.DATA_DIR,
            )
            download_image(db_url, config.DATA_DIR)
            print_db_file_metadata(config.VDB_METADATA_FILE)
        else:
            console.print(
                "Oras library is not available. Install using 'pip install appthreat-vulnerability-db[oras]' and re-run this command.",
                markup=False
            )
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
        if args.cache_os and not args.only_aqua:
            sources.insert(0, AquaSource())
        for s in sources:
            LOG.info("Refreshing %s", s.__class__.__name__)
            s.refresh()
        cve_data_count, cve_index_count = db_lib.stats()
        console.print(
            "cve_data_count", cve_data_count, "cve_index_count", cve_index_count
        )
        db_lib.optimize_and_close_all()
        # Create metadata about the database
        with open(config.VDB_METADATA_FILE, mode="w", encoding="utf-8") as meta_file:
            json.dump(
                create_db_file_metadata(sources, cve_data_count, cve_index_count),
                meta_file,
            )
    if args.search:
        if db_lib.needs_update():
            console.print(
                "Vulnerability database needs to be refreshed. Please run 'vdb --download-image' to download the latest."
            )
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
