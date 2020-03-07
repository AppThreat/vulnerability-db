#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re

from tabulate import tabulate

import vdb.lib.config as config
import vdb.lib.db as dbLib
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

at_logo = """
  ___            _____ _                    _
 / _ \          |_   _| |                  | |
/ /_\ \_ __  _ __ | | | |__  _ __ ___  __ _| |_
|  _  | '_ \| '_ \| | | '_ \| '__/ _ \/ _` | __|
| | | | |_) | |_) | | | | | | | |  __/ (_| | |_
\_| |_/ .__/| .__/\_/ |_| |_|_|  \___|\__,_|\__|
      | |   | |
      |_|   |_|
"""


def build_args():
    """
    Constructs command line arguments for the vulnerability-db tool
    """
    parser = argparse.ArgumentParser(
        description="AppThreat's vulnerability database and package search library with a built-in file based storage"
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        default=False,
        dest="cache",
        help="Cache vulnerability information in platform specific user_data_dir",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        default=False,
        dest="sync",
        help="Sync to receive the latest vulnerability data. Should have invoked cache first.",
    )
    parser.add_argument(
        "--search",
        dest="search",
        help="Search for package and version in the database. Use colon to separate package and version. Use comma to specify multiple values. Eg: android:8.0",
    )
    return parser.parse_args()


def print_results(results):
    """Pretty print report summary
    """
    table = []
    added_list = []
    headers = ["Id", "Package", "CWE", "Severity", "Score", "Description"]
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        if id not in added_list:
            package_issue = res.package_issue
            table.append(
                [
                    id,
                    package_issue.affected_location.version,
                    vuln_occ_dict.get("problem_type"),
                    vuln_occ_dict.get("severity"),
                    vuln_occ_dict.get("cvss_score"),
                    vuln_occ_dict.get("short_description"),
                ]
            )
            added_list.append(id)
    print(tabulate(table, headers, tablefmt="grid"), flush=True)


def main():
    args = build_args()
    print(at_logo, flush=True)
    LOG.info("Vulnerability database loaded from {}".format(config.vdb_bin_file))
    if args.cache:
        for s in [GitHubSource(), NvdSource()]:
            LOG.info("Refreshing {}".format(s.__class__.__name__))
            s.refresh()
    elif args.sync:
        for s in [GitHubSource(), NvdSource()]:
            LOG.info("Syncing {}".format(s.__class__.__name__))
            s.download_recent()
    elif args.search:
        db = dbLib.get()
        search_list = re.split(r"[,|;]", args.search)
        for pkg_info in search_list:
            pstr = re.split(r"[:=@]", pkg_info)
            if pstr:
                if len(pstr) == 2 and dbLib.index_search(*pstr):
                    results = dbLib.pkg_search(db, *pstr)
                    print_results(results)
                elif len(pstr) == 3:
                    results = dbLib.vendor_pkg_search(db, *pstr)
                    print_results(results)
                else:
                    print("No vulnerability found!")


if __name__ == "__main__":
    main()
