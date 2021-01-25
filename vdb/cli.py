#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import re

from tabulate import tabulate

from vdb.lib import config as config
from vdb.lib import db as dbLib
from vdb.lib.gha import GitHubSource
from vdb.lib.npm import NpmSource
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
        "--clean",
        action="store_true",
        default=False,
        dest="clean",
        help="Clear the vulnerability database cache from platform specific user_data_dir",
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
        "--sync-npm",
        action="store_true",
        default=False,
        dest="sync_npm",
        help="Sync from npm.",
    )
    parser.add_argument(
        "--sync-github",
        action="store_true",
        default=False,
        dest="sync_github",
        help="Sync from github.",
    )
    parser.add_argument(
        "--search",
        dest="search",
        help="Search for package and version in the database. Use colon to separate package and version. Use comma to specify multiple values. Eg: android:8.0",
    )
    parser.add_argument(
        "--search-npm",
        dest="search_npm",
        help="Search for package and version in the database. Use colon to separate package and version. Use comma to specify multiple values. Eg: android:8.0",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        default=False,
        dest="list",
        help="List data in the db as a table",
    )
    return parser.parse_args()


def print_results(results):
    """Pretty print report summary"""
    table = []
    added_list = []
    headers = [
        "Id",
        "Package",
        "Affected Version",
        "Fix Version",
        "CWE",
        "Severity",
        "Score",
        "Description",
    ]
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        package_type = vuln_occ_dict.get("type")
        if id not in added_list:
            package_issue = res.package_issue
            full_pkg = package_issue.affected_location.package
            if package_issue.affected_location.vendor:
                full_pkg = "{}:{}".format(
                    package_issue.affected_location.vendor,
                    package_issue.affected_location.package,
                )
            if package_type and package_type != "*":
                full_pkg = package_type + ":" + full_pkg
            table.append(
                [
                    id,
                    full_pkg,
                    package_issue.affected_location.version,
                    package_issue.fixed_location,
                    vuln_occ_dict.get("problem_type"),
                    vuln_occ_dict.get("severity"),
                    vuln_occ_dict.get("cvss_score"),
                    vuln_occ_dict.get("short_description"),
                ]
            )
            added_list.append(id)
    print(tabulate(table, headers, tablefmt="grid"))


def main():
    args = build_args()
    print(at_logo)
    if args.clean:
        if os.path.exists(config.data_dir):
            try:
                os.rmdir(config.data_dir)
            except Exception:
                pass
    else:
        LOG.info("Vulnerability database loaded from {}".format(config.vdb_bin_file))

    if args.cache:
        for s in [GitHubSource(), NvdSource()]:
            LOG.info("Refreshing {}".format(s.__class__.__name__))
            s.refresh()
    elif args.sync:
        for s in [GitHubSource(), NvdSource()]:
            LOG.info("Syncing {}".format(s.__class__.__name__))
            s.download_recent()
    if args.sync_npm:
        for s in [NpmSource()]:
            LOG.info("Syncing {}".format(s.__class__.__name__))
            s.download_recent()
    if args.sync_github:
        for s in [GitHubSource()]:
            LOG.info("Syncing {}".format(s.__class__.__name__))
            s.download_recent()
    if args.search_npm:
        source = NpmSource()
        results = source.bulk_search(config.npm_app_info, [args.search_npm])
        print_results(results)
    if args.list:
        db = dbLib.get()
        results = dbLib.list_all_occurrence(db)
        print_results(results)
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
