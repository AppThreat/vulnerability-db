"""
NPM Security Advisory to NVD CVE converter

This module implements basic functionality to query npm registry for security advisories
"""
import logging

try:
    import orjson

    ORJSON_AVAILABLE = True
except ImportError:
    import json

    ORJSON_AVAILABLE = False

import requests

from vdb.lib import config as config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    convert_md_references,
    convert_to_occurrence,
    fix_text,
    get_default_cve_data,
    serialize_vuln_list,
)

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

json_lib = orjson if ORJSON_AVAILABLE else json


class NpmSource(NvdSource):
    """
    Npm source
    """

    def bulk_search(self, app_info, pkg_list):
        """
        Bulk search the resource instead of downloading the information

        :param payload: Data containing required metadata and dependencies
        :return: Vulnerability occurrences
        """
        payload = {**app_info}
        requires = {}
        dependencies = {}
        for pkg in pkg_list:
            vendor = None
            if isinstance(pkg, dict):
                vendor = pkg.get("vendor")
                name = pkg.get("name")
                version = pkg.get("version")
            else:
                tmpA = pkg.split("|")
                version = tmpA[len(tmpA) - 1]
                name = tmpA[len(tmpA) - 2]
                if len(tmpA) == 3:
                    vendor = tmpA[0]
            key = name
            if vendor:
                key = f"{vendor}/{name}"
            requires[key] = version
            dependencies[key] = {"version": version}
        payload["requires"] = requires
        payload["dependencies"] = dependencies
        return convert_to_occurrence(serialize_vuln_list(self.fetch(payload)))

    def fetch(self, payload):
        LOG.debug("Fetch npm advisory from {}".format(config.npm_audit_url))
        r = requests.post(url=config.npm_audit_url, json=payload)
        json_data = r.json()
        return self.convert(json_data)

    def download_recent(self, local_store=True):
        """Method which downloads the recent CVE"""
        url = config.npm_advisories_url + "?perPage=100&page=1"
        r = requests.get(url=url)
        if r.ok:
            json_data = r.json()
            data = self.convert(json_data.get("objects"))
            if data and local_store:
                self.store(data)
            return data
        return []

    def download_all(self, local_store=True):
        """Download all historic cve data"""
        data_list = []
        url = config.npm_advisories_url + "?perPage=100&page=1"
        for y in range(0, int(config.npm_pages_count)):
            r = requests.get(url=url)
            if r.ok:
                json_data = r.json()
                data = self.convert(json_data.get("objects"))
                if data and local_store:
                    self.store(data)
                data_list += data
                if json_data.get("urls", {}).get("next"):
                    url = config.npm_server + json_data.get("urls").get("next")
                else:
                    break
        return data_list

    def get_version_ranges(self, version_str):
        """
        Version range formats used by npm
        <1.10.2
        <=4.0.13 || >=4.1.0 <4.1.2
        >=4.0.14 <4.1.0 || >=4.1.2
        :param version_str:
        :return: List of version ranges
        """
        version_list = []
        tmpA = version_str.split("||")
        for ver in tmpA:
            version_start_including = ""
            version_end_including = ""
            version_start_excluding = ""
            version_end_excluding = ""
            ver = ver.strip()
            ver = (
                ver.replace("<= ", "<=")
                .replace(">= ", ">=")
                .replace("< ", "<")
                .replace("> ", ">")
            )
            tmpB = ver.split(" ")
            if tmpB[0] == ">=" and len(tmpB) > 1:
                version_start_including = tmpB[1]
            elif tmpB[0].startswith(">="):
                version_start_including = tmpB[0].replace(">=", "")
            elif tmpB[0].startswith(">"):
                version_start_excluding = tmpB[0].replace(">", "")
            if tmpB[-1].startswith("<="):
                version_end_including = tmpB[-1].replace("<=", "")
            elif tmpB[-1].startswith("<"):
                version_end_excluding = tmpB[-1].replace("<", "")
            if (
                not version_start_including
                and not version_end_including
                and not version_start_excluding
                and not version_end_excluding
            ):
                version_start_including = version_str
            version_list.append(
                {
                    "version_start_including": version_start_including,
                    "version_end_including": version_end_including,
                    "version_start_excluding": version_start_excluding,
                    "version_end_excluding": version_end_excluding,
                }
            )
        return version_list

    def convert(self, adv_data):
        ret_data = []
        if isinstance(adv_data, list):
            for d in adv_data:
                self.to_vuln(d, ret_data)
        else:
            if adv_data.get("advisories"):
                for k, v in adv_data.get("advisories").items():
                    if v["deleted"]:
                        continue
                    self.to_vuln(v, ret_data)
        return ret_data

    def to_vuln(self, v, ret_data):
        assigner = "@npm"
        # Iterate the cve list if available
        cves = v.get("cves")
        if not cves:
            cves = ["{}-{}".format("NPM", v.get("id"))]
        for cve_id in cves:
            publishedDate = v["created"]
            lastModifiedDate = v["updated"]
            title = v.get("title", "")
            overview = v.get("overview", "")
            recommendation = v.get("recommendation", "")
            description = """# {}
{}
{}
            """.format(
                title, overview, recommendation
            )
            references = (
                [{"name": "npm advisory", "url": v.get("url")}] if v.get("url") else []
            )
            if v.get("references"):
                references = convert_md_references(v.get("references"))
            references = json_lib.dumps(references)
            if isinstance(references, bytes):
                references = references.decode("utf-8", "ignore")
            severity = v.get("severity")
            vendor = "npm"
            product = v["module_name"]
            score, severity, vectorString, attackComplexity = get_default_cve_data(
                severity
            )
            exploitabilityScore = score
            metadata = v.get("metadata", {})
            if isinstance(metadata, dict) and metadata.get("exploitability"):
                exploitabilityScore = metadata.get("exploitability")
            cwe_id = v.get("cwe")
            version = v["vulnerable_versions"]
            fix_version = v.get("patched_versions")
            version_ranges = self.get_version_ranges(version)
            fix_version_ranges = self.get_version_ranges(fix_version)
            vr = 0
            for ver in version_ranges:
                version_start_including = ver["version_start_including"]
                version_end_including = ver["version_end_including"]
                version_start_excluding = ver["version_start_excluding"]
                version_end_excluding = ver["version_end_excluding"]
                top_fix_version = (
                    fix_version_ranges[vr]
                    if len(fix_version_ranges) > vr
                    else fix_version_ranges[0]
                )
                fix_version_start_including = top_fix_version.get(
                    "version_start_including", ""
                )
                fix_version_end_including = top_fix_version.get(
                    "version_end_including", ""
                )
                fix_version_start_excluding = top_fix_version.get(
                    "version_start_excluding", ""
                )
                fix_version_end_excluding = top_fix_version.get(
                    "version_end_excluding", ""
                )
                description = fix_text(description)

                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vectorString,
                    vendor=vendor,
                    product=product,
                    version="*",
                    edition="*",
                    version_start_including=version_start_including,
                    version_end_including=version_end_including,
                    version_start_excluding=version_start_excluding,
                    version_end_excluding=version_end_excluding,
                    fix_version_start_including=fix_version_start_including,
                    fix_version_end_including=fix_version_end_including,
                    fix_version_start_excluding=fix_version_start_excluding,
                    fix_version_end_excluding=fix_version_end_excluding,
                    severity=severity,
                    attackComplexity=attackComplexity,
                    score=score,
                    exploitabilityScore=exploitabilityScore,
                    publishedDate=publishedDate,
                    lastModifiedDate=lastModifiedDate,
                )
                try:
                    vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                    vuln.description = description
                    ret_data.append(vuln)
                except Exception as e:
                    LOG.debug(e)
                vr = vr + 1
        return ret_data
