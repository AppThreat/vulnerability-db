"""
NPM Security Advisory to NVD CVE converter

This module implements basic functionality to query npm registry for security advisories
"""
import json
import logging

import requests

import vdb.lib.config as config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    get_default_cve_data,
    serialize_vuln_list,
    convert_to_occurrence,
)

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


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
            if isinstance(pkg, dict):
                name = pkg.get("name")
                version = pkg.get("version")
            else:
                tmpA = pkg.split("|")
                version = tmpA[len(tmpA) - 1]
                name = tmpA[len(tmpA) - 2]
            requires[name] = version
            dependencies[name] = {"version": version}
        payload["requires"] = requires
        payload["dependencies"] = dependencies
        return convert_to_occurrence(serialize_vuln_list(self.fetch(payload)))

    def fetch(self, payload):
        LOG.debug("Fetch npm advisory from {}".format(config.npm_url))
        r = requests.post(url=config.npm_url, json=payload)
        json_data = r.json()
        return self.convert(json_data)

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
            tmpB = ver.split(" ")
            if tmpB[0].startswith(">="):
                version_start_including = tmpB[0].replace(">=", "")
            elif tmpB[0].startswith(">"):
                version_start_excluding = tmpB[0].replace(">", "")
            if tmpB[len(tmpB) - 1].startswith("<="):
                version_end_including = tmpB[len(tmpB) - 1].replace("<=", "")
            elif tmpB[len(tmpB) - 1].startswith("<"):
                version_end_excluding = tmpB[len(tmpB) - 1].replace("<", "")
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
        assigner = "@npm"
        for k, v in adv_data.get("advisories").items():
            if v["deleted"]:
                continue
            # Iterate the cve list if available
            cves = v.get("cves")
            if not cves:
                cves = [v.get("id")]
            for cve_id in cves:
                publishedDate = v["created"]
                lastModifiedDate = v["updated"]
                # FIXME: This should include overview and recommendation
                description = v.get("title", "").replace("`", "")
                # FIXME: This should include references
                references = [{"name": "npm advisory", "url": v.get("url")}]
                severity = v.get("severity")
                vendor = "npm"
                product = v["module_name"]
                score, severity, vectorString, attackComplexity = get_default_cve_data(
                    severity
                )
                cwe_id = v.get("cwe")
                version = v["vulnerable_versions"]
                version_ranges = self.get_version_ranges(version)
                for ver in version_ranges:
                    version_start_including = ver["version_start_including"]
                    version_end_including = ver["version_end_including"]
                    version_start_excluding = ver["version_start_excluding"]
                    version_end_excluding = ver["version_end_excluding"]
                    tdata = config.CVE_TPL % dict(
                        cve_id=cve_id,
                        cwe_id=cwe_id,
                        assigner=assigner,
                        references=json.dumps(references),
                        description=description,
                        vectorString=vectorString,
                        vendor=vendor,
                        product=product,
                        version="*",
                        version_start_including=version_start_including,
                        version_end_including=version_end_including,
                        version_start_excluding=version_start_excluding,
                        version_end_excluding=version_end_excluding,
                        severity=severity,
                        attackComplexity=attackComplexity,
                        score=score,
                        publishedDate=publishedDate,
                        lastModifiedDate=lastModifiedDate,
                    )
                    vuln = NvdSource.convert_vuln(json.loads(tdata, strict=False))
                    ret_data.append(vuln)
        return ret_data
