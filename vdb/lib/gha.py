"""
GitHub Security Advisory to NVD CVE converter

This module fetches the recent security advisories from GitHub and stores them in NVD CVE 1.1 json format. Below substitutions are made to properly construct the NVD CVE Json

- versionStartIncluding and versionEndIncluding are calculated from version range. Version End is used to hold any single version number being passed
- vectorString is constructed based on severity. The official calculator [url](https://www.first.org/cvss/calculator/3.1) was used to construct some realistic strings for given severity
- Full description (description) is ignored for now

"""
import logging
import os
import re

try:
    import orjson

    ORJSON_AVAILABLE = True
except ImportError:
    import json

    ORJSON_AVAILABLE = False

import requests

from vdb.lib import config as config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import get_default_cve_data

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

api_token = os.environ.get("GITHUB_TOKEN")
headers = {"Authorization": "token %s" % api_token}

json_lib = orjson if ORJSON_AVAILABLE else json


def get_query(type="recent"):
    """"""
    extra_args = ""
    if type == "recent" or not type:
        extra_args = "first: 100"
    else:
        extra_args = 'first: 100, after: "' + str(type) + '"'
    gqljson = {
        "query": """
            query {
                securityAdvisories(%(extra_args)s) {
                nodes {
                  id
                  ghsaId
                  summary
                  description
                  identifiers {
                    type
                    value
                  }
                  origin
                  publishedAt
                  updatedAt
                  references {
                    url
                  }
                  severity
                  withdrawnAt
                  vulnerabilities(first: 10) {
                    nodes {
                      firstPatchedVersion {
                        identifier
                      }
                      package {
                        ecosystem
                        name
                      }
                      severity
                      updatedAt
                      vulnerableVersionRange
                    }
                  }
                }
                pageInfo {
                  endCursor
                  hasNextPage
                }
              }
            }
        """
        % dict(extra_args=extra_args)
    }
    return gqljson


class GitHubSource(NvdSource):
    """GitHub CVE source"""

    def download_all(self, local_store=True):
        """Download all historic cve data"""
        data_list = []
        lastId = None
        for y in range(0, int(config.gha_pages_count)):
            data, page_info = self.fetch(type=lastId)
            if data:
                if local_store:
                    self.store(data)
            if page_info and page_info["hasNextPage"]:
                lastId = page_info["endCursor"]
        return data_list

    def download_recent(self, local_store=True):
        """Method which downloads the recent CVE"""
        data, page_info = self.fetch("recent")
        if data and local_store:
            self.store(data)
        return data

    def fetch(self, type):
        """Private method to fetch the advisory data via GraphQL api"""
        LOG.debug(
            "Download GitHub advisory from {} with cursor {}".format(
                config.gha_url, type
            )
        )
        r = requests.post(
            url=config.gha_url, json=get_query(type=type), headers=headers
        )
        json_data = r.json()
        return self.convert(json_data)

    def get_version_range(self, version_str):
        """
        Version range format - https://developer.github.com/v4/object/securityvulnerability/
        = 0.2.0 denotes a single vulnerable version.
        <= 1.0.8 denotes a version range up to and including the specified version
        < 0.1.11 denotes a version range up to, but excluding, the specified version
        >= 4.3.0, < 4.3.5 denotes a version range with a known minimum and maximum version.
        >= 0.0.1 denotes a version range with a known minimum, but no known maximum
        > 2.1.0, < 2.1.8
        > 2.0.0, <= 2.0.14
        """
        version_start_including = ""
        version_end_including = ""
        version_start_excluding = ""
        version_end_excluding = ""
        if version_str.startswith("= "):
            version_end_including = version_str.replace("= ", "")
        elif version_str.startswith("<= "):
            version_end_including = version_str.replace("<= ", "")
        elif version_str.startswith("< "):
            version_end_excluding = version_str.replace("< ", "")
        elif version_str.startswith(">= "):
            version_start_including = version_str.replace(">= ", "").split(", ")[0]
        elif version_str.startswith("> "):
            version_start_excluding = version_str.replace("> ", "").split(", ")[0]
        if version_end_excluding == "":
            tmpA = version_str.split(", ")
            if tmpA[len(tmpA) - 1].startswith("<= "):
                version_end_including = tmpA[len(tmpA) - 1].replace("<= ", "")
            elif tmpA[len(tmpA) - 1].startswith("< "):
                version_end_excluding = tmpA[len(tmpA) - 1].replace("< ", "")
        if (
            not version_start_including
            and not version_end_including
            and not version_start_excluding
            and not version_end_excluding
        ):
            version_start_including = version_str
        return (
            version_start_including,
            version_end_including,
            version_start_excluding,
            version_end_excluding,
        )

    def convert(self, cve_data):
        """Convert the GitHub advisory data into Vulnerability objects"""
        ret_data = []
        if cve_data.get("errors"):
            return ret_data, None
        if cve_data.get("message") and cve_data.get("message") == "Bad credentials":
            LOG.warning("GITHUB_TOKEN environment variable is invalid!")
            return ret_data, None
        page_info = cve_data["data"]["securityAdvisories"].get("pageInfo")
        for cve in cve_data["data"]["securityAdvisories"]["nodes"]:
            # If this CVE is withdrawn continue
            if cve.get("withdrawnAt"):
                continue
            cve_id = None
            assigner = "cve@mitre.org"
            references = []
            for r in cve["references"]:
                references.append({"url": r["url"], "name": r["url"]})
            for id in cve["identifiers"]:
                if id["type"] == "CVE":
                    cve_id = id["value"]
            if not cve_id:
                cve_id = cve["ghsaId"]
                assigner = "@github"
            references = json_lib.dumps(references)
            if isinstance(references, bytes):
                references = references.decode("utf-8", "ignore")
            for p in cve["vulnerabilities"]["nodes"]:
                if not p:
                    continue
                vendor = p["package"]["ecosystem"]
                product = p["package"]["name"]
                if ":" in product or "/" in product:
                    tmpA = re.split(r"[/|:]", product)
                    # This extract's the correct vendor based on the namespace
                    # Eg: org.springframework:spring-webflux would result in
                    # vendor: org.springframework
                    # product: spring-webflux
                    vendor = tmpA[0]
                    product = tmpA[len(tmpA) - 1]
                version = p["vulnerableVersionRange"]
                (
                    version_start_including,
                    version_end_including,
                    version_start_excluding,
                    version_end_excluding,
                ) = self.get_version_range(version)
                top_fix_version = p.get("firstPatchedVersion")
                if not top_fix_version or not top_fix_version.get("identifier"):
                    top_fix_version = {"identifier": ""}
                fix_version = top_fix_version.get("identifier", {})
                (
                    fix_version_start_including,
                    fix_version_end_including,
                    fix_version_start_excluding,
                    fix_version_end_excluding,
                ) = self.get_version_range(fix_version)

                severity = p["severity"]
                score, severity, vectorString, attackComplexity = get_default_cve_data(
                    severity
                )
                exploitabilityScore = score
                description = """# {}
{}
            """.format(
                    cve.get("summary"), cve.get("description")
                )

                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id="UNKNOWN",
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vectorString,
                    vendor=vendor.lower(),
                    product=product.lower(),
                    version="*",
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
                    publishedDate=cve["publishedAt"],
                    lastModifiedDate=cve["updatedAt"],
                )
                try:
                    tdata_json = json_lib.loads(tdata)
                    vuln = NvdSource.convert_vuln(tdata_json)
                    vuln.description = description
                    ret_data.append(vuln)
                except Exception as e:
                    LOG.debug(e)
        return ret_data, page_info
