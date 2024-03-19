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

import httpx
import orjson

from vdb.lib import config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import compress_str, get_default_cve_data, get_cvss3_from_vector

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

api_token = os.environ.get("GITHUB_TOKEN")
headers = {"Authorization": f"token {api_token}"}


vendor_overrides = {
    "pip": "pypi",
    "go": "golang",
    "rust": "cargo",
    "rubygems": "gem"
}


def get_query(qtype="recent"):
    """"""
    if qtype == "recent" or not qtype:
        extra_args = "first: 100"
    else:
        extra_args = 'first: 100, after: "' + str(qtype) + '"'
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

    def download_all(self):
        """Download all historic cve data"""
        data_list = []
        last_id = None
        for y in range(0, int(config.GHA_PAGES_COUNT)):
            data, page_info = self.fetch(vtype=last_id)
            if data:
                self.store(data)
            if page_info and page_info["hasNextPage"]:
                last_id = page_info["endCursor"]
        return data_list

    def download_recent(self):
        """Method which downloads the recent CVE"""
        data, _ = self.fetch("recent")
        if data:
            self.store(data)
        return data

    def fetch(self, vtype):
        """Private method to fetch the advisory data via GraphQL api"""
        LOG.debug(
            "Download GitHub advisory from %s with cursor %s", config.GHA_URL, vtype
        )
        client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
        r = client.post(
            url=config.GHA_URL, json=get_query(qtype=vtype), headers=headers
        )
        json_data = r.json()
        return self.convert(json_data)

    @staticmethod
    def get_version_range(version_str):
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
            tmp_a = version_str.split(", ")
            if tmp_a[len(tmp_a) - 1].startswith("<= "):
                version_end_including = tmp_a[len(tmp_a) - 1].replace("<= ", "")
            elif tmp_a[len(tmp_a) - 1].startswith("< "):
                version_end_excluding = tmp_a[len(tmp_a) - 1].replace("< ", "")
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
            assigner = "mitre"
            references = []
            for r in cve["references"]:
                references.append({"url": r["url"], "name": r["url"]})
            for cid in cve["identifiers"]:
                if cid["type"] == "CVE":
                    cve_id = cid["value"]
            if not cve_id:
                cve_id = cve["ghsaId"]
                assigner = "github_m"
            references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
            if isinstance(references, bytes):
                references = references.decode("utf-8", "ignore")
            for p in cve["vulnerabilities"]["nodes"]:
                if not p:
                    continue
                vendor = p["package"]["ecosystem"].lower()
                product = p["package"]["name"]
                vendor = vendor_overrides.get(vendor, vendor)
                if vendor not in ("golang", "swift", "composer") and (":" in product or "/" in product):
                    tmp_a = re.split(r"[/|:]", product)
                    # This extract's the correct vendor based on the namespace
                    # Eg: org.springframework:spring-webflux would result in
                    # product: org.springframework/spring-webflux
                    product = f"{tmp_a[0]}/{tmp_a[len(tmp_a) - 1]}"
                if vendor not in ("nuget",):
                    product = product.lower()
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
                (
                    score,
                    severity,
                    vector_string,
                    attack_complexity,
                ) = get_default_cve_data(severity)
                exploitability_score = score
                cvss3_obj = get_cvss3_from_vector(vector_string)
                attack_complexity = ""
                user_interaction = "REQUIRED"
                if cvss3_obj:
                    exploitability_score = cvss3_obj.get("temporalScore")
                    attack_complexity = cvss3_obj.get("attackComplexity")
                    score = cvss3_obj.get("baseScore")
                    user_interaction = cvss3_obj.get("userInteraction")
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
                    vectorString=vector_string,
                    vendor=vendor.lower(),
                    product=product.lower(),
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
                    attackComplexity=attack_complexity,
                    score=score,
                    userInteraction=user_interaction,
                    exploitabilityScore=exploitability_score,
                    publishedDate=cve["publishedAt"],
                    lastModifiedDate=cve["updatedAt"],
                )
                try:
                    tdata_json = orjson.loads(tdata)
                    vuln = NvdSource.convert_vuln(tdata_json)
                    vuln.description = compress_str(description)
                    ret_data.append(vuln)
                except Exception as e:
                    LOG.debug(e)
        return ret_data, page_info
