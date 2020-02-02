"""
GitHub Security Advisory to NVD CVE convertor

This simple script fetches the recent security advisories from GitHub and stores them in NVD CVE 1.1 jsonlines format. Below substitutions are made to properly construct the NVD CVE Json

- versionStartIncluding and versionEndIncluding are calculated from version range. Version End is chosen to hold any single version number being passed
- vectorString is constructed based on severity. The official calculator [url](https://www.first.org/cvss/calculator/3.1) was used to construct some realistic strings for given severity
- Full description (description) is ignored for now

"""
import json
import logging
import os
import re

import requests

import vulndb.lib.config as config
from vulndb.lib.nvd import NvdSource

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


CVE_TPL = """
{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"%(cve_id)s","ASSIGNER":"%(assigner)s"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"%(cwe_id)s"}]}]},"references":{"reference_data": %(references)s},"description":{"description_data":[{"lang":"en","value":"%(description)s"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:*:*:*:*:*:*","versionStartIncluding":"%(version_start)s","versionEndIncluding":"%(version_end)s"}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"%(vectorString)s","attackVector":"NETWORK","attackComplexity":"%(attackComplexity)s","privilegesRequired":"NONE","userInteraction":"REQUIRED","scope":"UNCHANGED","confidentialityImpact":"%(severity)s","integrityImpact":"%(severity)s","availabilityImpact":"%(severity)s","baseScore":%(score).1f,"baseSeverity":"%(severity)s"},"exploitabilityScore":%(score).1f,"impactScore":%(score).1f},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"NONE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL","baseScore":%(score).1f},"severity":"%(severity)s","exploitabilityScore":%(score).1f,"impactScore":%(score).1f,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}},"publishedDate":"%(publishedDate)s","lastModifiedDate":"%(lastModifiedDate)s"}
"""

api_token = os.environ.get("GITHUB_TOKEN")
headers = {"Authorization": "token %s" % api_token}


def get_query(type="recent"):
    """
    """
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
    """GitHub CVE source
    """

    def download_all(self):
        """Download all historic cve data
        """
        data_list = []
        lastId = None
        for y in range(0, int(config.gha_pages_count)):
            data, page_info = self.fetch(type=lastId)
            if data:
                self.store(data)
                data_list += data
            if page_info and page_info["hasNextPage"]:
                lastId = page_info["endCursor"]
        return data_list

    def download_recent(self):
        """Method which downloads the recent CVE
        """
        data, page_info = self.fetch("recent")
        if data:
            self.store(data)
        return data

    def fetch(self, type):
        """Private method to fetch the advisory data via GraphQL api
        """
        LOG.info(
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
        """
        version_start = ""
        version_end = "*"
        if version_str.startswith("= "):
            version_end = version_str.replace("= ", "")
        elif version_str.startswith("<= "):
            version_end = version_str.replace("<= ", "")
        # FIXME: This could lead to more false positives
        elif version_str.startswith("< "):
            version_end = version_str.replace("< ", "")
        elif version_str.startswith(">= "):
            version_str = version_str.replace(">= ", "")
            tmpA = version_str.split(", ")
            version_start = tmpA[0]
            version_end = tmpA[len(tmpA) - 1].replace("< ", "").replace("<= ", "")
        return version_start, version_end

    def convert(self, cve_data):
        """Convert the GitHub advisory data into Vulnerability objects

        TODO: Fix version information is getting ignored since the CVE Json format does not support this attribute
        """
        ret_data = []
        if cve_data.get("errors"):
            return ret_data, None
        if cve_data.get("message") and cve_data.get("message") == "Bad credentials":
            LOG.warning("GITHUB_TOKEN environment variable is invalid!")
            return ret_data, None
        page_info = cve_data["data"]["securityAdvisories"]["pageInfo"]
        for cve in cve_data["data"]["securityAdvisories"]["nodes"]:
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
            for p in cve["vulnerabilities"]["nodes"]:
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
                version_start, version_end = self.get_version_range(version)
                vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                score = 9.0
                severity = p["severity"]
                attackComplexity = severity
                if p["severity"] == "LOW":
                    score = 2.0
                    attackComplexity = "HIGH"
                    vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
                elif p["severity"] == "MODERATE":
                    score = 5.0
                    severity = "MEDIUM"
                    vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
                elif p["severity"] == "HIGH":
                    score = 7.5
                    attackComplexity = "LOW"
                    vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                tdata = CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id="UNKNOWN",
                    assigner=assigner,
                    references=json.dumps(references),
                    description=cve["summary"],
                    vectorString=vectorString,
                    vendor=vendor.lower(),
                    product=product.lower(),
                    version="*",
                    version_start=version_start,
                    version_end=version_end,
                    severity=severity,
                    attackComplexity=attackComplexity,
                    score=score,
                    publishedDate=cve["publishedAt"],
                    lastModifiedDate=cve["updatedAt"],
                )
                vuln = NvdSource.convert_vuln(json.loads(tdata))
                ret_data.append(vuln)
        return ret_data, page_info
