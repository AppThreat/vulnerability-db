import datetime
import gzip
import logging

try:
    import orjson

    ORJSON_AVAILABLE = True
except ImportError:
    import json

    ORJSON_AVAILABLE = False

import requests

from vdb.lib import (
    CustomNamedTemporaryFile,
    CvssV3,
    Vulnerability,
    VulnerabilityDetail,
    VulnerabilitySource,
)
from vdb.lib import config as config
from vdb.lib import db as dbLib

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

# Start year of historic cve data
start_year = config.nvd_start_year
# Current time
now = datetime.datetime.now()
# Size of the stream to read and write to the file
download_chunk_size = 128
# Create database
db = dbLib.get()

json_lib = orjson if ORJSON_AVAILABLE else json


def get_version(inc_version, exc_version):
    """
    Method to determine whether to use including or excluding version
    :param inc_version: Including version
    :param exc_version: Excluding version
    :return: Including version if it is not empty or *. Excluding version otherwise
    """
    if inc_version and inc_version != "*":
        return inc_version
    return exc_version


class NvdSource(VulnerabilitySource):
    """NVD CVE source. This uses CVE json 1.1 format that are split based on the year"""

    def download_all(self, local_store=True):
        """Download all historic cve data"""
        data_list = []
        for y in range(now.year, int(start_year) - 1, -1):
            data = self.fetch(y)
            if not data:
                continue
            if local_store:
                self.store(data)
        return data_list

    def download_recent(self, local_store=True):
        """Method which downloads the recent CVE gzip from NVD"""
        data = self.fetch("recent")
        if local_store:
            self.store(data)
        return data

    def fetch(self, year):
        """Private Method which downloads the given CVE gzip from NVD"""
        url = config.nvd_url % dict(year=year)
        LOG.debug("Download NVD CVE from {}".format(url))
        with CustomNamedTemporaryFile() as tf:
            try:
                r = requests.get(url, stream=True)
            except Exception:
                logging.warning(f"Exception while downloading NVD feed from {url}")
                return None
            for chunk in r.iter_content(chunk_size=download_chunk_size):
                tf.write(chunk)
            tf.flush()
            with gzip.open(tf.name, "rb") as gzipjf:
                try:
                    cve_data = gzipjf.read()
                    json_data = json_lib.loads(cve_data)
                    return self.convert(json_data)
                except Exception:
                    logging.warning(
                        f"Exception while parsing NVD CVE feed for {year}. Please try after some time"
                    )
                    return None

    def convert(self, cve_data):
        """Convert cve data to Vulnerability"""
        items = cve_data.get("CVE_Items")
        data = []
        for cve_item in items:
            v = NvdSource.convert_vuln(cve_item)
            if v:
                data.append(v)
        return data

    def refresh(self):
        """Refresh CVE data"""
        return self.download_all()

    def store(self, data, reindex=True):
        """Store data in the database"""
        docs = dbLib.store(db, data, reindex)
        return docs

    def bulk_search():
        """
        Bulk search the resource instead of downloading the information
        :return: Vulnerability result
        """
        raise NotImplementedError

    @staticmethod
    def convert_vuln(vuln):
        id = vuln["cve"]["CVE_data_meta"]["ID"]
        problem_type = ""
        if (
            vuln["cve"]["problemtype"]["problemtype_data"]
            and vuln["cve"]["problemtype"]["problemtype_data"][0]["description"]
        ):
            problem_type = vuln["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ][0]["value"]
        cvss_v3 = None
        severity = None
        base_score = None
        description = vuln["cve"]["description"]["description_data"][0]["value"]
        # Issue 12 - Ignore disputed vulnerabilities
        if "** DISPUTED **" in description:
            return None
        rdata = vuln.get("cve", {}).get("references", {}).get("reference_data", [])
        related_urls = [r["url"] for r in rdata]
        if "baseMetricV3" in vuln["impact"]:
            cvss_data = vuln["impact"]["baseMetricV3"]["cvssV3"]
            cvss_data["exploitabilityScore"] = vuln["impact"]["baseMetricV3"][
                "exploitabilityScore"
            ]
            cvss_data["impactScore"] = vuln["impact"]["baseMetricV3"]["impactScore"]
            cvss_v3 = CvssV3(
                base_score=cvss_data["baseScore"],
                exploitability_score=cvss_data["exploitabilityScore"],
                impact_score=cvss_data["impactScore"],
                attack_vector=cvss_data["attackVector"],
                attack_complexity=cvss_data["attackComplexity"],
                privileges_required=cvss_data["privilegesRequired"],
                user_interaction=cvss_data["userInteraction"],
                scope=cvss_data["scope"],
                confidentiality_impact=cvss_data["confidentialityImpact"],
                integrity_impact=cvss_data["integrityImpact"],
                availability_impact=cvss_data["availabilityImpact"],
            )
            severity = cvss_data["baseSeverity"]
            base_score = cvss_v3.base_score
        details = NvdSource.convert_vuln_detail(vuln)
        if not details:
            return None
        return Vulnerability(
            id,
            problem_type,
            base_score,
            severity,
            description,
            related_urls,
            details,
            cvss_v3,
            vuln["lastModifiedDate"],
        )

    @staticmethod
    def convert_vuln_detail(vuln):
        nodes_list = vuln["configurations"]["nodes"]
        details = []
        for node in nodes_list:
            cpe_list = []
            # For AND operator we store all the cpe_matches thus
            # increasing the false-positives. But this is better than leaving
            # the CPE out altogether. Grafeas format unfortunately is not
            # suitable for AND/OR based vulnerability storage
            # min and max_affected_version can sometimes include the excluded version
            # thus, further increasing the false positives
            if node["operator"] == "AND":
                for cc in node.get("children", []):
                    cpe_list += cc["cpe_match"]
            cpe_list += node.get("cpe_match", [])
            cpe_details_list = []
            fix_cpe_uri = None
            for cpe in cpe_list:
                detail = {}
                if not cpe.get("cpe23Uri"):
                    continue
                if cpe["vulnerable"] and cpe.get("cpe23Uri"):
                    detail["cpe_uri"] = cpe["cpe23Uri"]
                    detail["min_affected_version_including"] = cpe.get(
                        "versionStartIncluding"
                    )
                    detail["min_affected_version_excluding"] = cpe.get(
                        "versionStartExcluding"
                    )
                    detail["max_affected_version_including"] = cpe.get(
                        "versionEndIncluding"
                    )
                    detail["max_affected_version_excluding"] = cpe.get(
                        "versionEndExcluding"
                    )
                    detail["source_update_time"] = vuln["lastModifiedDate"]
                    cpe_details_list.append(detail)
                else:  # cpe is not vulnerable
                    if node["operator"] == "OR":
                        fix_cpe_uri = cpe["cpe23Uri"]
            # Add fix version details
            for det in cpe_details_list:
                if fix_cpe_uri:
                    det["fixed_location"] = fix_cpe_uri
                adetail = VulnerabilityDetail.from_dict(det)
                # Include only the application details
                if adetail and adetail.package_type not in config.nvd_exclude_types:
                    details.append(adetail)
        if not details:
            return None
        return details
