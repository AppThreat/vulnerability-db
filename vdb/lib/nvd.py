import datetime
import gzip
import logging
from collections import defaultdict
from urllib.parse import urlparse

import httpx
import orjson

from vdb.lib import (
    CPE_FULL_REGEX,
    CustomNamedTemporaryFile,
    CvssV3,
    Vulnerability,
    VulnerabilityDetail,
    config,
)
from vdb.lib.cve import CVESource
from vdb.lib.utils import url_to_purl


logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

# Start year of historic cve data
start_year = config.NVD_START_YEAR
# Current time
now = datetime.datetime.now()
# Size of the stream to read and write to the file
DOWNLOAD_CHUNK_SIZE = 128

purl_proposal_cache = defaultdict(list)


def filterable_cve(cve_id: str) -> bool:
    """Method to check if the CVE id is less than the start year"""
    if not cve_id.startswith("CVE"):
        return False
    for year in range(1999, start_year):
        if cve_id.startswith(f"CVE-{year}-"):
            return True
    return False


def get_version(inc_version: str, exc_version: str) -> str:
    """
    Method to determine whether to use including or excluding version
    :param inc_version: Including version
    :param exc_version: Excluding version
    :return: Including version if it is not empty or *. Excluding version otherwise
    """
    if inc_version and inc_version != "*":
        return inc_version
    return exc_version


def filterable_git_url(url: str, hostname: str) -> bool:
    if "git" not in hostname:
        return True
    for part in (
        "cve",
        "disclosure",
        "secdb",
        "research",
        "exploit",
        "security-advisory",
        "advisories",
        "bulletins",
        "pocs",
        "_poc",
        "/poc",
        "0day",
        "vulnerabilit",
        "xss",
        "cisagov",
        "-post/",
        "_posts",
        ".pdf",
        "covering360",
        "fuzz",
        "-csrf",
        "advisory-db",
        "defcon",
        "audit-",
        "announcements",
        "divide-by-zero",
        "security-research",
        "apidoc",
        "-query-help",
        "/blog",
        "/news",
        "/support/",
        "/bug_report",
        "nu11secur1ty",
    ):
        if part in url.lower():
            return True
    for part in (
        "github.io",
        "gist.github.com",
        "about.gitlab.com",
        "lists.apache.org",
        "gitbooks.io",
        "githubusercontent.com",
        "enterprise.github.com",
        "git-scm.com",
        "docs.",
    ):
        if part in hostname.lower():
            return True
    return False


def get_alt_cpes(cpe_uri, git_urls):
    alt_cpes = []
    parsed_git_repo_names: dict[str, bool] = {}
    # Try to extract any git references from related urls
    # See: https://github.com/AppThreat/vulnerability-db/issues/91
    for agit_url in git_urls:
        url_obj = urlparse(agit_url)
        # Ignore obvious filterable urls
        if filterable_git_url(agit_url, url_obj.hostname) or (
            not url_obj.path and not url_obj.query
        ):
            continue
        purl_obj = url_to_purl(agit_url)
        if not purl_obj:
            continue
        git_repo_product = f"{purl_obj.get('namespace')}/{purl_obj.get('name')}"
        if not parsed_git_repo_names.get(git_repo_product):
            parsed_git_repo_names[git_repo_product] = True
            # We only need 2 new aliases
            if len(purl_proposal_cache.get(cpe_uri, [])) > 2:
                purl_proposal_cache[cpe_uri].pop(0)
            purl_proposal_cache[cpe_uri].append(
                f"cpe:2.3:a:{purl_obj['type']}:{git_repo_product}:*:*:*:*:*:*:*:*"
            )
    # See if there is something useful in the cache
    if not alt_cpes:
        alt_cpes = purl_proposal_cache.get(cpe_uri, [])
    return alt_cpes


class NvdSource(CVESource):
    """NVD CVE source. This uses CVE json 1.1 format that are split based on the year"""

    def download_all(self):
        """Download all historic cve data"""
        super().download_all()
        for y in range(now.year, int(start_year) - 1, -1):
            data = self.fetch(y)
            if not data:
                continue
            self.store(data)

    def download_recent(self):
        """Method which downloads the recent CVE gzip from NVD"""
        # Create database
        data = self.fetch("recent")
        if data:
            self.store(data)
        return data

    def fetch(self, year: int | str) -> list[Vulnerability] | None:
        """Private Method which downloads the given CVE gzip from NVD"""
        url = config.NVD_URL % dict(year=year)
        LOG.debug("Download NVD CVE from %s", url)
        with CustomNamedTemporaryFile() as tf:
            try:
                with httpx.stream("GET", url, follow_redirects=True, timeout=180) as r:
                    for chunk in r.iter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
                        tf.write(chunk)
                    tf.flush()
            except Exception:
                logging.warning("Exception while downloading NVD feed from %s", url)
                return None
            with gzip.open(tf.name, "rb") as gzipjf:
                try:
                    cve_data = gzipjf.read()
                    json_data = orjson.loads(cve_data)
                    return self.convert(json_data)
                except Exception:
                    logging.warning(
                        "Exception while parsing NVD CVE feed for %s. Please try after some time",
                        year,
                    )
                    return None

    def convert(self, cve_data: dict) -> list[Vulnerability]:
        """Convert cve data to Vulnerability"""
        # If this the data from the api, use the new convert_api method
        if not cve_data.get("CVE_Items") and cve_data.get("vulnStatus"):
            return self._convert_api(cve_data)
        items = cve_data.get("CVE_Items")
        data = []
        for cve_item in items:
            v = NvdSource.convert_vuln(cve_item)
            if v:
                data.append(v)
        return data

    @staticmethod
    def _convert_api(api_data: dict) -> list[Vulnerability]:
        """Convert NVD API data to vulnerability"""
        v = NvdSource.convert_api_vuln(api_data)
        return [v] if v else []

    def refresh(self):
        """Refresh CVE data"""
        return self.download_all()

    def bulk_search(self, app_info, pkg_list):
        """
        Bulk search the resource instead of downloading the information
        :return: Vulnerability result
        """

    @staticmethod
    def convert_vuln(vuln: dict) -> Vulnerability | None:
        vid = vuln["cve"]["CVE_data_meta"]["ID"]
        if filterable_cve(vid):
            return None
        assigner = vuln["cve"]["CVE_data_meta"]["ASSIGNER"]
        # CWE
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
                vector_string=cvss_data["vectorString"],
            )
            severity = cvss_data["baseSeverity"]
            base_score = cvss_v3.base_score
        details = NvdSource.convert_vuln_detail(vuln)
        if not details:
            return None
        return Vulnerability(
            vid,
            assigner,
            problem_type,
            base_score,
            severity,
            description,
            related_urls,
            details,
            cvss_v3,
            vuln["lastModifiedDate"],
            vuln["publishedDate"],
        )

    @staticmethod
    def convert_vuln_detail(vuln: dict) -> list[VulnerabilityDetail] | None:
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
                    detail["mii"] = cpe.get("versionStartIncluding")
                    detail["mie"] = cpe.get("versionStartExcluding")
                    detail["mai"] = cpe.get("versionEndIncluding")
                    detail["mae"] = cpe.get("versionEndExcluding")
                    detail["source_update_time"] = vuln["lastModifiedDate"]
                    detail["source_orig_time"] = vuln["publishedDate"]
                    cpe_details_list.append(detail)
                else:  # cpe is not vulnerable
                    if node["operator"] == "OR":
                        fix_cpe_uri = cpe["cpe23Uri"]
            # Add fix version details
            for det in cpe_details_list:
                if fix_cpe_uri:
                    det["fixed_location"] = fix_cpe_uri
                adetail = VulnerabilityDetail.from_dict(det)
                if adetail:
                    details.append(adetail)
        if not details:
            return None
        return details

    @staticmethod
    def convert_api_vuln_detail(vuln: dict) -> list[VulnerabilityDetail] | None:
        """Convert configurations section from the API into details"""
        config_list = vuln.get("configurations", [])
        details = []
        rdata = vuln.get("references", [])
        git_urls = [r["url"].lower() for r in rdata if "git" in r["url"]]
        # Alternative CPEs identified for the given vulnerability detail
        vuln_alt_cpes = {}
        for aconfig in config_list:
            cpe_list = []
            nodes = aconfig.get("nodes", [])
            oper = aconfig.get("operator", "")
            # AND operator flow
            if oper == "AND":
                for cc in nodes:
                    if not cc.get("negate"):
                        cpe_list += filter(
                            lambda c: c.get("vulnerable"), cc["cpeMatch"]
                        )
            for anode in nodes:
                if not anode.get("negate"):
                    cpe_list += filter(
                        lambda c: c.get("vulnerable"), anode.get("cpeMatch", [])
                    )
            cpe_details_list = []
            for cpe in cpe_list:
                cpe_uri = cpe["criteria"]
                # Ignore os and hardware vulnerabilities from nvd
                if (
                    cpe_uri
                    and cpe_uri.startswith("cpe:2.3:o")
                    or cpe_uri.startswith("cpe:2.3:h")
                ):
                    continue
                all_parts = CPE_FULL_REGEX.match(cpe_uri)
                # If a single version is mentioned using cpe then use that as a fallback
                single_version = ""
                if (
                    all_parts
                    and all_parts.group("version")
                    and all_parts.group("version") != "*"
                ):
                    single_version = all_parts.group("version")
                    # Version numbers could have erroneous \ or commas
                    if single_version:
                        single_version = single_version.removeprefix(",").removesuffix("\\").strip()
                version_start_including = cpe.get(
                    "versionStartIncluding", single_version
                )
                version_end_including = cpe.get("versionEndIncluding", single_version)
                detail = {
                    "cpe_uri": cpe_uri,
                    "mii": version_start_including,
                    "mie": cpe.get("versionStartExcluding"),
                    "mai": version_end_including,
                    "mae": cpe.get("versionEndExcluding"),
                    "source_update_time": vuln["lastModified"],
                    "source_orig_time": vuln["published"],
                }
                cpe_details_list.append(detail)
                alt_cpes = get_alt_cpes(detail["cpe_uri"], git_urls)
                for altc in alt_cpes:
                    # Filter duplicates
                    if vuln_alt_cpes.get(altc):
                        continue
                    new_git_detail = detail.copy()
                    new_git_detail["cpe_uri"] = altc
                    cpe_details_list.append(new_git_detail)
                    vuln_alt_cpes[altc] = True
            for det in cpe_details_list:
                adetail = VulnerabilityDetail.from_dict(det)
                if adetail:
                    details.append(adetail)
        if not details:
            return None
        return details

    @staticmethod
    def _get_value(vuln: dict, key: str) -> str:
        if vuln.get(key):
            value = vuln[key]
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                for val in value:
                    if isinstance(val, dict):
                        if val.get("lang", "") == "en":
                            return val.get("value")
        return ""

    @staticmethod
    def convert_api_vuln(vuln: dict) -> Vulnerability | None:
        # Undergoing Analysis, Analyzed, Modified, Deferred are accepted.
        # Only the below 3 can be rejected
        if vuln["vulnStatus"] in ("Awaiting Analysis", "Rejected", "Received"):
            return None
        vid = vuln["id"]
        assigner = vuln["sourceIdentifier"]
        # CWE
        problem_type = ""
        for aweakness in vuln.get("weaknesses", []):
            if aweakness.get("description") and aweakness["description"][0][
                "value"
            ].startswith("CWE-"):
                problem_type = aweakness["description"][0]["value"]
                break
        description = NvdSource._get_value(vuln, "descriptions")
        rdata = vuln.get("references", [])
        related_urls = [r["url"] for r in rdata]
        metrics = vuln.get("metrics", {})
        cvss_metrics = []
        if metrics.get("cvssMetricV31"):
            cvss_metrics = metrics.get("cvssMetricV31")
        elif metrics.get("cvssMetricV30"):
            cvss_metrics = metrics.get("cvssMetricV30")
        cvss_data = cvss_metrics[0].get("cvssData")
        cvss_v3 = CvssV3(
            base_score=cvss_data["baseScore"],
            exploitability_score=cvss_metrics[0]["exploitabilityScore"],
            impact_score=cvss_metrics[0]["impactScore"],
            attack_vector=cvss_data["attackVector"],
            attack_complexity=cvss_data["attackComplexity"],
            privileges_required=cvss_data["privilegesRequired"],
            user_interaction=cvss_data["userInteraction"],
            scope=cvss_data["scope"],
            confidentiality_impact=cvss_data["confidentialityImpact"],
            integrity_impact=cvss_data["integrityImpact"],
            availability_impact=cvss_data["availabilityImpact"],
            vector_string=cvss_data["vectorString"],
        )
        severity = cvss_data["baseSeverity"]
        base_score = cvss_v3.base_score
        details = NvdSource.convert_api_vuln_detail(vuln)
        if not details:
            return None
        return Vulnerability(
            vid,
            assigner,
            problem_type,
            base_score,
            severity,
            description,
            related_urls,
            details,
            cvss_v3,
            vuln["lastModified"],
            vuln["published"],
        )
