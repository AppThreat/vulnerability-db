"""
NPM Security Advisory to NVD CVE converter

This module implements basic functionality to query npm registry for security advisories
"""
import logging

import httpx
import orjson

from vdb.lib import config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    compress_str,
    convert_md_references,
    convert_to_occurrence,
    fix_text,
    get_cvss3_from_vector,
    get_default_cve_data,
    serialize_vuln_list,
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
                tmp_a = pkg.split("|")
                version = tmp_a[len(tmp_a) - 1]
                name = tmp_a[len(tmp_a) - 2]
                if len(tmp_a) == 3:
                    vendor = tmp_a[0]
            key = name
            if vendor:
                key = f"{vendor}/{name}"
            requires[key] = version
            dependencies[key] = {"version": version}
        payload["requires"] = requires
        payload["dependencies"] = dependencies
        return convert_to_occurrence(serialize_vuln_list(self.fetch(payload)))

    def fetch(self, payload):
        client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
        LOG.debug("Fetch npm advisory from %s", config.NPM_AUDIT_URL)
        r = client.post(url=config.NPM_AUDIT_URL, json=payload)
        json_data = r.json()
        return self.convert(json_data)

    def download_recent(self):
        """Method which downloads the recent CVE"""
        client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
        url = config.NPM_ADVISORIES_URL + "?perPage=100&page=1"
        r = client.get(url=url)
        if r.ok:
            json_data = r.json()
            data = self.convert(json_data.get("objects"))
            if data:
                self.store(data)
            return data
        return []

    def download_all(self):
        """Download all historic cve data"""
        data_list = []
        client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
        url = config.NPM_ADVISORIES_URL + "?perPage=100&page=1"
        for y in range(0, int(config.NPM_PAGES_COUNT)):
            r = client.get(url=url)
            if r.ok:
                json_data = r.json()
                data = self.convert(json_data.get("objects"))
                if data:
                    self.store(data)
                data_list += data
                if json_data.get("urls", {}).get("next"):
                    url = config.NPM_SERVER + json_data.get("urls").get("next")
                else:
                    break
        return data_list

    @staticmethod
    def get_version_ranges(version_str):
        """
        Version range formats used by npm
        <1.10.2
        <=4.0.13 || >=4.1.0 <4.1.2
        >=4.0.14 <4.1.0 || >=4.1.2
        :param version_str:
        :return: List of version ranges
        """
        version_list = []
        tmp_a = version_str.split("||")
        for ver in tmp_a:
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
            tmp_b = ver.split(" ")
            if tmp_b[0] == ">=" and len(tmp_b) > 1:
                version_start_including = tmp_b[1]
            elif tmp_b[0].startswith(">="):
                version_start_including = tmp_b[0].replace(">=", "")
            elif tmp_b[0].startswith(">"):
                version_start_excluding = tmp_b[0].replace(">", "")
            if tmp_b[-1].startswith("<="):
                version_end_including = tmp_b[-1].replace("<=", "")
            elif tmp_b[-1].startswith("<"):
                version_end_excluding = tmp_b[-1].replace("<", "")
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
        assigner = "github_m"
        # Iterate the cve list if available
        cves = v.get("cves")
        if not cves:
            cves = ["{}-{}".format("NPM", v.get("id"))]
        for cve_id in cves:
            published_date = v["created"]
            last_modified_date = v["updated"]
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
            references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
            if isinstance(references, bytes):
                references = references.decode("utf-8", "ignore")
            severity = v.get("severity")
            vendor = "npm"
            product = v["module_name"]
            score, severity, vector_string, attack_complexity = get_default_cve_data(
                severity
            )
            cvss = v.get("cvss")
            user_interaction = "REQUIRED"
            exploitability_score = score
            metadata = v.get("metadata", {})
            if isinstance(metadata, dict) and metadata.get("exploitability"):
                exploitability_score = metadata.get("exploitability")
            if cvss:
                if cvss.get("score"):
                    score = cvss.get("score")
                if cvss.get("vectorString"):
                    vector_string = cvss.get("vectorString")
                    if vector_string:
                        cvss3_obj = get_cvss3_from_vector(vector_string)
                        if cvss3_obj:
                            exploitability_score = cvss3_obj.get("temporalScore")
                            attack_complexity = cvss3_obj.get("attackComplexity")
                            user_interaction = cvss3_obj.get("userInteraction")
            cwe_id = v.get("cwe")
            findings = v.get("findings")
            used_version = ""
            if findings and len(findings):
                used_version = findings[0].get("version")
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
                    vectorString=vector_string,
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
                    attackComplexity=attack_complexity,
                    score=score,
                    userInteraction=user_interaction,
                    exploitabilityScore=exploitability_score,
                    publishedDate=published_date,
                    lastModifiedDate=last_modified_date,
                )
                try:
                    vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                    vuln.description = compress_str(description)
                    ret_data.append([vuln, f"""{v["id"]}|{product}|{used_version}"""])
                except Exception as e:
                    LOG.debug(e)
                vr = vr + 1
        return ret_data
