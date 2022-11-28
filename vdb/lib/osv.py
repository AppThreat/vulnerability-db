"""
osv to NVD CVE converter

This module fetches the vulnerability data from osv.dev and stores them in NVD CVE 1.1 json format.
"""
from zipfile import ZipFile

import requests

from vdb.lib import CustomNamedTemporaryFile
from vdb.lib import config as config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    convert_score_severity,
    get_cvss3_from_vector,
    get_default_cve_data,
    parse_purl,
)

# Size of the stream to read and write to the file
download_chunk_size = 4096

try:
    import orjson

    ORJSON_AVAILABLE = True
except ImportError:
    import json

    ORJSON_AVAILABLE = False

json_lib = orjson if ORJSON_AVAILABLE else json

vendor_overrides = {"apk": "alpine", "deb": "debian"}


class OSVSource(NvdSource):
    """OSV CVE source"""

    def download_all(self, local_store=True):
        """Download all cve data"""
        # For performance do not retain the whole data in-memory
        # See: https://github.com/AppThreat/vulnerability-db/issues/27
        data_list = []
        for lang, url in config.osv_url_dict.items():
            data = self.fetch(url)
            if not data:
                continue
            if local_store:
                self.store(data)
        return data_list

    def download_recent(self, local_store=True):
        raise NotImplementedError

    def fetch(self, url):
        ret_data = []
        with CustomNamedTemporaryFile() as tf:
            try:
                r = requests.get(url, stream=True)
                for chunk in r.iter_content(chunk_size=download_chunk_size):
                    tf.write(chunk)
                tf.flush()
            except Exception:
                return ret_data
            with ZipFile(tf.name, "r") as zipfp:
                for zf in zipfp.namelist():
                    if zf.endswith(".json"):
                        with zipfp.open(zf) as jsonf:
                            cve_data = jsonf.read()
                            try:
                                json_data = json_lib.loads(cve_data)
                                ret_data += self.convert(json_data)
                            except Exception as e:
                                pass
        return ret_data

    def convert(self, cve_data):
        if cve_data.get("withdrawn"):
            return []
        return self.to_vuln(cve_data)

    def to_vuln(self, cve_data):
        ret_data = []
        if not cve_data.get("affected"):
            return ret_data
        cve_id = cve_data.get("id")
        cwe_id = ""
        cve_references = cve_data.get("references", [])
        aliases = cve_data.get("aliases", [])
        aliases_block = ""
        if aliases and len(aliases) > 1:
            aliases_block = """
## Related CVE(s)
{}
            """.format(
                ", ".join(aliases)
            )
        description = """# {}
{}
{}
            """.format(
            cve_data.get("summary", "Summary"),
            cve_data.get("details", ""),
            aliases_block,
        )
        references = []
        # Change the key from type to name in references
        for aref in cve_references:
            references.append({"name": aref.get("type", "url"), "url": aref.get("url")})
        references = json_lib.dumps(references)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        # Try to locate the CVE id from the aliases section
        if not cve_id.startswith("CVE") and not cve_id.startswith("RUSTSEC"):
            for i in aliases:
                if not i.startswith("OSV"):
                    cve_id = i
                    break
        assigner = "OSV"
        vectorString = ""
        if cve_id.startswith("GHSA"):
            assigner = "@github"
        elif cve_id.startswith("CVE"):
            assigner = "cve@mitre.org"
        elif cve_id.startswith("NPM"):
            assigner = "@npm"
        severity = "LOW"
        if cve_data.get("severity"):
            severity_list = cve_data.get("severity")
            for sv in severity_list:
                if sv["type"] == "CVSS_V3":
                    vectorString = sv["score"]
        # Issue 58
        cve_database_specific = cve_data.get("database_specific")
        cve_ecosystem_specific = cve_data.get("ecosystem_specific")
        if cve_database_specific:
            if cve_database_specific.get("severity"):
                severity = cve_database_specific.get("severity")
            if cve_database_specific.get("cwe_ids"):
                cwes = cve_database_specific.get("cwe_ids")
                if isinstance(cwes, list):
                    cwe_id = ",".join(cwes)
        if cve_ecosystem_specific and cve_ecosystem_specific.get("severity"):
            severity = cve_ecosystem_specific.get("severity")
        for pkg_data in cve_data.get("affected"):
            if pkg_data.get("ecosystem_specific"):
                ecosystem_specific = pkg_data.get("ecosystem_specific")
                if ecosystem_specific.get("severity"):
                    severity = ecosystem_specific.get("severity")
            if pkg_data.get("database_specific"):
                database_specific = pkg_data.get("database_specific")
                if database_specific.get("cwes"):
                    cwes = database_specific.get("cwes")
                    if isinstance(cwes, list):
                        cwe_id = cwes[0].get("cweId")
                if database_specific.get("cvss"):
                    cvss = database_specific.get("cvss")
                    if isinstance(cvss, dict):
                        if cvss.get("severity"):
                            severity = cvss.get("severity", "").upper()
                        if not vectorString and cvss.get("vectorString"):
                            vectorString = cvss.get("vectorString")
                        if cvss.get("score"):
                            score = cvss.get("score")
                            severity = convert_score_severity(score)
            if vectorString:
                cvss3_obj = get_cvss3_from_vector(vectorString)
                score = cvss3_obj.get("baseScore")
                severity = cvss3_obj.get("baseSeverity")
                exploitabilityScore = cvss3_obj.get("temporalScore")
                attackComplexity = cvss3_obj.get("attackComplexity")
            else:
                score, severity, dvectorString, attackComplexity = get_default_cve_data(
                    severity
                )
                # Set the default vector string only if unavailable
                if not vectorString and dvectorString:
                    vectorString = dvectorString
                exploitabilityScore = score
            ranges = pkg_data.get("ranges", [])
            vendor = pkg_data.get("package", {}).get("ecosystem", "").lower()
            pkg_name = pkg_data.get("package", {}).get("name", "")
            purl = parse_purl(pkg_data.get("package", {}).get("purl", ""))
            if purl:
                if purl.get("namespace"):
                    vendor = purl["namespace"]
                if purl.get("name"):
                    pkg_name = purl["name"]
            if ":" in pkg_name:
                tmpA = pkg_name.split(":")
                if len(tmpA) == 2:
                    vendor = tmpA[0]
                    pkg_name = tmpA[-1]
            # For OS packages, such as alpine OSV appends the os version to the vendor which is weird
            # Let's remove it to keep things sane
            if ":" in vendor:
                vendor = vendor.split(":")[0]
            # Substitute alpine for apk and debian for deb
            if vendor_overrides.get(vendor):
                vendor = vendor_overrides.get(vendor)
            for r in ranges:
                events = r.get("events")
                versions_list = r.get("versions", [])
                version_end_including = ""
                version_start_excluding = ""
                version_end_excluding = ""
                fix_version_start_including = ""
                fix_version_end_including = ""
                fix_version_start_excluding = ""
                fix_version_end_excluding = ""
                version_start_including = ""
                if versions_list:
                    version_start_including = versions_list[0]
                    if (
                        len(versions_list) > 1
                        and version_start_including != versions_list[-1]
                    ):
                        version_end_including = versions_list[-1]
                for ev in events:
                    # Reset all versions for introduced event
                    if ev.get("introduced"):
                        version_end_including = ""
                        version_start_excluding = ""
                        version_end_excluding = ""
                        fix_version_start_including = ""
                        fix_version_end_including = ""
                        fix_version_start_excluding = ""
                        fix_version_end_excluding = ""
                        version_start_including = ev.get("introduced")
                    if ev.get("fixed"):
                        fix_version_start_including = ev.get("fixed")
                        fix_version_end_including = ev.get("fixed")
                        version_end_excluding = ev.get("fixed")
                    if ev.get("last_affected"):
                        version_end_including = ev.get("last_affected")
                    if ev.get("limit"):
                        version_end_excluding = ev.get("limit")
                    # Create an entry for each introduced + fixed/limit event
                    if version_start_including and (
                        fix_version_start_including
                        or version_end_including
                        or version_end_excluding
                    ):
                        tdata = config.CVE_TPL % dict(
                            cve_id=cve_id,
                            cwe_id=cwe_id,
                            assigner=assigner,
                            references=references,
                            description="",
                            vectorString=vectorString,
                            vendor=vendor,
                            product=pkg_name,
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
                            publishedDate=cve_data.get("published"),
                            lastModifiedDate=cve_data.get("modified"),
                        )
                        try:
                            vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                            vuln.description = description
                            ret_data.append(vuln)
                        except Exception as e:
                            pass
        return ret_data
