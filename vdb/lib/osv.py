"""
osv to NVD CVE converter

This module fetches the vulnerability data from osv.dev and stores them in NVD CVE 1.1 json format.
"""
from zipfile import ZipFile

import httpx
import orjson
from semver import Version

from vdb.lib import CustomNamedTemporaryFile, config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    compress_str,
    convert_score_severity,
    get_cvss3_from_vector,
    get_default_cve_data,
    parse_purl,
)

# Size of the stream to read and write to the file
DOWNLOAD_CHUNK_SIZE = 4096

vendor_overrides = {
    "apk": "alpine",
    "deb": "debian",
    "go": "golang",
    "crates.io": "cargo",
    "swifturl": "swift",
    "github actions": "github"
}


class OSVSource(NvdSource):
    """OSV CVE source"""

    def download_all(self):
        """Download all cve data"""
        # For performance do not retain the whole data in-memory
        # See: https://github.com/AppThreat/vulnerability-db/issues/27
        data_list = []
        for _, url in config.osv_url_dict.items():
            data = self.fetch(url)
            if data:
                self.store(data)
        return data_list

    def download_recent(self):
        pass

    def fetch(self, url):
        ret_data = []
        client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
        with CustomNamedTemporaryFile() as tf:
            try:
                with client.stream("GET", url) as r:
                    for chunk in r.iter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
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
                                json_data = orjson.loads(cve_data)
                                ret_data += self.convert(json_data)
                            except Exception:
                                pass
        return ret_data

    def convert(self, cve_data):
        if cve_data.get("withdrawn"):
            return []
        return self.to_vuln(cve_data)

    @staticmethod
    def to_vuln(cve_data):
        ret_data = []
        if not cve_data.get("affected"):
            return ret_data
        cve_id = cve_data.get("id")
        cwe_id = ""
        edition = "*"
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
        if "** DISPUTED **" in description or "** REJECT **" in description:
            return ret_data
        references = []
        # Change the key from type to name in references
        for aref in cve_references:
            references.append({"name": aref.get("type", "url"), "url": aref.get("url")})
        references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        # Quality of PYSEC data is quite low missing both severity and score
        # Where a PYSEC feed also reference a github id, let's ignore it since G comes before P
        #   so it would have gotten processed
        # Fixes #99
        if cve_id.startswith("PYSEC"):
            for i in aliases:
                if i.startswith("GHSA"):
                    return ret_data
        # Try to locate the CVE id from the aliases section
        if not cve_id.startswith("CVE") and not cve_id.startswith("RUSTSEC"):
            for i in aliases:
                if i.startswith("CVE"):
                    cve_id = i
                    break
        assigner = "google"
        vector_string = ""
        if cve_id.startswith("GHSA"):
            assigner = "github_m"
        elif cve_id.startswith("CVE"):
            assigner = "mitre"
        elif cve_id.startswith("NPM"):
            assigner = "github_m"
        # For malwares, default to critical
        severity = "CRITICAL" if cve_id.startswith("MAL") else "LOW"
        if cve_data.get("severity"):
            severity_list = cve_data.get("severity")
            for sv in severity_list:
                if sv["type"] == "CVSS_V3":
                    vector_string = sv["score"]
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
                        if not vector_string and cvss.get("vectorString"):
                            vector_string = cvss.get("vectorString")
                        if cvss.get("score"):
                            score = cvss.get("score")
                            severity = convert_score_severity(score)
            user_interaction = "REQUIRED"
            if vector_string:
                cvss3_obj = get_cvss3_from_vector(vector_string)
                score = cvss3_obj.get("baseScore")
                severity = cvss3_obj.get("baseSeverity")
                exploitability_score = cvss3_obj.get("temporalScore")
                attack_complexity = cvss3_obj.get("attackComplexity")
                user_interaction = cvss3_obj.get("userInteraction")
            else:
                (
                    score,
                    severity,
                    dvector_string,
                    attack_complexity,
                ) = get_default_cve_data(severity)
                # Override the score for malware
                if cve_id.startswith("MAL"):
                    score = 10.0
                    user_interaction = "NONE"
                # Set the default vector string only if unavailable
                if not vector_string and dvector_string:
                    vector_string = dvector_string
                exploitability_score = score
            ranges = pkg_data.get("ranges", [])
            versions_list = pkg_data.get("versions", [])
            vendor_ecosystem = pkg_data.get("package", {}).get("ecosystem", "").lower()
            vendor = vendor_ecosystem
            pkg_name = pkg_data.get("package", {}).get("name", "")
            pkg_name_list = []
            purl = parse_purl(pkg_data.get("package", {}).get("purl", ""))
            if purl:
                if purl.get("type"):
                    vendor = purl["type"]
                if purl.get("namespace") and purl.get("name"):
                    pkg_name = f'{purl["namespace"]}/{purl["name"]}'
                elif purl.get("name"):
                    pkg_name = purl["name"]
            if ":" in pkg_name and vendor.lower() not in ("swift", "swifturl", "github", "github actions"):
                # Example: commons-fileupload:commons-fileupload
                # org.apache.tomcat:tomcat
                tmp_a = pkg_name.split(":")
                if len(tmp_a) == 2:
                    pkg_name = f"{tmp_a[0]}/{tmp_a[-1]}"
            # In case of swift, we need to remove any https protocol from the name
            if pkg_name.startswith("https://"):
                pkg_name = pkg_name.removeprefix("https://")
            if pkg_name:
                pkg_name_list.append(pkg_name)
            # Substitute alpine for apk and debian for deb
            if vendor_overrides.get(vendor):
                vendor = vendor_overrides.get(vendor)
            # Since swift allows both url and local based lookups, we store both the variations
            if vendor in ("swift", "swifturl", "github", "github actions") and pkg_name.startswith("github.com"):
                pkg_name_list.append(pkg_name.removeprefix("github.com/"))
            # For OS packages, such as alpine OSV appends the os version to the vendor
            # Let's remove it and add it to package name
            if ":" in vendor_ecosystem and (
                    "alpine" in vendor
                    or "apk" in vendor
                    or "deb" in vendor
                    or "debian" in vendor
                    or "almalinux" in vendor
                    or "rocky" in vendor
            ):
                tmp_v = vendor_ecosystem.split(":")
                vendor = tmp_v[0].lower().replace(" ", "").replace("-", "")
                vdistro = tmp_v[1]
                if vendor in ("alpine", "apk"):
                    vdistro = vdistro.replace("v", "")
                # In os-release, ID for rockylinux is simply rocky
                if "rocky" in vendor:
                    vendor = vendor.replace("linux", "")
                edition = f"{vendor}-{vdistro}"
                # Only use the precise version for os packages
                if (
                        "debian" in vendor
                        or "deb" in vendor
                        or "alpine" in vendor
                        or "apk" in vendor
                        or "almalinux" in vendor
                        or "rocky" in vendor
                ):
                    pkg_name_list = [f"{vendor}/{edition}/{pkg_name.removeprefix(vendor + '/')}"]
                else:
                    pkg_name_list.append(f"{edition}/{pkg_name}")
            # For some ecosystem, osv provides a full list of versions with partial events. See osv-pypi2.json for an example
            # Problem 1: Storing each version as-is is slowing down vdb
            # Problem 2: The versions_list may be unsorted and trying to sort based on semantic versions can fail
            # Solution: We do our best to sort the versions_list. If it fails, we assume the input is sorted and store the first and last entry as min and max.
            # The assumption seems to be working as of today, but could result in false positives or false negatives in the future.
            needs_version_backup = True
            for r in ranges:
                events = r.get("events")
                for ev in events:
                    if ev.get("introduced", "") in (0, "0", "0.0.0"):
                        break
                    if ev.get("fixed") or ev.get("last_affected"):
                        needs_version_backup = False
                        break
            if needs_version_backup and len(versions_list) > 1:
                try:
                    min_ver = min(versions_list, key=Version.parse)
                    max_ver = max(versions_list, key=Version.parse)
                except Exception:
                    min_ver = versions_list[0]
                    max_ver = versions_list[-1]
                for full_pkg in pkg_name_list:
                    tdata = config.CVE_TPL % dict(
                        cve_id=cve_id,
                        cwe_id=cwe_id,
                        assigner=assigner,
                        references=references,
                        description="",
                        vectorString=vector_string,
                        vendor=vendor,
                        product=full_pkg,
                        version="*",
                        edition=edition,
                        version_start_including=min_ver,
                        version_end_including=max_ver,
                        version_start_excluding="",
                        version_end_excluding="",
                        fix_version_start_including="",
                        fix_version_end_including="",
                        fix_version_start_excluding=max_ver,
                        fix_version_end_excluding="",
                        severity=severity,
                        attackComplexity=attack_complexity,
                        score=score,
                        userInteraction=user_interaction,
                        exploitabilityScore=exploitability_score,
                        publishedDate=cve_data.get("published"),
                        lastModifiedDate=cve_data.get("modified"),
                    )
                    try:
                        vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                        vuln.description = compress_str(description)
                        ret_data.append(vuln)
                    except Exception:
                        pass
            for r in ranges:
                if r.get("type") == "GIT" and r.get("repo"):
                    vendor = "generic"
                    repo_name = (r.get("repo").removeprefix("http://")
                                 .removeprefix("https://")
                                 .removeprefix("git://")
                                 .removesuffix("/")
                                 .removesuffix(".git")
                                 .lower())
                    # See #112
                    for special_type in ("github.com", "gitlab.com"):
                        if repo_name.startswith(special_type):
                            vendor = special_type.removesuffix(".com")
                            repo_name = repo_name.replace(f"{special_type}/", "")
                    pkg_name_list.append(repo_name)
                events = r.get("events")
                rversions_list = r.get("versions", [])
                version_end_including = ""
                version_start_excluding = ""
                version_end_excluding = ""
                fix_version_start_including = ""
                fix_version_end_including = ""
                fix_version_start_excluding = ""
                fix_version_end_excluding = ""
                version_start_including = ""
                if rversions_list:
                    version_start_including = rversions_list[0]
                    if (
                            len(rversions_list) > 1
                            and version_start_including != rversions_list[-1]
                    ):
                        version_end_including = rversions_list[-1]
                for ev in events:
                    # Reset all versions for introduced event
                    if ev.get("introduced") is not None:
                        version_end_including = ""
                        version_start_excluding = ""
                        version_end_excluding = ""
                        fix_version_start_including = ""
                        fix_version_end_including = ""
                        fix_version_start_excluding = ""
                        fix_version_end_excluding = ""
                        version_start_including = ev.get("introduced").split(":")[-1]
                        # Sometimes, the quality of data will be so low we need
                        # workarounds like this to make the result searchable
                        if version_start_including in (0, "0", "0.0.0"):
                            version_start_including = "0.0.0"
                    if ev.get("fixed"):
                        fix_version_start_including = ev.get("fixed").split(":")[-1]
                        fix_version_end_including = ev.get("fixed").split(":")[-1]
                        version_end_excluding = ev.get("fixed").split(":")[-1]
                    if ev.get("last_affected"):
                        version_end_including = ev.get("last_affected").split(":")[-1]
                        fix_version_start_excluding = version_end_including
                    if ev.get("limit"):
                        version_end_excluding = ev.get("limit").split(":")[-1]
                    # Create an entry for each introduced + fixed/limit event
                    if version_start_including and (
                            fix_version_start_including
                            or version_end_including
                            or version_end_excluding
                            or (len(events) == 1 and not versions_list)
                    ):
                        for full_pkg in pkg_name_list:
                            tdata = config.CVE_TPL % dict(
                                cve_id=cve_id,
                                cwe_id=cwe_id,
                                assigner=assigner,
                                references=references,
                                description="",
                                vectorString=vector_string,
                                vendor=vendor,
                                product=full_pkg,
                                version="*",
                                edition=edition,
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
                                publishedDate=cve_data.get("published"),
                                lastModifiedDate=cve_data.get("modified"),
                            )
                            try:
                                vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                                vuln.description = compress_str(description)
                                ret_data.append(vuln)
                            except Exception:
                                pass
        return ret_data
