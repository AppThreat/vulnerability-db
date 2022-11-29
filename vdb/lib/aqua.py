"""
Aqua vuln-list to NVD CVE converter

This module fetches the vulnerability data from aquasec vuln-list repo and stores them in NVD CVE 1.1 json format.
"""
from datetime import datetime
from zipfile import ZipFile

import os
import requests

from vdb.lib import CustomNamedTemporaryFile
from vdb.lib import config as config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    convert_score_severity,
    get_cvss3_from_vector,
    get_default_cve_data,
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

threat_to_severity = {
    "negligible": "LOW",
    "low": "LOW",
    "severity_low": "LOW",
    "medium": "MEDIUM",
    "severity_medium": "MEDIUM",
    "moderate": "MEDIUM",
    "severity_moderate": "MEDIUM",
    "important": "HIGH",
    "high": "HIGH",
    "severity_important": "HIGH",
    "critical": "CRITICAL",
    "severity_critical": "CRITICAL",
}


class AquaSource(NvdSource):
    """Aqua CVE source"""

    def download_all(self, local_store=True):
        """Download all cve data"""
        # For performance do not retain the whole data in-memory
        # See: https://github.com/AppThreat/vulnerability-db/issues/27
        data_list = []
        self.fetch(config.aquasec_vuln_list_url)
        return data_list

    def download_recent(self, local_store=True):
        raise NotImplementedError

    def _process_zip(self, zname):
        with ZipFile(zname, "r") as zipfp:
            for zf in zipfp.namelist():
                if self.is_supported_source(zf):
                    with zipfp.open(zf) as jsonf:
                        cve_data = jsonf.read()
                        try:
                            json_data = json_lib.loads(cve_data)
                            ret_data = self.convert(json_data)
                            self.store(ret_data, reindex=False)
                        except Exception as e:
                            pass

    def fetch(self, url):
        # Check if there is an existing cached zip file we could use
        cached_zip = os.path.join(config.cache_dir, "vuln-list.zip")
        if os.path.exists(cached_zip):
            return self._process_zip(cached_zip)
        with CustomNamedTemporaryFile() as tf:
            try:
                r = requests.get(url, stream=True)
                for chunk in r.iter_content(chunk_size=download_chunk_size):
                    tf.write(chunk)
                tf.flush()
                return self._process_zip(tf.name)
            except Exception:
                return []

    def convert(self, cve_data):
        if cve_data.get("updateinfo_id"):
            return self.alsa_to_vuln(cve_data)
        elif cve_data.get("id", "").startswith("ALAS"):
            return self.alas_rlsa_to_vuln(cve_data, "amazon")
        elif cve_data.get("id", "").startswith("RLSA"):
            return self.alas_rlsa_to_vuln(cve_data, "rocky")
        elif cve_data.get("Candidate"):
            return self.ubuntu_to_vuln(cve_data)
        elif cve_data.get("affected_release"):
            return self.redhat_to_vuln(cve_data)
        elif cve_data.get("name", "").startswith("AVG"):
            return self.arch_to_vuln(cve_data)
        elif cve_data.get("Tracking"):
            return self.suse_to_vuln(cve_data)
        elif cve_data.get("os_version"):
            return self.photon_to_vuln(cve_data)
        return []

    def is_supported_source(self, zfname):
        for distro in (
            "alpine",
            "cwe",
            "debian",
            "ghsa",
            "go",
            "nvd",
            "osv",
            "redhat-cpe",
            "kevc",
            "oval",
            "glad",
            "mariner",
        ):
            if distro in zfname:
                return False
        nvd_start_year = 2018
        try:
            nvd_start_year = int(config.nvd_start_year)
        except:
            pass
        for year in range(1999, nvd_start_year):
            if f"CVE-{year}-" in zfname:
                return False
        if zfname.endswith(".json"):
            return True
        return False

    def alsa_to_vuln(self, cve_data):
        """AlmaLinux"""
        ret_data = []
        if cve_data.get("type") != "security":
            return ret_data
        packages = cve_data.get("pkglist", {}).get("packages", [])
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = cve_data.get("updateinfo_id")
        cwe_id = ""
        cve_references = cve_data.get("references", [])
        references = []
        for aref in cve_references:
            references.append(
                {"name": aref.get("title", "id"), "url": aref.get("href")}
            )
        references = json_lib.dumps(references)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = cve_data.get("description", "")
        if not description and cve_data.get("title"):
            description = """# {}
{}
{}
            """.format(
                cve_data.get("summary"), cve_data.get("title"), cve_data.get("solution")
            )

        assigner = cve_data.get("fromstr", "")
        severity = threat_to_severity[cve_data.get("severity").lower()]
        score, severity, vectorString, attackComplexity = get_default_cve_data(severity)
        exploitabilityScore = score
        vendor = "alma"
        pkg_name = packages[0].get("name")
        version_start_including = ""
        version_end_including = ""
        version_start_excluding = ""
        fix_version_end_including = ""
        fix_version_start_excluding = ""
        fix_version_end_excluding = ""
        fix_version_start_including = packages[0].get("version")
        version_end_excluding = packages[0].get("version")
        publishedDate = ""
        if cve_data.get("issued_date", {}).get("$date"):
            try:
                publishedDate = datetime.fromtimestamp(
                    int(cve_data.get("issued_date", {}).get("$date")) / 1000
                )
            except Exception:
                pass
        lastModifiedDate = ""
        if cve_data.get("updated_date", {}).get("$date"):
            try:
                lastModifiedDate = datetime.fromtimestamp(
                    int(cve_data.get("updated_date", {}).get("$date")) / 1000
                )
            except Exception:
                pass
        if pkg_name and fix_version_start_including:
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
                publishedDate=publishedDate,
                lastModifiedDate=lastModifiedDate,
            )
            try:
                vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                vuln.description = description
                ret_data.append(vuln)
            except Exception as e:
                pass
        return ret_data

    def alas_rlsa_to_vuln(self, cve_data, vendor):
        """Amazon Linux"""
        ret_data = []
        packages = cve_data.get("packages", [])
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = cve_data.get("id")
        cwe_id = ""
        cve_references = cve_data.get("references", [])
        references = []
        for aref in cve_references:
            references.append({"name": aref.get("id"), "url": aref.get("href")})
        references = json_lib.dumps(references)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        if not cve_id.startswith("CVE") and cve_data.get("cveids"):
            cve_id = cve_data.get("cveids")[0]
        description = cve_data.get("description", "")
        assigner = vendor
        severity = threat_to_severity[cve_data.get("severity").lower()]
        score, severity, vectorString, attackComplexity = get_default_cve_data(severity)
        exploitabilityScore = score
        publishedDate = cve_data.get("issued", {}).get("date")
        lastModifiedDate = cve_data.get("updated", {}).get("date")
        done_pkgs = {}
        for apkg in packages:
            pkg_key = f"""{apkg.get("name")}:{apkg.get("version")}"""
            if done_pkgs.get(pkg_key):
                continue
            pkg_name = apkg.get("name")
            version_start_including = ""
            version_end_including = ""
            version_start_excluding = ""
            fix_version_end_including = ""
            fix_version_start_excluding = ""
            fix_version_end_excluding = ""
            fix_version_start_including = apkg.get("version")
            version_end_excluding = apkg.get("version")

            if pkg_name and fix_version_start_including:
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
                    publishedDate=publishedDate,
                    lastModifiedDate=lastModifiedDate,
                )
                try:
                    vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                    vuln.description = description
                    ret_data.append(vuln)
                    done_pkgs[pkg_key] = True
                except Exception as e:
                    pass
        return ret_data

    def ubuntu_to_vuln(self, cve_data):
        """Ubuntu Linux"""
        ret_data = []
        packages = cve_data.get("Patches", {})
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = cve_data.get("Candidate")
        cwe_id = ""
        cve_references = cve_data.get("References", [])
        references = []
        for aref in cve_references:
            references.append({"name": aref, "url": aref})
        references = json_lib.dumps(references)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = cve_data.get("Description")
        if not description and cve_data.get("UbuntuDescription"):
            description = cve_data.get("UbuntuDescription")
        assigner = "ubuntu"
        vendor = "ubuntu"
        severity = threat_to_severity[cve_data.get("Priority").lower()]
        score, severity, vectorString, attackComplexity = get_default_cve_data(severity)
        exploitabilityScore = score
        publishedDate = cve_data.get("PublicDate")
        lastModifiedDate = cve_data.get("PublicDate")
        for pkg_name, distro_obj in packages.items():
            for distro_name, status_obj in distro_obj.items():
                if status_obj.get("Status") in (
                    "ignored",
                    "needs-triage",
                ):
                    continue
                version_start_including = ""
                version_end_including = ""
                version_start_excluding = ""
                version_end_excluding = ""
                fix_version_end_including = ""
                fix_version_start_excluding = ""
                fix_version_end_excluding = ""
                fix_version_start_including = ""
                fix_note = status_obj.get("Note")
                # Remove epoch
                if ":" in fix_note:
                    fix_note = fix_note.split(":")[-1]
                # Released CVEs have fixes
                if (
                    status_obj.get("Status")
                    in (
                        "not-affected",
                        "released",
                    )
                    and " " not in fix_note
                    and "CVE" not in fix_note
                ):
                    fix_version_start_including = fix_note
                    version_end_excluding = fix_note
                # Handle CVEs that are deferred
                if (
                    status_obj.get("Status") in ("deferred", "needed")
                    and " " not in fix_note
                ):
                    version_end_including = "99.99.9"
                if pkg_name and (fix_version_start_including or version_end_including):
                    for full_pkg_name in (f"{distro_name}/{pkg_name}", pkg_name):
                        tdata = config.CVE_TPL % dict(
                            cve_id=cve_id,
                            cwe_id=cwe_id,
                            assigner=assigner,
                            references=references,
                            description="",
                            vectorString=vectorString,
                            vendor=vendor,
                            product=full_pkg_name,
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
                            publishedDate=publishedDate,
                            lastModifiedDate=lastModifiedDate,
                        )
                        try:
                            vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                            vuln.description = description
                            ret_data.append(vuln)
                        except Exception as e:
                            pass
        return ret_data

    def redhat_to_vuln(self, cve_data):
        """RedHat Linux"""
        ret_data = []
        cvss3 = cve_data.get("cvss3", {})
        if cvss3.get("status") is not None and cvss3.get("status") != "verified":
            return ret_data
        packages = cve_data.get("affected_release", [])
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = cve_data.get("name")
        cwe_id = cve_data.get("cwe")
        cve_references = cve_data.get("references", "")
        references = []
        for aref in cve_references:
            for bref in aref.split("\n"):
                references.append({"name": bref, "url": bref})
        references = json_lib.dumps(references)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = "\n".join(cve_data.get("details", []))
        assigner = "redhat"
        vectorString = cvss3.get("cvss3_scoring_vector")
        score = cvss3.get("cvss3_base_score")
        if score:
            try:
                score = float(score)
            except Exception:
                pass
        severity = threat_to_severity[cve_data.get("threat_severity").lower()]
        cvss3_obj = get_cvss3_from_vector(vectorString)
        exploitabilityScore = ""
        attackComplexity = ""
        if cvss3_obj:
            exploitabilityScore = cvss3_obj.get("temporalScore")
            attackComplexity = cvss3_obj.get("attackComplexity")
            score = cvss3_obj.get("baseScore")
        publishedDate = cve_data.get("public_date")
        lastModifiedDate = cve_data.get("public_date")
        done_pkgs = {}
        for arelease in packages:
            pkg_key = arelease.get("package")
            if done_pkgs.get(pkg_key):
                continue
            tmpA = pkg_key.split("-")
            if len(tmpA) < 2:
                continue
            pkg_name = tmpA[0]
            version = pkg_key.replace(pkg_name + "-", "")
            version_start_including = ""
            version_end_including = version
            version_start_excluding = ""
            version_end_excluding = ""
            fix_version_end_including = ""
            fix_version_start_excluding = version
            fix_version_end_excluding = ""
            fix_version_start_including = ""
            if pkg_name and version:
                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vectorString,
                    vendor="redhat",
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
                    publishedDate=publishedDate,
                    lastModifiedDate=lastModifiedDate,
                )
                try:
                    vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                    vuln.description = description
                    ret_data.append(vuln)
                    done_pkgs[pkg_key] = True
                except Exception as e:
                    pass
        return ret_data

    def arch_to_vuln(self, cve_data):
        """Arch Linux"""
        ret_data = []
        packages = cve_data.get("packages", [])
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = cve_data.get("name")
        cwe_id = ""
        references = []
        if cve_data.get("issues") and len(cve_data.get("issues")) > 0:
            cve_id = cve_data.get("issues")[0]
        description = cve_data.get("type", "")
        assigner = "archlinux"
        severity = threat_to_severity[cve_data.get("severity").lower()]
        score, severity, vectorString, attackComplexity = get_default_cve_data(severity)
        publishedDate = ""
        lastModifiedDate = ""
        for pkg_name in packages:
            version_start_including = ""
            version_end_including = cve_data.get("affected")
            version_start_excluding = ""
            version_end_excluding = cve_data.get("fixed")
            fix_version_end_including = ""
            fix_version_start_excluding = ""
            fix_version_end_excluding = ""
            fix_version_start_including = cve_data.get("fixed")
            if pkg_name and version_end_including:
                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vectorString,
                    vendor="arch",
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
                    exploitabilityScore=score,
                    publishedDate=publishedDate,
                    lastModifiedDate=lastModifiedDate,
                )
                try:
                    vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                    vuln.description = description
                    ret_data.append(vuln)
                except Exception as e:
                    pass
        return ret_data

    def suse_to_vuln(self, cve_data):
        """Suse Linux"""
        ret_data = []
        packages = cve_data.get("ProductTree", {}).get("Relationships", [])
        if not packages or not len(packages) > 0:
            return ret_data
        cve_id = ""
        description = ""
        severity = ""
        # Package name has to be extracted from the title :(
        pkg_name = cve_data.get("Title", "").split(" ")[-1]
        publishedDate = cve_data.get("Tracking", {}).get("InitialReleaseDate", "")
        lastModifiedDate = cve_data.get("Tracking", {}).get("CurrentReleaseDate", "")
        if cve_data.get("Vulnerabilities"):
            for avuln in cve_data.get("Vulnerabilities"):
                cve_id = avuln.get("CVE")
                description = avuln.get("Description")
                threats = avuln.get("Threats")
                if threats and len(threats) > 0:
                    severity = threat_to_severity[threats[0].get("Severity").lower()]
                cwe_id = ""
                cve_references = avuln.get("References", [])
                references = []
                for aref in cve_references:
                    references.append(
                        {"name": aref.get("Description", "id"), "url": aref.get("URL")}
                    )
                references = json_lib.dumps(references)
                if isinstance(references, bytes):
                    references = references.decode("utf-8", "ignore")
                assigner = "suse"
                score, severity, vectorString, attackComplexity = get_default_cve_data(
                    severity
                )
                done_pkgs = {}
                for pref in packages:
                    pkg_key = pref.get("ProductReference")
                    if done_pkgs.get(pkg_key):
                        continue
                    version = pkg_key.replace(pkg_name + "-", "")
                    version_start_including = ""
                    version_end_including = ""
                    version_start_excluding = ""
                    version_end_excluding = version
                    fix_version_end_including = ""
                    fix_version_start_excluding = ""
                    fix_version_end_excluding = ""
                    fix_version_start_including = version
                    if pkg_name and version:
                        tdata = config.CVE_TPL % dict(
                            cve_id=cve_id,
                            cwe_id=cwe_id,
                            assigner=assigner,
                            references=references,
                            description="",
                            vectorString=vectorString,
                            vendor="suse",
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
                            exploitabilityScore=score,
                            publishedDate=publishedDate,
                            lastModifiedDate=lastModifiedDate,
                        )
                        try:
                            vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                            vuln.description = description
                            ret_data.append(vuln)
                            done_pkgs[pkg_key] = True
                        except Exception as e:
                            pass
        return ret_data

    def photon_to_vuln(self, cve_data):
        """Photon Linux"""
        ret_data = []
        cve_id = cve_data.get("cve_id")
        pkg_name = cve_data.get("pkg")
        cwe_id = ""
        references = []
        description = """Summary
{}
        """.format(
            cve_data.get("aff_ver")
        )
        assigner = "photon"
        score = cve_data.get("cve_score")
        severity = convert_score_severity(score)
        score, severity, vectorString, attackComplexity = get_default_cve_data(severity)
        publishedDate = ""
        lastModifiedDate = ""
        version_start_including = ""
        version_end_including = ""
        version_start_excluding = ""
        version_end_excluding = cve_data.get("res_ver")
        fix_version_end_including = ""
        fix_version_start_excluding = ""
        fix_version_end_excluding = ""
        fix_version_start_including = cve_data.get("res_ver")
        if pkg_name and version_end_excluding:
            tdata = config.CVE_TPL % dict(
                cve_id=cve_id,
                cwe_id=cwe_id,
                assigner=assigner,
                references=references,
                description="",
                vectorString=vectorString,
                vendor="photon",
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
                exploitabilityScore=score,
                publishedDate=publishedDate,
                lastModifiedDate=lastModifiedDate,
            )
            try:
                vuln = NvdSource.convert_vuln(json_lib.loads(tdata))
                vuln.description = description
                ret_data.append(vuln)
            except Exception as e:
                pass
        return ret_data
