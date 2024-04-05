"""
Aqua vuln-list to NVD CVE converter

This module fetches the vulnerability data from aquasec vuln-list repo and stores them in NVD CVE 1.1 json format.
"""

import os
from datetime import datetime
from zipfile import ZipFile

import httpx
import orjson

from vdb.lib import CustomNamedTemporaryFile, config
from vdb.lib.nvd import NvdSource
from vdb.lib.utils import (
    compress_str,
    convert_score_severity,
    get_cvss3_from_vector,
    get_default_cve_data,
)

# Size of the stream to read and write to the file
DOWNLOAD_CHUNK_SIZE = 4096


class AquaSource(NvdSource):
    """Aqua CVE source"""

    def download_all(self):
        """Download all cve data"""
        # For performance do not retain the whole data in-memory
        # See: https://github.com/AppThreat/vulnerability-db/issues/27
        data_list = []
        self.fetch(config.VULN_LIST_URL)
        return data_list

    def download_recent(self):
        pass

    def _process_zip(self, zname):
        with ZipFile(zname, "r") as zipfp:
            for zf in zipfp.namelist():
                if self.is_supported_source(zf):
                    with zipfp.open(zf) as jsonf:
                        cve_data = jsonf.read()
                        try:
                            json_data = orjson.loads(cve_data)
                            ret_data = self.convert(json_data)
                            self.store(ret_data)
                        except Exception:
                            pass

    def fetch(self, url):
        # Check if there is an existing cached zip file we could use
        cached_zip = os.path.join(config.CACHE_DIR, "vuln-list.zip")
        if os.path.exists(cached_zip):
            return self._process_zip(cached_zip)
        with CustomNamedTemporaryFile() as tf:
            try:
                client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
                with client.stream("GET", url) as r:
                    for chunk in r.iter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
                        tf.write(chunk)
                    tf.flush()
                    return self._process_zip(tf.name)
            except Exception:
                return []

    def convert(self, cve_data):
        if cve_data.get("vulnStatus"):
            return self.nvd_api_to_vuln(cve_data)
        if cve_data.get("updateinfo_id"):
            return self.alsa_to_vuln(cve_data)
        if cve_data.get("id", "").startswith("ALAS"):
            return self.alas_rlsa_to_vuln(cve_data, "amazon")
        if cve_data.get("id", "").startswith("RLSA"):
            return self.alas_rlsa_to_vuln(cve_data, "rocky")
        if cve_data.get("Candidate"):
            return self.ubuntu_to_vuln(cve_data)
        if cve_data.get("affected_release"):
            return self.redhat_to_vuln(cve_data)
        if cve_data.get("name", "").startswith("AVG"):
            return self.arch_to_vuln(cve_data)
        if cve_data.get("Tracking"):
            return self.suse_to_vuln(cve_data)
        if cve_data.get("os_version"):
            return self.photon_to_vuln(cve_data)
        if cve_data.get("Annotations") and cve_data.get("Header"):
            return self.debian_to_vuln(cve_data)
        if cve_data.get("secfixes"):
            return self.wolfi_to_vuln(cve_data)
        if cve_data.get("id", "").startswith("CVE-") and cve_data.get("state"):
            return self.alpine_to_vuln(cve_data)
        return []

    @staticmethod
    def is_supported_source(zfname):
        for distro in ("alpine-unfixed",):
            if distro in zfname:
                return True
        for distro in (
            "alpine",
            "cwe",
            "ghsa",
            "go",
            "osv",
            "redhat-cpe",
            "kevc",
            "oval",
            "glad",
            "mariner",
        ):
            if distro in zfname:
                return False
        nvd_start_year = config.NVD_START_YEAR
        for year in range(1999, nvd_start_year):
            if f"CVE-{year}-" in zfname:
                return False
        if zfname.endswith(".json"):
            return True
        return False

    @staticmethod
    def alsa_to_vuln(cve_data):
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
        references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = cve_data.get("description", "")
        if not description and cve_data.get("title"):
            description = f"""# {cve_data.get("summary")}
{cve_data.get("title")}
{cve_data.get("solution")}
            """
        assigner = cve_data.get("fromstr", "")
        severity = config.THREAT_TO_SEVERITY[cve_data.get("severity").lower()]
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        exploitability_score = score
        user_interaction = "REQUIRED"
        vendor = "almalinux"
        pkg_name = packages[0].get("name")
        version_start_including = ""
        version_end_including = ""
        version_start_excluding = ""
        fix_version_end_including = ""
        fix_version_start_excluding = ""
        fix_version_end_excluding = ""
        fix_version_start_including = packages[0].get("version").split(":")[-1]
        version_end_excluding = packages[0].get("version").split(":")[-1]
        published_date = ""
        if cve_data.get("issued_date", {}).get("$date"):
            try:
                published_date = datetime.fromtimestamp(
                    int(cve_data.get("issued_date", {}).get("$date")) / 1000
                )
            except Exception:
                pass
        last_modified_date = ""
        if cve_data.get("updated_date", {}).get("$date"):
            try:
                last_modified_date = datetime.fromtimestamp(
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
                vectorString=vector_string,
                vendor="rpm",
                product=f"{vendor}/{pkg_name}",
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
                ret_data.append(vuln)
            except Exception:
                pass
        return ret_data

    @staticmethod
    def alas_rlsa_to_vuln(cve_data, vendor):
        """Amazon Linux"""
        ret_data = []
        packages = cve_data.get("packages", [])
        cve_id = cve_data.get("id")
        if not packages or cve_id in ("CVE-PENDING",) or not len(packages) > 0:
            return ret_data
        cwe_id = ""
        cve_references = cve_data.get("references", [])
        references = []
        for aref in cve_references:
            references.append({"name": aref.get("id"), "url": aref.get("href")})
        references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        if not cve_id.startswith("CVE") and cve_data.get("cveids"):
            cve_id = cve_data.get("cveids")[0]
        description = cve_data.get("description", "")
        assigner = vendor
        severity = config.THREAT_TO_SEVERITY[cve_data.get("severity").lower()]
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        exploitability_score = score
        user_interaction = "REQUIRED"
        published_date = cve_data.get("issued", {}).get("date")
        last_modified_date = cve_data.get("updated", {}).get("date")
        done_pkgs = {}
        for apkg in packages:
            version = apkg.get("version")
            # Remove epoch
            if ":" in version:
                version = version.split(":")[-1]
            pkg_key = f"""{apkg.get("name")}:{version}"""
            if done_pkgs.get(pkg_key):
                continue
            pkg_name = apkg.get("name")
            version_start_including = ""
            version_end_including = ""
            version_start_excluding = ""
            fix_version_end_including = ""
            fix_version_start_excluding = ""
            fix_version_end_excluding = ""
            fix_version_start_including = version
            version_end_excluding = version

            if pkg_name and fix_version_start_including:
                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vector_string,
                    vendor="rpm",
                    product=f"{vendor}/{pkg_name}",
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
                    ret_data.append(vuln)
                    done_pkgs[pkg_key] = True
                except Exception:
                    pass
        return ret_data

    @staticmethod
    def ubuntu_to_vuln(cve_data):
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
        references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = cve_data.get("Description")
        if "** DISPUTED **" in description or "** REJECT **" in description:
            return ret_data
        if not description and cve_data.get("UbuntuDescription"):
            description = cve_data.get("UbuntuDescription")
        assigner = "canonical"
        vendor = "ubuntu"
        severity = config.THREAT_TO_SEVERITY[cve_data.get("Priority").lower()]
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        exploitability_score = score
        user_interaction = "REQUIRED"
        published_date = cve_data.get("PublicDate")
        last_modified_date = cve_data.get("PublicDate")
        for pkg_name, distro_obj in packages.items():
            for distro_name, status_obj in distro_obj.items():
                fix_note = status_obj.get("Note")
                # DNE - does not exist
                if status_obj.get("Status") in ("DNE",):
                    continue
                version_start_including = ""
                version_end_including = ""
                version_start_excluding = ""
                version_end_excluding = ""
                fix_version_end_including = ""
                fix_version_start_excluding = ""
                fix_version_end_excluding = ""
                fix_version_start_including = ""
                # Remove epoch
                if ":" in fix_note:
                    fix_note = fix_note.split(":")[-1]
                # Released CVEs have fixes
                if (
                    status_obj.get("Status") in ("not-affected", "released")
                    and " " not in fix_note
                    and "CVE" not in fix_note
                ):
                    fix_version_start_including = fix_note
                    version_end_excluding = fix_note
                # Handle CVEs that are deferred
                # Let's include the vulnerabilities that did not get a fix
                if (
                    status_obj.get("Status") in ("deferred", "needed")
                    and " " not in fix_note
                ):
                    version_end_including = config.PLACEHOLDER_FIX_VERSION
                if status_obj.get("Status") in ("ignored", "needs-triage"):
                    version_end_including = config.PLACEHOLDER_FIX_VERSION
                if pkg_name and (fix_version_start_including or version_end_including):
                    for full_pkg_name in (f"{distro_name}/{pkg_name}",):
                        tdata = config.CVE_TPL % dict(
                            cve_id=cve_id,
                            cwe_id=cwe_id,
                            assigner=assigner,
                            references=references,
                            description="",
                            vectorString=vector_string,
                            vendor="deb",
                            product=f"{vendor}/{full_pkg_name}",
                            version="*",
                            edition=distro_name,
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
                            ret_data.append(vuln)
                        except Exception:
                            pass
        return ret_data

    @staticmethod
    def redhat_to_vuln(cve_data):
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
        references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
        if isinstance(references, bytes):
            references = references.decode("utf-8", "ignore")
        description = "\n".join(cve_data.get("details", []))
        assigner = "redhat"
        vector_string = cvss3.get("cvss3_scoring_vector")
        score = cvss3.get("cvss3_base_score")
        if score:
            try:
                score = float(score)
            except Exception:
                pass
        severity = config.THREAT_TO_SEVERITY[cve_data.get("threat_severity").lower()]
        cvss3_obj = get_cvss3_from_vector(vector_string)
        exploitability_score = ""
        attack_complexity = ""
        user_interaction = "REQUIRED"
        if cvss3_obj:
            exploitability_score = cvss3_obj.get("temporalScore")
            attack_complexity = cvss3_obj.get("attackComplexity")
            score = cvss3_obj.get("baseScore")
            user_interaction = cvss3_obj.get("userInteraction")
        published_date = cve_data.get("public_date")
        last_modified_date = cve_data.get("public_date")
        done_pkgs = {}
        for arelease in packages:
            pkg_key = arelease.get("package")
            if done_pkgs.get(pkg_key):
                continue
            tmp_a = pkg_key.split(":" if ":" in pkg_key else "-")
            if len(tmp_a) < 2:
                continue
            pkg_name = tmp_a[0]
            if pkg_name.endswith("-0"):
                pkg_name = pkg_name[0:-2]
            if ":" in pkg_key:
                version = pkg_key.split(":")[-1]
            else:
                version = pkg_key.replace(pkg_name + "-", "")
            # Remove epoch
            if ":" in version:
                version = version.split(":")[-1]
            edition = "*"
            cpe = arelease.get("cpe", "")
            if cpe and cpe.startswith("cpe:"):
                tmpc = cpe.split(":")
                if len(tmpc) > 2:
                    edition = f"{tmpc[-2]}-{tmpc[-1]}"
                    if edition.startswith("-el"):
                        edition = edition.replace("-el", "enterprise_linux-")
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
                    vectorString=vector_string,
                    vendor="rpm",
                    product=f"redhat/{pkg_name}",
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
                    publishedDate=published_date,
                    lastModifiedDate=last_modified_date,
                )
                try:
                    vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                    vuln.description = compress_str(description)
                    ret_data.append(vuln)
                    done_pkgs[pkg_key] = True
                except Exception:
                    pass
        return ret_data

    @staticmethod
    def arch_to_vuln(cve_data):
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
        severity = config.THREAT_TO_SEVERITY[cve_data.get("severity").lower()]
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        published_date = ""
        last_modified_date = ""
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
                    vectorString=vector_string,
                    vendor="alpm",
                    product=f"arch/{pkg_name}",
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
                    userInteraction="REQUIRED",
                    exploitabilityScore=score,
                    publishedDate=published_date,
                    lastModifiedDate=last_modified_date,
                )
                try:
                    vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                    vuln.description = compress_str(description)
                    ret_data.append(vuln)
                except Exception:
                    pass
        return ret_data

    @staticmethod
    def product_ref_to_name_version(product_ref):
        product_parts = product_ref.split("-")
        name_parts = []
        version_parts = []
        for i, part in enumerate(product_parts):
            if part[0].isdigit() and "bit" not in part and "kb" not in part:
                version_parts = product_parts[i:]
                name_parts = product_parts[:i]
                break
        return "-".join(name_parts), "-".join(version_parts)

    def suse_to_vuln(self, cve_data):
        """Suse Linux"""
        ret_data = []
        packages = cve_data.get("ProductTree", {}).get("Relationships", [])
        if not packages or not len(packages) > 0:
            return ret_data
        severity = ""
        # Package name has to be extracted from the title :(
        published_date = cve_data.get("Tracking", {}).get("InitialReleaseDate", "")
        last_modified_date = cve_data.get("Tracking", {}).get("CurrentReleaseDate", "")
        if cve_data.get("Vulnerabilities"):
            for avuln in cve_data.get("Vulnerabilities"):
                cve_id = avuln.get("CVE")
                description = avuln.get("Description")
                threats = avuln.get("Threats")
                if threats and len(threats) > 0:
                    severity = config.THREAT_TO_SEVERITY[
                        threats[0].get("Severity").lower()
                    ]
                cwe_id = ""
                cve_references = avuln.get("References", [])
                references = []
                for aref in cve_references:
                    references.append(
                        {"name": aref.get("Description", "id"), "url": aref.get("URL")}
                    )
                references = orjson.dumps(references, option=orjson.OPT_NAIVE_UTC)
                if isinstance(references, bytes):
                    references = references.decode("utf-8", "ignore")
                assigner = "suse"
                (
                    score,
                    severity,
                    vector_string,
                    attack_complexity,
                ) = get_default_cve_data(severity)
                done_pkgs = {}
                for pref in packages:
                    pkg_key = pref.get("ProductReference")
                    if done_pkgs.get(pkg_key):
                        continue
                    pkg_name, version = self.product_ref_to_name_version(pkg_key)
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
                            vectorString=vector_string,
                            vendor="rpm",
                            product=f"suse/{pkg_name}",
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
                            userInteraction="REQUIRED",
                            exploitabilityScore=score,
                            publishedDate=published_date,
                            lastModifiedDate=last_modified_date,
                        )
                        try:
                            vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                            vuln.description = compress_str(description)
                            ret_data.append(vuln)
                            done_pkgs[pkg_key] = True
                        except Exception:
                            pass
        return ret_data

    @staticmethod
    def photon_to_vuln(cve_data):
        """Photon Linux"""
        ret_data = []
        cve_id = cve_data.get("cve_id")
        pkg_name = cve_data.get("pkg")
        cwe_id = ""
        references = []
        description = f"""Summary
{cve_data.get("aff_ver")}
        """
        assigner = "vmware"
        score = cve_data.get("cve_score")
        severity = convert_score_severity(score)
        newscore, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        if not score and newscore:
            score = newscore
        published_date = ""
        last_modified_date = ""
        version_start_including = ""
        version_end_including = ""
        version_start_excluding = ""
        version_end_excluding = cve_data.get("res_ver").split(":")[-1]
        fix_version_end_including = ""
        fix_version_start_excluding = ""
        fix_version_end_excluding = ""
        fix_version_start_including = cve_data.get("res_ver").split(":")[-1]
        distro_name = "*"
        if cve_data.get("os_version"):
            distro_name = f"""photon-{cve_data.get("os_version")}"""
            pkg_name = f"{distro_name}/{pkg_name}"
        if pkg_name and version_end_excluding:
            tdata = config.CVE_TPL % dict(
                cve_id=cve_id,
                cwe_id=cwe_id,
                assigner=assigner,
                references=references,
                description="",
                vectorString=vector_string,
                vendor="rpm",
                product=f"photon/{pkg_name}",
                version="*",
                edition=distro_name,
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
                userInteraction="REQUIRED",
                exploitabilityScore=score,
                publishedDate=published_date,
                lastModifiedDate=last_modified_date,
            )
            try:
                vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                vuln.description = compress_str(description)
                ret_data.append(vuln)
            except Exception:
                pass
        return ret_data

    @staticmethod
    def debian_to_vuln(cve_data):
        """Debian Linux"""
        ret_data = []
        header = cve_data.get("Header")
        annotations = cve_data.get("Annotations")
        cve_id = header.get("ID")
        cwe_id = ""
        references = []
        description = header.get("Description", "").replace("(", "").replace(")", "")
        # Try harder to retain all description
        for ann in annotations:
            if ann.get("Original", "").startswith("NOTE:"):
                description = f"{description}\n{ann.get('Original')}"
        if "** DISPUTED **" in description or "** REJECT **" in description:
            return ret_data
        assigner = "debian"
        vendor = "debian"
        for ann in annotations:
            if ann.get("Type") == "RESERVED" or ann.get("Original") == "RESERVED":
                continue
            # Try to dealias
            if (
                not cve_id.startswith("CVE")
                and ann.get("Type") == "xref"
                and ann.get("Bugs")
            ):
                aliases_block = f"""
## Related CVE(s)
{", ".join(ann.get("Bugs"))}
            """
                description += aliases_block
                for bug in ann.get("Bugs"):
                    if bug.startswith("CVE"):
                        cve_id = bug
                        break
            kind = ann.get("Kind")
            if kind not in (
                "fixed",
                "unfixed",
                "no-dsa",
                "end-of-life",
                "ignored",
                "not-affected",
                "postponed",
            ):
                continue
            pkg_name = ann.get("Package")
            if not pkg_name:
                continue
            distro_name = ann.get("Release")
            if distro_name:
                pkg_name = f"{distro_name}/{pkg_name}"
            version = ann.get("Version", config.PLACEHOLDER_FIX_VERSION)
            # We need to track not-affected entries with a special exclude version
            if kind == "not-affected":
                version = config.PLACEHOLDER_EXCLUDE_VERSION
            # Remove epoch
            if ":" in version:
                version = version.split(":")[-1]
            severity = "MEDIUM"
            # Try harder to set LOW priority
            if kind == "postponed" or (
                ann.get("Description")
                and "minor issue" in ann.get("Description").lower()
            ):
                severity = "LOW"
            if ann.get("Severity"):
                severity = config.THREAT_TO_SEVERITY.get(ann.get("Severity"), "MEDIUM")
            score, severity, vector_string, attack_complexity = get_default_cve_data(
                severity
            )
            published_date = ""
            last_modified_date = ""
            version_start_including = ""
            version_end_including = ""
            version_start_excluding = ""
            version_end_excluding = version
            fix_version_end_including = ""
            fix_version_start_excluding = ""
            fix_version_end_excluding = ""
            fix_version_start_including = version
            if pkg_name and version_end_excluding:
                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vector_string,
                    vendor="deb",
                    product=f"{vendor}/{pkg_name}",
                    version="*",
                    edition=distro_name if distro_name else "*",
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
                    userInteraction="REQUIRED",
                    exploitabilityScore=score,
                    publishedDate=published_date,
                    lastModifiedDate=last_modified_date,
                )
                try:
                    vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                    vuln.description = compress_str(description)
                    ret_data.append(vuln)
                except Exception:
                    pass
        return ret_data

    @staticmethod
    def wolfi_to_vuln(cve_data):
        """Wolfi OS and Chainguard"""
        ret_data = []
        cwe_id = ""
        references = []
        assigner = cve_data.get("reponame")
        # No severity of any kind in the advisories
        severity = "LOW"
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        published_date = ""
        last_modified_date = ""
        pkg_name = cve_data.get("name")
        for fix_version_start_including, cve_list in cve_data.get("secfixes").items():
            for cve_id in cve_list:
                version_start_including = ""
                version_end_including = (
                    "*" if fix_version_start_including == "0" else ""
                )
                version_start_excluding = ""
                version_end_excluding = (
                    fix_version_start_including
                    if fix_version_start_including != "0"
                    else ""
                )
                fix_version_end_including = ""
                fix_version_start_excluding = ""
                fix_version_end_excluding = ""
                tdata = config.CVE_TPL % dict(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    assigner=assigner,
                    references=references,
                    description="",
                    vectorString=vector_string,
                    vendor="apk",
                    product=f"{assigner}/{pkg_name}",
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
                    userInteraction="REQUIRED",
                    exploitabilityScore=score,
                    publishedDate=published_date,
                    lastModifiedDate=last_modified_date,
                )
                try:
                    vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                    vuln.description = f"""URL Prefix: {cve_data.get("urlprefix")}. Affected arch: {", ".join(cve_data.get("archs"))}"""
                    ret_data.append(vuln)
                except Exception:
                    pass
        return ret_data

    @staticmethod
    def alpine_to_vuln(cve_data):
        """Alpine"""
        ret_data = []
        assigner = "alpine"
        # No severity of any kind in the advisories
        severity = "LOW"
        score, severity, vector_string, attack_complexity = get_default_cve_data(
            severity
        )
        published_date = ""
        last_modified_date = ""
        cve_id = cve_data.get("id")
        for astate in cve_data.get("state", []):
            if astate.get("fixed"):
                continue
            pkg_name = astate.get("packageName")
            unfixed_version = astate.get("packageVersion")
            edition = f"alpine-{astate.get('repo').split('-')[0]}"
            tdata = config.CVE_TPL % dict(
                cve_id=cve_id,
                cwe_id="",
                assigner=assigner,
                references=[],
                description="",
                vectorString=vector_string,
                vendor="apk",
                product=f"{assigner}/{edition}/{pkg_name}",
                version=unfixed_version,
                edition=edition,
                version_start_including=unfixed_version,
                version_end_including=unfixed_version,
                version_start_excluding="",
                version_end_excluding="",
                fix_version_start_including="",
                fix_version_end_including="",
                fix_version_start_excluding="",
                fix_version_end_excluding="",
                severity=severity,
                attackComplexity=attack_complexity,
                score=score,
                userInteraction="NONE",
                exploitabilityScore=score,
                publishedDate=published_date,
                lastModifiedDate=last_modified_date,
            )
            try:
                vuln = NvdSource.convert_vuln(orjson.loads(tdata))
                vuln.description = f"CVE {cve_id} is unfixed in {edition}. See https://security.alpinelinux.org/vuln/{cve_id} for more details."
                ret_data.append(vuln)
            except Exception:
                pass
        return ret_data

    @staticmethod
    def nvd_api_to_vuln(cve_data):
        """NVD API"""
        v = NvdSource.convert_api_vuln(cve_data)
        return [v] if v else []
