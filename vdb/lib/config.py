import os

from appdirs import user_cache_dir, user_data_dir

# NVD CVE json feed url
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%(year)s.json.gz"

# NVD start year. 2018 is quicker. 2002 is quite detailed but slow
NVD_START_YEAR = os.getenv("NVD_START_YEAR", "2018")
try:
    NVD_START_YEAR = int(NVD_START_YEAR)
except ValueError:
    pass

# GitHub advisory feed url
GHA_URL = os.getenv("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql")

# No of pages to download from GitHub during a full refresh
GHA_PAGES_COUNT = os.getenv("GITHUB_PAGE_COUNT", "2")
NPM_PAGES_COUNT = os.getenv("NPM_PAGE_COUNT", "2")

# DB file dir
DATA_DIR = os.getenv("VDB_HOME", user_data_dir("vdb"))
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

CACHE_DIR = os.getenv("VDB_CACHE", user_cache_dir("vdb"))
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

# Binary db file
VDB_BIN_FILE = os.path.join(DATA_DIR, "data.vdb6")

# Binary DB index file
VDB_BIN_INDEX = os.path.join(DATA_DIR, "data.index.vdb6")

# NPM advisory url
NPM_SERVER = "https://registry.npmjs.org"
NPM_AUDIT_URL = NPM_SERVER + "/-/npm/v1/security/audits"
NPM_ADVISORIES_URL = NPM_SERVER + "/-/npm/v1/security/advisories"

NPM_APP_INFO = {"name": "appthreat-vdb", "version": "6.0.0"}

CVE_TPL = """
{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"%(cve_id)s","ASSIGNER":"%(assigner)s"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"%(cwe_id)s"}]}]},"references":{"reference_data": %(references)s},"description":{"description_data":[{"lang":"en","value":"%(description)s"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:%(edition)s:*:*:*:*:*","versionStartExcluding":"%(version_start_excluding)s","versionEndExcluding":"%(version_end_excluding)s","versionStartIncluding":"%(version_start_including)s","versionEndIncluding":"%(version_end_including)s"}, {"vulnerable":false,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(fix_version_start_including)s:*:%(edition)s:*:*:*:*:*","versionStartExcluding":"%(fix_version_start_excluding)s","versionEndExcluding":"%(fix_version_end_excluding)s","versionStartIncluding":"%(fix_version_start_including)s","versionEndIncluding":"%(fix_version_end_including)s"}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"%(vectorString)s","attackVector":"NETWORK","attackComplexity":"%(attackComplexity)s","privilegesRequired":"NONE","userInteraction":"%(userInteraction)s","scope":"UNCHANGED","confidentialityImpact":"%(severity)s","integrityImpact":"%(severity)s","availabilityImpact":"%(severity)s","baseScore":%(score).1f,"baseSeverity":"%(severity)s"},"exploitabilityScore":%(exploitabilityScore).1f,"impactScore":%(score).1f},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"NONE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL","baseScore":%(score).1f},"severity":"%(severity)s","exploitabilityScore":%(exploitabilityScore).1f,"impactScore":%(score).1f,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}},"publishedDate":"%(publishedDate)s","lastModifiedDate":"%(lastModifiedDate)s"}
"""

osv_url_dict = {
    "javascript": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    "python": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "go": "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
    "java": "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip",
    "rust": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
    "csharp": "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip",
    "ruby": "https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip",
    "dwf": "https://osv-vulnerabilities.storage.googleapis.com/DWF/all.zip",
    "gsd": "https://osv-vulnerabilities.storage.googleapis.com/GSD/all.zip",
    "hex": "https://osv-vulnerabilities.storage.googleapis.com/Hex/all.zip",
    "packagist": "https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip",
    "pub": "https://osv-vulnerabilities.storage.googleapis.com/Pub/all.zip",
    "uvi": "https://osv-vulnerabilities.storage.googleapis.com/UVI/all.zip",
    "github": "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
    "alpine": "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip",
    "debian": "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip",
    "cran": "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip",
    "almalinux": "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip",
    "rockylinux": "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip",
    "swift": "https://osv-vulnerabilities.storage.googleapis.com/SwiftURL/all.zip",
    "git": "https://osv-vulnerabilities.storage.googleapis.com/GIT/all.zip",
}

# These feeds introduce too much false positives
if os.getenv("OSV_INCLUDE_FUZZ"):
    osv_url_dict[
        "linux"
    ] = "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip"
    osv_url_dict[
        "oss-fuzz"
    ] = "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip"
    osv_url_dict["android"] = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip",

VULN_LIST_URL = "https://github.com/appthreat/vuln-list/archive/refs/heads/main.zip"

# Placeholder fix version to use to indicate max versions
PLACEHOLDER_FIX_VERSION = "99.99.9"

# Placeholder exclude version to use to indicate non-vulnerability
# This is highly important for debian where a specific distro may be non-vulnerable
# While CPEs are the correct method of representing the exclusion, this version hack is aimed to be a short workaround
PLACEHOLDER_EXCLUDE_VERSION = "88.88.8"

# How many CVEs should be packed and written to the db file as a unit
# A large value here requires a larger max_buffer_size. Else could lead to msgpack.exceptions.BufferFull exceptions during read
BATCH_WRITE_SIZE = 20

# Limits size of unpacked data
MAX_BUFFER_SIZE = 200 * 1024 * 1024  # 200 MiB

THREAT_TO_SEVERITY = {
    "unspecified": "LOW",
    "": "LOW",
    "negligible": "LOW",
    "low": "LOW",
    "unimportant": "LOW",
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

VENDOR_TO_VERS_SCHEME = {
    "almalinux": "rpm",
    "rocky": "rpm",
    "photon": "rpm",
    "ubuntu": "deb",
    "debian": "deb",
    "suse": "rpm",
    "redhat": "rpm",
    "opensuse": "rpm",
    "alpine": "apk",
    "gentoo": "ebuild",
    "amazon": "rpm",
    "wolfi": "apk",
    "chainguard": "apk",
}

OS_PKG_TYPES = (
    "deb",
    "apk",
    "rpm",
    "swid",
    "alpm",
    "docker",
    "oci",
    "container",
    "qpkg",
    "buildroot",
    "coreos",
    "ebuild",
)

# URL for the pre-compiled database
VDB_DATABASE_URL = os.getenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdbxz:v6")
