import os

from appdirs import user_cache_dir, user_data_dir

# NVD CVE json feed url
nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%(year)s.json.gz"

# NVD start year. 2018 is quicker. 2002 is quite detailed but slow
nvd_start_year = os.getenv("NVD_START_YEAR", 2018)

# GitHub advisory feed url
gha_url = os.getenv("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql")

# No of pages to download from GitHub during a full refresh
gha_pages_count = os.getenv("GITHUB_PAGE_COUNT", 2)
npm_pages_count = os.getenv("NPM_PAGE_COUNT", 2)

# DB file dir
data_dir = os.getenv("VDB_HOME", user_data_dir("vdb"))
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

cache_dir = os.getenv("VDB_CACHE", user_cache_dir("vdb"))
if not os.path.exists(cache_dir):
    os.makedirs(cache_dir)

# Binary db file
vdb_bin_file = os.path.join(data_dir, "data.vdb")

# Binary DB index file
vdb_bin_index = os.path.join(data_dir, "data.index.vdb")

# NPM advisory url
npm_server = "https://registry.npmjs.org"
npm_audit_url = npm_server + "/-/npm/v1/security/audits"
npm_advisories_url = npm_server + "/-/npm/v1/security/advisories"

npm_app_info = {"name": "appthreat-vdb", "version": "1.0.0"}

CVE_TPL = """
{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"%(cve_id)s","ASSIGNER":"%(assigner)s"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"%(cwe_id)s"}]}]},"references":{"reference_data": %(references)s},"description":{"description_data":[{"lang":"en","value":"%(description)s"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:%(edition)s:*:*:*:*:*","versionStartExcluding":"%(version_start_excluding)s","versionEndExcluding":"%(version_end_excluding)s","versionStartIncluding":"%(version_start_including)s","versionEndIncluding":"%(version_end_including)s"}, {"vulnerable":false,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(fix_version_start_including)s:*:%(edition)s:*:*:*:*:*","versionStartExcluding":"%(fix_version_start_excluding)s","versionEndExcluding":"%(fix_version_end_excluding)s","versionStartIncluding":"%(fix_version_start_including)s","versionEndIncluding":"%(fix_version_end_including)s"}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"%(vectorString)s","attackVector":"NETWORK","attackComplexity":"%(attackComplexity)s","privilegesRequired":"NONE","userInteraction":"REQUIRED","scope":"UNCHANGED","confidentialityImpact":"%(severity)s","integrityImpact":"%(severity)s","availabilityImpact":"%(severity)s","baseScore":%(score).1f,"baseSeverity":"%(severity)s"},"exploitabilityScore":%(exploitabilityScore).1f,"impactScore":%(score).1f},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"NONE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL","baseScore":%(score).1f},"severity":"%(severity)s","exploitabilityScore":%(exploitabilityScore).1f,"impactScore":%(score).1f,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}},"publishedDate":"%(publishedDate)s","lastModifiedDate":"%(lastModifiedDate)s"}
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
    "android": "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip",
    "alpine": "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip",
    "gsd": "https://osv-vulnerabilities.storage.googleapis.com/GSD/all.zip",
    "linux": "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip",
    "debian": "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip",
    "oss-fuzz": "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip",
}

aquasec_vuln_list_url = (
    "https://github.com/ngcloudsec/vuln-list/archive/refs/heads/main.zip"
)

# CVE types to exclude - hardware
nvd_exclude_types = ["h"]
if os.getenv("NVD_EXCLUDE_TYPES") is not None:
    nvd_exclude_types = os.getenv("NVD_EXCLUDE_TYPES", "").split(",")

# Placeholder fix version to use to indicate max versions
placeholder_fix_version = "99.99.9"

# Placeholder exclude version to use to indicate non-vulnerability
# This is highly important for debian where a specific distro may be non-vulnerable
# While CPEs are the correct method of representing the exclusion, this version hack is aimed to be a short workaround
placeholder_exclude_version = "88.88.8"
