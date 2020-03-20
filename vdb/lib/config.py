import os

from appdirs import user_data_dir

# NVD CVE json feed url
nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%(year)s.json.gz"

# NVD start year. 2016 is quicker. 2002 is quite detailed but slow
nvd_start_year = os.environ.get("NVD_START_YEAR", 2016)

# GitHub advisory feed url
gha_url = "https://api.github.com/graphql"

# No of pages to download from GitHub during a full refresh
gha_pages_count = os.environ.get("GITHUB_PAGE_COUNT", 5)

# DB file dir
data_dir = os.environ.get("vdb_HOME", user_data_dir("vdb"))
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

# Binary db file
vdb_bin_file = os.path.join(data_dir, "data.vdb")

# Binary DB index file
vdb_bin_index = os.path.join(data_dir, "data.index.vdb")

# NPM advisory url
npm_url = "https://registry.npmjs.org/-/npm/v1/security/audits"

CVE_TPL = """
{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"%(cve_id)s","ASSIGNER":"%(assigner)s"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"%(cwe_id)s"}]}]},"references":{"reference_data": %(references)s},"description":{"description_data":[{"lang":"en","value":"%(description)s"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:*:*:*:*:*:*","versionStartExcluding":"%(version_start_excluding)s","versionEndExcluding":"%(version_end_excluding)s","versionStartIncluding":"%(version_start_including)s","versionEndIncluding":"%(version_end_including)s"}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"%(vectorString)s","attackVector":"NETWORK","attackComplexity":"%(attackComplexity)s","privilegesRequired":"NONE","userInteraction":"REQUIRED","scope":"UNCHANGED","confidentialityImpact":"%(severity)s","integrityImpact":"%(severity)s","availabilityImpact":"%(severity)s","baseScore":%(score).1f,"baseSeverity":"%(severity)s"},"exploitabilityScore":%(score).1f,"impactScore":%(score).1f},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"NONE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL","baseScore":%(score).1f},"severity":"%(severity)s","exploitabilityScore":%(score).1f,"impactScore":%(score).1f,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}},"publishedDate":"%(publishedDate)s","lastModifiedDate":"%(lastModifiedDate)s"}
"""
