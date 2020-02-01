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
data_dir = os.environ.get("VULNDB_HOME", user_data_dir("vulndb"))
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

# Binary db file
vulndb_bin_file = os.path.join(data_dir, "data.vdb")

# Binary DB index file
vulndb_bin_index = os.path.join(data_dir, "data.index.vdb")
