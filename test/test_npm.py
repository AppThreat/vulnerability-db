import json
import os

import pytest

from vdb.lib.npm import NpmSource


@pytest.fixture
def test_app_info():
    return {"name": "appthreat-vulnerability-db-test", "version": "1.0.0"}


@pytest.fixture
def test_pkg_list():
    return ["handlebars|4.1.0", "growl|1.10.0"]


@pytest.fixture
def test_cve_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "npm_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


def test_bulk_search(test_app_info, test_pkg_list):
    data = NpmSource().bulk_search(test_app_info, test_pkg_list)
    assert len(data) == 7
    assert data[0].id == "CVE-2017-16042"


def test_version_ranges():
    source = NpmSource()
    version_list = source.get_version_ranges("<1.10.2")
    assert version_list == [
        {
            "version_start_including": "",
            "version_end_including": "",
            "version_start_excluding": "",
            "version_end_excluding": "1.10.2",
        }
    ]
    version_list = source.get_version_ranges("<=4.0.13 || >=4.1.0 <4.1.2")
    assert version_list == [
        {
            "version_start_including": "",
            "version_end_including": "4.0.13",
            "version_start_excluding": "",
            "version_end_excluding": "",
        },
        {
            "version_start_including": "4.1.0",
            "version_end_including": "",
            "version_start_excluding": "",
            "version_end_excluding": "4.1.2",
        },
    ]


def test_convert(test_cve_json):
    data = NpmSource().convert(test_cve_json)
    assert len(data) == 8
    assert data[0].id == "CVE-2017-16042"
