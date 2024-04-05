import json
import os

import pytest

from vdb.lib import VulnerabilityLocation, db6, search
from vdb.lib.aqua import AquaSource
from vdb.lib.cve import CVESource
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource


@pytest.fixture
def test_cve_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cve_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_cve_wconfig_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cve_wconfig_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_nvd_api_json1():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2024-0057.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_nvd_api_json2():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2024-21312.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_nvd_api_json3():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2024-23771.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_nvd_api_json4():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2015-3192.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_nvd_api_git_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2023-52426.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_rust_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_rust_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_mvn_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_mvn_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_mixed_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_mixed_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_go_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "GO-2022-0646.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_pypi_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv-pypi.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_pypi2_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv-pypi2.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_swift_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_swift_data.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_swift2_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_swift_data2.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_mevents_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv_multi_events.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_osv_git_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "osv-git.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_alsa_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "ALSA-2022-8580.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_alas_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "ALAS2022-2022-207.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_rlsa_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "RLSA-2022-7730.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-45406.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu2_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-3715.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu1_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-6083.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu3_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-3219.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu4_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-32081.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_ubuntu5_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-3821.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_redhat_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-45418.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_redhat2_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-21824.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_arch_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "AVG-999.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_opensuse_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "data",
        "openSUSE-SU-2022-2801-1.json",
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_suse_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "SUSE-SU-2022-4192-1.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_suse_json1():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "SUSE-SU-2015-0439-1.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_photon_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2021-3618.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2019-18625.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian2_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2023-21500.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian3_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-3567.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian4_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "DLA-981-1.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian5_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2021-22890.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian6_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-32091.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_debian7_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2020-35448.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_cg_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "redis.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_wolfi_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "protobuf-c.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


@pytest.fixture
def test_aqua_alpine_unfixed_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2024-25450.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


def test_convert(test_cve_json):
    nvdlatest = NvdSource()
    vulnerabilities = nvdlatest.convert(test_cve_json)
    assert len(vulnerabilities) == 384
    for v in vulnerabilities:
        details = v.details
        for detail in details:
            assert detail
            assert detail.severity
            assert detail.package
            assert detail.package_type

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 496
    assert cve_index_count == 1155
    results_count = len(list(search.search_by_any("CVE-2020-0001")))
    assert results_count == 4
    results_count = len(
        list(search.search_by_any("cpe:2.3:o:google:android:8.1:*:*:*:*:*:*:*"))
    )
    assert results_count == 25

    cvesource = CVESource()
    cve = cvesource.convert5(vulnerabilities)
    assert len(cve) == 384

    db6.clear_all()
    cvesource.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 0
    assert cve_index_count == 0


def test_convert2(test_cve_wconfig_json):
    nvdlatest = NvdSource()
    vulnerabilities = nvdlatest.convert(test_cve_wconfig_json)
    assert len(vulnerabilities) == 1
    for v in vulnerabilities:
        details = v.details
        for detail in details:
            assert detail
            assert detail.severity
            assert detail.package
            assert detail.package_type
            assert not detail.fixed_location

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 4
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 4
    results_count = len(
        list(search.search_by_any("cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*"))
    )
    assert results_count == 1

    cvesource = CVESource()
    cve = cvesource.convert5(vulnerabilities)
    assert len(cve) == 1

    db6.clear_all()
    cvesource.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 0
    assert cve_index_count == 0


def test_nvd_api_convert(
    test_nvd_api_json1,
    test_nvd_api_json2,
    test_nvd_api_json3,
    test_nvd_api_json4,
    test_nvd_api_git_json,
):
    # json1
    nvdlatest = NvdSource()
    vulnerabilities = nvdlatest.convert(test_nvd_api_json1)
    assert len(vulnerabilities) == 1
    for v in vulnerabilities:
        details = v.details
        for detail in details:
            assert detail
            assert detail.severity
            assert detail.package
            assert detail.package_type
            assert not detail.fixed_location

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 4
    assert cve_index_count == 20
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2024-0057")))
    assert results_count == 10
    results_count = len(
        list(search.search_by_any("cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*"))
    )
    assert results_count == 1

    # json2
    vulnerabilities = nvdlatest.convert(test_nvd_api_json2)
    assert len(vulnerabilities) == 1
    cvesource = CVESource()
    cve = cvesource.convert5(vulnerabilities)
    assert len(cve) == 1

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 7
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2024-21312")))
    assert results_count == 7

    # json3
    vulnerabilities = nvdlatest.convert(test_nvd_api_json3)
    assert len(vulnerabilities) == 0
    cve = cvesource.convert5(vulnerabilities)
    assert len(cve) == 0

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 0
    assert cve_index_count == 0
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2024-23771")))
    assert results_count == 0

    # json4
    vulnerabilities = nvdlatest.convert(test_nvd_api_json4)
    assert len(vulnerabilities) == 1

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 21
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2015-3192")))
    assert results_count == 21
    results_count = len(
        list(
            search.search_by_any(
                "cpe:2.3:a:pivotal_software:spring_framework:3.2.0:*:*:*:*:*:*:*"
            )
        )
    )
    assert results_count == 2

    # git_json
    vulnerabilities = nvdlatest.convert(test_nvd_api_git_json)
    assert len(vulnerabilities) == 1
    assert len(vulnerabilities[0].details) == 2

    db6.clear_all()
    nvdlatest.store(vulnerabilities)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2023-52426")))
    assert results_count == 2
    results_count = len(
        list(
            search.search_by_any("cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*")
        )
    )
    assert results_count == 1


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_nvd_download():
    nvdlatest = NvdSource()
    data = nvdlatest.download_recent()
    assert len(data) > 300


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_download_all():
    nvdlatest = NvdSource()
    nvdlatest.download_all()


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_gha_download():
    ghalatest = GitHubSource()
    data = ghalatest.download_recent()
    assert len(data) > 100


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_gha_download_all():
    ghalatest = GitHubSource()
    data = ghalatest.download_all()
    assert len(data) > 1000


def test_gha_version_ranges():
    source = GitHubSource()
    version_list = source.get_version_range("< 1.10.2")
    assert version_list == ("", "", "", "1.10.2")
    version_list = source.get_version_range("= 0.2.0")
    assert version_list == ("", "0.2.0", "", "")
    version_list = source.get_version_range("<= 1.0.8")
    assert version_list == ("", "1.0.8", "", "")
    version_list = source.get_version_range(">= 4.3.0, < 4.3.5")
    assert version_list == ("4.3.0", "", "", "4.3.5")
    version_list = source.get_version_range(">= 0.5.1")
    assert version_list == ("0.5.1", "", "", "")
    version_list = source.get_version_range("> 2.2.0, < 3.1.8")
    assert version_list == ("", "", "2.2.0", "3.1.8")
    version_list = source.get_version_range("> 2.0.0, <= 2.0.14")
    assert version_list == ("", "2.0.14", "2.0.0", "")
    version_list = source.get_version_range(">= 1.0.0, <= 2.0.14")
    assert version_list == ("1.0.0", "2.0.14", "", "")
    version_list = source.get_version_range("1.1.0")
    assert version_list == ("1.1.0", "", "", "")
    version_list = source.get_version_range("> 11.0, < 24.1.1")
    assert version_list == ("", "", "11.0", "24.1.1")


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_osv_download_all():
    osvlatest = OSVSource()
    data = osvlatest.download_all()
    assert len(data) > 1000


def test_osv_convert(
    test_osv_rust_json,
    test_osv_mvn_json,
    test_osv_mixed_json,
    test_osv_go_json,
    test_osv_pypi_json,
    test_osv_pypi2_json,
    test_osv_swift_json,
    test_osv_swift2_json,
    test_osv_mevents_json,
    test_osv_git_json,
):
    osvlatest = OSVSource()

    # git
    cve_data = osvlatest.convert(test_osv_git_json)
    assert cve_data
    assert len(cve_data) == 5

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 5
    assert cve_index_count == 5
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2019-0647")))
    assert results_count == 2
    results_count = len(list(search.search_by_any("pkg:maven/org.springframework/spring-web")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("pkg:apk/alpine/mariadb?arch=source")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("pkg:apk/alpine/alpine-3.2/mariadb?arch=source")))
    assert results_count == 1

    # multi events
    cve_data = osvlatest.convert(test_osv_mevents_json)
    assert cve_data
    assert len(cve_data) == 4

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 4
    assert cve_index_count == 4
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2019-3192")))
    assert results_count == 1
    results_count = len(list(search.search_by_any("pkg:apk/alpine/mariadb?arch=source")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("pkg:maven/org.springframework/spring-web")))
    assert results_count == 4

    # swift
    cve_data = osvlatest.convert(test_osv_swift_json)
    assert cve_data
    assert len(cve_data) == 2

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2

    # swift2
    cve_data = osvlatest.convert(test_osv_swift2_json)
    assert cve_data
    assert len(cve_data) == 2

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2024-21631")))
    assert results_count == 2

    # rust
    cve_data = osvlatest.convert(test_osv_rust_json)
    assert cve_data

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("pkg:apk/alpine/mariadb?arch=source")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("pkg:cargo/rusqlite")))
    assert results_count == 1

    # maven
    cve_data = osvlatest.convert(test_osv_mvn_json)
    assert cve_data
    assert len(cve_data) == 3

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 3
    assert cve_index_count == 3

    # mixed
    cve_data = osvlatest.convert(test_osv_mixed_json)
    assert cve_data
    assert len(cve_data) == 3

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 3
    assert cve_index_count == 3
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-23440")))
    assert results_count == 2

    # go
    cve_data = osvlatest.convert(test_osv_go_json)
    assert cve_data
    assert len(cve_data) == 1

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2020-8911")))
    assert results_count == 1

    # pypi
    cve_data = osvlatest.convert(test_osv_pypi_json)
    assert cve_data
    assert len(cve_data) == 1

    db6.clear_all()
    osvlatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-25951")))
    assert results_count == 1

    # pypi2
    cve_data = osvlatest.convert(test_osv_pypi2_json)
    assert not cve_data


def test_aqua_convert(
    test_aqua_alsa_json,
    test_aqua_alas_json,
    test_aqua_rlsa_json,
    test_aqua_ubuntu_json,
    test_aqua_ubuntu1_json,
    test_aqua_ubuntu2_json,
    test_aqua_ubuntu3_json,
    test_aqua_redhat_json,
    test_aqua_redhat2_json,
    test_aqua_arch_json,
    test_aqua_opensuse_json,
    test_aqua_suse_json,
    test_aqua_suse_json1,
    test_aqua_photon_json,
    test_aqua_debian_json,
    test_aqua_debian2_json,
    test_aqua_debian3_json,
    test_aqua_debian4_json,
    test_aqua_debian5_json,
    test_aqua_debian6_json,
    test_aqua_debian7_json,
):
    aqualatest = AquaSource()

    # alsa
    cve_data = aqualatest.convert(test_aqua_alsa_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1

    # alas
    cve_data = aqualatest.convert(test_aqua_alas_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 7
    assert cve_index_count == 7
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-34903")))
    assert results_count == 7

    # rlsa
    cve_data = aqualatest.convert(test_aqua_rlsa_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 4
    assert cve_index_count == 4
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-32746")))
    assert results_count == 4

    # ubuntu
    cve_data = aqualatest.convert(test_aqua_ubuntu_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 27
    assert cve_index_count == 27
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-45406")))
    assert results_count == 27

    # ubuntu1
    cve_data = aqualatest.convert(test_aqua_ubuntu1_json)
    assert cve_data
    assert len(cve_data) == 8

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 8
    assert cve_index_count == 8
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-6083")))
    assert results_count == 8

    # ubuntu2
    cve_data = aqualatest.convert(test_aqua_ubuntu2_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 10
    assert cve_index_count == 10
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-3715")))
    assert results_count == 10

    # ubuntu3
    cve_data = aqualatest.convert(test_aqua_ubuntu3_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 14
    assert cve_index_count == 14
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-3219")))
    assert results_count == 14

    # redhat
    cve_data = aqualatest.convert(test_aqua_redhat_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 14
    assert cve_index_count == 14
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-45418")))
    assert results_count == 14

    # redhat2
    cve_data = aqualatest.convert(test_aqua_redhat2_json)
    assert cve_data
    assert len(cve_data) == 7

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 7
    assert cve_index_count == 7
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-21824")))
    assert results_count == 7

    # arch
    cve_data = aqualatest.convert(test_aqua_arch_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2019-13045")))
    assert results_count == 1

    # opensuse
    cve_data = aqualatest.convert(test_aqua_opensuse_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-29869")))
    assert results_count == 1

    # suse
    cve_data = aqualatest.convert(test_aqua_suse_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-3618")))
    assert results_count == 1

    # suse1
    cve_data = aqualatest.convert(test_aqua_suse_json1)
    assert not cve_data

    # photon
    cve_data = aqualatest.convert(test_aqua_photon_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-3618")))
    assert results_count == 1

    # debian
    cve_data = aqualatest.convert(test_aqua_debian_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 4
    assert cve_index_count == 4
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2019-18625")))
    assert results_count == 4

    # debian2
    cve_data = aqualatest.convert(test_aqua_debian2_json)
    assert not cve_data

    # debian3
    cve_data = aqualatest.convert(test_aqua_debian3_json)
    assert cve_data

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-3567")))
    assert results_count == 1

    # debian4
    cve_data = aqualatest.convert(test_aqua_debian4_json)
    assert not cve_data

    # debian5
    cve_data = aqualatest.convert(test_aqua_debian5_json)
    assert cve_data
    assert len(cve_data) == 2

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-22890")))
    assert results_count == 2

    # debian6
    cve_data = aqualatest.convert(test_aqua_debian6_json)
    assert cve_data
    assert len(cve_data) == 2

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-32091")))
    assert results_count == 2

    # debian7
    cve_data = aqualatest.convert(test_aqua_debian7_json)
    assert cve_data
    assert len(cve_data) == 1

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 1
    assert cve_index_count == 1
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2020-35448")))
    assert results_count == 1


def test_ubuntu_convert(test_aqua_ubuntu4_json, test_aqua_ubuntu5_json):
    aqualatest = AquaSource()

    # ubuntu4
    cve_data = aqualatest.convert(test_aqua_ubuntu4_json)
    assert cve_data
    assert len(cve_data) == 14

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 14
    assert cve_index_count == 14
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-32081")))
    assert results_count == 14

    # ubuntu5
    cve_data = aqualatest.convert(test_aqua_ubuntu5_json)
    assert cve_data
    assert len(cve_data) == 10

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 10
    assert cve_index_count == 10
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-3821")))
    assert results_count == 10


def test_wolfi_convert(test_aqua_cg_json, test_aqua_wolfi_json):
    aqualatest = AquaSource()

    cve_data = aqualatest.convert(test_aqua_cg_json)
    assert cve_data
    assert len(cve_data) == 9

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 9
    assert cve_index_count == 9
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2022-0543")))
    assert results_count == 1

    cve_data = aqualatest.convert(test_aqua_wolfi_json)
    assert cve_data
    assert len(cve_data) == 2

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 2
    assert cve_index_count == 2
    results_count = len(list(search.search_by_any("CVE-2020-8022")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2021-3121")))
    assert results_count == 1


def test_alpine_convert(test_aqua_alpine_unfixed_json):
    aqualatest = AquaSource()

    cve_data = aqualatest.convert(test_aqua_alpine_unfixed_json)
    assert cve_data
    assert len(cve_data) == 3

    db6.clear_all()
    aqualatest.store(cve_data)
    cve_data_count, cve_index_count = db6.stats()
    assert cve_data_count == 3
    assert cve_index_count == 3
    results_count = len(list(search.search_by_any("CVE-2024-25451")))
    assert results_count == 0
    results_count = len(list(search.search_by_any("CVE-2024-25450")))
    assert results_count == 3


def test_vuln_location():
    vl = VulnerabilityLocation.from_values(
        "cpe:2.3:a:pivotal_software:spring_framework:3.2.0:*:*:*:*:*:*:*",
        "3.2.0",
        "3.2.0",
        "",
        "",
    )
    assert vl.version == "3.2.0"
    vl = VulnerabilityLocation.from_values(
        "cpe:2.3:a:org.springframework:spring-web:*:*:*:*:*:*:*:*",
        "5.0.0.RC2",
        "*",
        "",
        "5.0.0.RC3",
    )
    assert vl.version == ">=5.0.0.RC2-<5.0.0.RC3"
