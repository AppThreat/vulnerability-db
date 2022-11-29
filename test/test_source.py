import json
import os

import pytest

from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource
from vdb.lib.aqua import AquaSource


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
def test_aqua_alsa_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "ALSA-2022:8580.json"
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
        os.path.dirname(os.path.realpath(__file__)), "data", "RLSA-2022:7730.json"
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
def test_aqua_redhat_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2022-45418.json"
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
def test_aqua_photon_json():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "CVE-2021-3618.json"
    )
    with open(test_cve_data, "r") as fp:
        return json.loads(fp.read())


def test_convert(test_cve_json):
    nvdlatest = NvdSource()
    data = nvdlatest.convert(test_cve_json)
    assert len(data) == 384
    for v in data:
        details = v.details
        for detail in details:
            assert detail
            assert detail.severity
            assert detail.package
            assert detail.package_type


def test_convert2(test_cve_wconfig_json):
    nvdlatest = NvdSource()
    data = nvdlatest.convert(test_cve_wconfig_json)
    assert len(data) == 1
    for v in data:
        details = v.details
        for detail in details:
            assert detail
            assert detail.severity
            assert detail.package
            assert detail.package_type
            assert not detail.fixed_location


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_nvd_download():
    nvdlatest = NvdSource()
    data = nvdlatest.download_recent()
    assert len(data) > 300


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_download_all():
    nvdlatest = NvdSource()
    data = nvdlatest.download_all()
    assert len(data) > 128000


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


def test_osv_convert(test_osv_rust_json, test_osv_mvn_json, test_osv_mixed_json):
    osvlatest = OSVSource()
    cve_data = osvlatest.convert(test_osv_rust_json)
    assert cve_data

    cve_data = osvlatest.convert(test_osv_mvn_json)
    assert cve_data
    assert len(cve_data) == 3

    cve_data = osvlatest.convert(test_osv_mixed_json)
    assert cve_data
    assert len(cve_data) == 3


def test_aqua_convert(
    test_aqua_alsa_json,
    test_aqua_alas_json,
    test_aqua_rlsa_json,
    test_aqua_ubuntu_json,
    test_aqua_ubuntu1_json,
    test_aqua_ubuntu2_json,
    test_aqua_ubuntu3_json,
    test_aqua_redhat_json,
    test_aqua_arch_json,
    test_aqua_opensuse_json,
    test_aqua_suse_json,
    test_aqua_photon_json,
):
    aqualatest = AquaSource()
    cve_data = aqualatest.convert(test_aqua_alsa_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_alas_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_rlsa_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_ubuntu_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_ubuntu1_json)
    assert not cve_data
    cve_data = aqualatest.convert(test_aqua_ubuntu2_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_ubuntu3_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_redhat_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_arch_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_opensuse_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_suse_json)
    assert cve_data
    cve_data = aqualatest.convert(test_aqua_photon_json)
    assert cve_data
