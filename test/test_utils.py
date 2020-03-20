import vdb.lib.utils as utils


def test_normalise():
    res = utils.normalise_num(100, 3)
    assert res == 100

    res = utils.normalise_num(100, 4)
    assert res == 1000

    res = utils.normalise_num(100, 2)
    assert res == 100
    assert utils.normalise_version_str("2.0.0", 3) == "2.0.0"
    assert utils.normalise_version_str("2.0.10", 4) == "2.0.10.0"


def test_version_compare():
    res = utils.version_compare("3.0.0", "2.0.0", "2.7.9.4")
    assert not res
    res = utils.version_compare("2.0.0", "2.0.0", "2.7.9.4")
    assert res
    res = utils.version_compare("2.7.0", "2.0.0", "2.7.9.4")
    assert res
    res = utils.version_compare("2.7.9.4", "2.0.0", "2.7.9.4")
    assert res
    res = utils.version_compare("2.7.9.5", "2.0.0", "2.7.9.4")
    assert not res
    res = utils.version_compare("1.0.0", "2.0.0", "2.7.9.4")
    assert not res
    res = utils.version_compare("4.0.0", "2.0.0", "2.7.9.4")
    assert not res
    res = utils.version_compare("3.7.9.4", "2.0.0", "*")
    assert res


def test_version_parts_compare():
    res = utils.version_compare("42.2.8", "*", "9.1.22")
    assert not res
    res = utils.version_compare("42.2.8", "*", "9.3.15")
    assert not res
    res = utils.version_compare("42.2.8", "*", "9.0")
    assert not res
    res = utils.version_compare("1.2.0", "0.7.0", "1.2.0")
    assert res
    res = utils.version_compare("2.1.8", "2.0.0", "2.0.14")
    assert not res
    res = utils.version_compare("2.1.800.0", "2.0.0", "2.2.14")
    assert res
    res = utils.version_compare("2.1.8.0", "2.0.0.800", "2.2.14.10")
    assert res
    res = utils.version_compare("82.1.8.0", "52.0.0", "96.2")
    assert res


def test_version_build_compare():
    res = utils.version_compare("1.2.0", "1.2.0-alpha", "1.2.0-beta")
    assert not res
    res = utils.version_compare("1.2.0", "1.1.0-alpha", "1.2.0-beta")
    assert not res
    res = utils.version_compare("1.3.0", "1.2.0-alpha", "1.3.1-beta")
    assert res
    res = utils.version_compare("1.3.0", "1.2.0", "1.3.1-beta")
    assert res
    res = utils.version_compare("1.3.0", "1.2.0-beta", "1.3.2.0")
    assert res


def test_parse_uri():
    vendor, package, version = utils.parse_cpe(
        "cpe:2.3:o:google:android:9.0:*:*:*:*:*:*:*"
    )
    assert vendor == "google"
    assert package == "android"
    assert version == "9.0"


def test_version_len():
    assert utils.version_len("1.0.0") == 3
    assert utils.version_len("2.1.800.5") == 6
    assert utils.version_len("1.2.0-beta1") == 3
    assert utils.version_len("1.3.0.beta1") == 3
