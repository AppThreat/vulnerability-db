from vdb.lib import utils as utils


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
    res = utils.version_compare("2.10.0", "2.1.0", "2.1.5")
    assert not res
    res = utils.version_compare("2.10.0", "2.0.0", "2.9.10")
    assert not res
    res = utils.version_compare("2.0.0", None, "2.7.9", "2.0.0")
    assert not res
    res = utils.version_compare("2.7.9", "2.0.0", None, None, "2.7.9")
    assert not res
    res = utils.version_compare("1.0", "1.0", "3.0")
    assert res
    res = utils.version_compare("1.0", "1.0.0", "3.0")
    assert res
    res = utils.version_compare("2.0", "1.0", "3.0")
    assert res
    res = utils.version_compare("2.0.0", "1.0", "3.0")
    assert res
    res = utils.version_compare("3.0", "1.0", "3.0")
    assert res
    res = utils.version_compare("3.0.0", "1.0", "3.0")
    assert res
    res = utils.version_compare("4.0", "1.0", "3.0")
    assert not res
    res = utils.version_compare("2.9.10.5", "*", "*", None, "2.8.11")
    assert not res
    res = utils.version_compare("2.9.10.5", "2.0.0", "*", None, "2.9.10.5")
    assert not res
    res = utils.version_compare("2.9.10.3", "2.0.0", "*", None, "2.9.10.5")
    assert res
    res = utils.version_compare("2.9.10.4", "2.0.0", "*", None, "2.9.10.5")
    assert res
    res = utils.version_compare("2.9.10.3", "2.9.0", "2.9.10.4", None, None)
    assert res
    res = utils.version_compare("2.9.10.4", "2.9.0", "2.9.10.4", None, None)
    assert res
    res = utils.version_compare("2.9.10.3", None, "2.9.10.4")
    assert res
    res = utils.version_compare("2.9.10.4", None, "2.9.10.5")
    assert res
    res = utils.version_compare("2.9.10.4", None, "2.9.10.1")
    assert not res
    res = utils.version_compare("2.9.10.4", None, "2.9.10")
    assert not res
    res = utils.version_compare("2.9.10.3", "0", "2.9.10.4")
    assert res
    res = utils.version_compare("2.9.10.4", "0", "2.9.10.5")
    assert res
    res = utils.version_compare("2.9.10.4", "0", "2.9.10.1")
    assert not res
    res = utils.version_compare("2.9.10.4", "0", "2.9.10")
    assert not res
    res = utils.version_compare("5.2.0.RELEASE", "5.2.0", "5.2.4")
    assert res
    res = utils.version_compare("5.2.1.FINAL", "5.2.0", "5.2.4")
    assert res
    res = utils.version_compare("5.2.5.FINAL", "5.2.0", "5.2.4")
    assert not res
    res = utils.version_compare("5.2.0.RELEASE", "5.2.0-alpha1", "5.2.4")
    assert res
    res = utils.version_compare("5.2.1.FINAL", "5.2.0-beta.1", "5.2.4")
    assert res
    res = utils.version_compare("5.2.5.FINAL", "5.2.0", "5.2.4")
    assert not res
    res = utils.version_compare("2.0.27.Final", None, "2.1.0")
    assert res
    res = utils.version_compare("2.0.27.Final", None, "2.0.29")
    assert res
    res = utils.version_compare("2.0.27.Final", None, None, None, "2.1.0")
    assert res
    res = utils.version_compare("2.0.27.Final", None, None, None, "2.0.29")
    assert res
    res = utils.version_compare("2.0.27.Final", "*", "*", None, "2.1.1")
    assert res
    res = utils.version_compare("2.0.27.Final", "*", "*", None, "2.0.29")
    assert res


def test_version_compare_go():
    res = utils.version_compare("v1.1.1", "v1.1.0", "v1.1.2")
    assert res
    res = utils.version_compare("v1.1.3", "v1.1.0", "v1.1.2")
    assert not res
    res = utils.version_compare(
        "v0.0.0-20190308221718-c2843e01d9a2", "2019-03-25", "2019-03-25"
    )
    assert not res
    res = utils.version_compare("v0.0.0-20190308221718-c2843e01d9a2", "*", "2017-03-17")
    assert not res
    res = utils.version_compare("v0.0.0-20190308221718-c2843e01d9a2", "*", "2019-03-17")
    assert res
    res = utils.version_compare(
        "v0.0.0-20180904163835-0709b304e793", "2019-03-25", "2019-03-25"
    )
    assert not res
    res = utils.version_compare(
        "v0.0.0-20180904163835-0709b304e793", "2018-09-03", "2018-09-05"
    )
    assert res
    res = utils.version_compare(
        "v0.0.0-20180904163835-0709b304e793", "2018-09-04", "2018-09-05"
    )
    assert res
    res = utils.version_compare(
        "v0.0.0-20180904163835-0709b304e793", "2018-09-05", "2018-09-05"
    )
    assert not res
    res = utils.version_compare("v0.0.0-20180904163835-0709b304e793", "*", "2017-03-17")
    assert not res
    res = utils.version_compare("v0.0.0-20180826012351-8a410e7b638d", "*", "2018-09-25")
    assert res
    res = utils.version_compare("v0.0.0-20180826012351-8a410e7b638d", "*", "2018-07-12")
    assert not res
    res = utils.version_compare("v0.0.0-20180826012351-8a410e7b638d", "*", "2018-09-27")
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


def test_fix_test():
    assert (
        utils.fix_text(
            "Unauthenticated crypto and weak IV in Magento\\Framework\\Encryption"
        )
        == "Unauthenticated crypto and weak IV in Magento Framework Encryption"
    )


def test_convert_md_references():
    assert utils.convert_md_references(
        "- [Issue #60](https://github.com/tj/node-growl/issues/60)\n- [PR #61](https://github.com/tj/node-growl/pull/61)"
    ) == [
        {"name": "Issue #60", "url": "https://github.com/tj/node-growl/issues/60"},
        {"name": "PR #61", "url": "https://github.com/tj/node-growl/pull/61"},
    ]
