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
    res = utils.version_compare("2.0.27.RELEASE", "*", "2.0.27", None, None)
    assert res
    res = utils.version_compare("0.6.18", "0", "0.6.19-r0", None, None)
    assert res
    res = utils.version_compare("2.15.4-r0", "0", "2.14.1-r0", None, None)
    assert not res
    res = utils.version_compare("1.8.19", "0", "1.8.20_p2-r0", None, None)
    assert res
    res = utils.version_compare("5.8.9", "0", "6.0_p20170701-r0", None, None)
    assert res
    res = utils.version_compare("1.5", "0", "1.6_rc2-r5", None, None)
    assert res
    res = utils.version_compare("0.99.1", "0", "0.99.4-r0", None, None)
    assert res
    res = utils.version_compare("0.7.0", "0", "0.7.1_alpha-r0", None, None)
    assert res


def test_version_compare1():
    res = utils.version_compare("12.1.0.2.0", "*", "12.1.0.2", None, None)
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


def test_version_build_diff_compare():
    res = utils.version_compare("7.0.0", "*", "*", None, "2020-04-23t00-58-49z")
    assert not res
    res = utils.version_compare("7.0.0", "*", "*", None, "2018-05-16t23-35-33z")
    assert not res
    res = utils.version_compare("7.0.0", "2018-05-16t23-35-33z", "2020-04-23t00-58-49z")
    assert not res
    res = utils.version_compare(
        "7.0.0", None, "2020-04-23t00-58-49z", "2020-04-23t00-58-49z", None
    )
    assert not res
    res = utils.version_compare(
        "7.0.0", None, "2018-05-16t23-35-33z", "2018-05-16t23-35-33z", None
    )
    assert not res
    res = utils.version_compare("7.0.0", "*", None, "2020-04-23t00-58-49z", None)
    assert not res
    res = utils.version_compare("7.0.0", "*", None, "2018-05-16t23-35-33z", None)
    assert not res


def test_version_hash_compare():
    res = utils.version_compare(
        "3.1.2", "0", None, None, "acb672b6a179567632e032f547582f30fa2f4aa7"
    )
    assert not res
    res = utils.version_compare(
        "3.1.2",
        "acb672b6a179567632e032f547582f30fa2f4aa7",
        "acb672b6a179567632e032f547582f30fa2f4aa7",
        None,
        None,
    )
    assert not res
    res = utils.version_compare(
        "8b626d45127d6f5ada7d815b83cfdc09e8cb1394",
        "8b626d45127d6f5ada7d815b83cfdc09e8cb1394",
        "8b626d45127d6f5ada7d815b83cfdc09e8cb1394",
        None,
        None,
    )
    assert res


def test_os_build_compare():
    res = utils.version_compare("2.8.4-1+squeeze4", "0", "2.8.6-1+squeeze4")
    assert res
    res = utils.version_compare("2.8.4-7+squeeze4", "0", "2.8.6-1+squeeze4")
    assert res
    res = utils.version_compare("2.6.34-1squeeze8", "0", "2.6.32-48squeeze8")
    assert not res
    res = utils.version_compare("3.0.1-8+wheezy6", "0", "3.0.4-3+wheezy6")
    assert res
    res = utils.version_compare("1:51.2.1-1~deb7u1", "0", "1:52.2.1-1~deb7u1")
    assert res
    res = utils.version_compare("2:51.2.1-1~deb7u1", "0", "1:52.2.1-1~deb7u1")
    assert res
    res = utils.version_compare("6:51.2.1-1~deb7u1", "0", "2:52.2.1-1~deb7u1")
    assert res
    res = utils.version_compare(
        "1.2.0-1.2+wheezy4+deb7u1", "0", "1.2.1-2.2+wheezy4+deb7u1"
    )
    assert res
    res = utils.version_compare("8:7.2.947-7+deb7u4", "0", "2:7.3.547-7+deb7u4")
    assert res
    res = utils.version_compare("9.04~dfsg-6.3+deb7u7", "0", "9.05~dfsg-6.3+deb7u7")
    assert res
    res = utils.version_compare("1:1.7.5.4-1+wheezy5", "0", "1:1.7.10.4-1+wheezy5")
    assert res
    res = utils.version_compare("1:1.7.11.1-1+wheezy5", "0", "1:1.7.10.4-1+wheezy5")
    assert not res
    res = utils.version_compare(
        "7u180-2.6.14-2~deb8u1", "7u179-2.6.14-2~deb8u1", "7u181-2.6.14-2~deb8u1"
    )
    assert res
    res = utils.version_compare(
        "7u182-2.8.14-2~deb8u1", "7u179-2.6.14-2~deb8u1", "7u181-2.6.14-2~deb8u1"
    )
    assert res
    res = utils.version_compare(
        "1.0.8~git20140621.1.440916e+dfsg1-13~deb8u3",
        "0",
        "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3",
    )
    assert res
    res = utils.version_compare("2:3.25-1+debu8u4", "0", "2:3.26-1+debu8u4")
    assert res
    res = utils.version_compare(
        "2.4.9", "0", "2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1"
    )
    assert res
    res = utils.version_compare("2.4.15-7.woody.2.1", "0", "2.4.17-2.woody.2.2")
    assert res
    res = utils.version_compare(
        "0.12.0+git20120207.aaa852f-1+deb7u1",
        "0",
        "0.12.1+git20120407.aaa852f-1+deb7u1",
    )
    assert res
    res = utils.version_compare("2.36.1-8+deb11u1", 0, "*", None, "2.36.1-8+deb11u1")
    assert not res
    res = utils.version_compare("1.10-4+deb11u1", 0, "*", None, "1.10-4+deb11u1")
    assert not res
    res = utils.version_compare("1.15.0", 0, "*", None, "1.15.1-2ubuntu2.2")
    assert res
    res = utils.version_compare("1:1.1.1k-7.el8_6", 0, "*", None, "1.1.1k")
    assert not res
    res = utils.version_compare("1.1.1f-1ubuntu2.8", 0, "*", None, "1.1.1-1ubuntu2.1")
    assert not res
    res = utils.version_compare("0.23.22-1.amzn2.0.1", 0, "*", None, "0.23.22")
    assert not res


def test_ubuntu_openssl():
    res = utils.version_compare("1.1.1f-1ubuntu2.8", 0, "*", None, "1.1.1.e")
    assert not res
    res = utils.version_compare(
        "1.1.1f-1ubuntu2.8", 0, "*", None, "1.1.1-1ubuntu2.1~18.04.2"
    )
    assert not res
    res = utils.version_compare(
        "1.1.1f-1ubuntu2.8", 0, "*", None, "1.1.1-1ubuntu2.1~18.04.6"
    )
    assert not res
    res = utils.version_compare("1.10-0ubuntu4", 0, "*", None, "1.10-0ubuntu4.1")
    assert res
    res = utils.version_compare("2.2.19-3ubuntu2.1", 0, "*", None, "*")
    assert res
    res = utils.version_compare("2.2.19-3ubuntu2.1", 0, "*", None, None)
    assert res
    res = utils.version_compare("2.34-0.1ubuntu9.1", 0, "*", None, "2.34-0.1ubuntu9.3")
    assert res
    res = utils.version_compare("3.0-1", 0, "*", None, "3.0-1ubuntu0.1")
    assert res
    res = utils.version_compare("2:8.39-12build1", 0, "*", None, "8.39-9ubuntu0.1")
    assert not res
    res = utils.version_compare(
        "7.7.0+dfsg-1ubuntu1", 0, "*", None, "7.7.0+dfsg-1ubuntu1.1"
    )
    assert res
    res = utils.version_compare("1.45.5-2ubuntu1", 0, "*", None, "1.45.5-1")
    assert not res
    res = utils.version_compare("3.0-1", 0, "*", None, "3.0-1ubuntu0.1")
    assert res
    res = utils.version_compare("10.34-7", 0, "*", None, "10.34-7ubuntu0.1")
    assert res
    res = utils.version_compare("2:6.2.0+dfsg-4", 0, "*", None, "2:6.2.0+dfsg-4ubuntu0.1")
    assert res


def test_debian_build_compare():
    res = utils.version_compare("1:2019.10.06-1", 0, "*", None, "20070829-6+deb7u1")
    assert not res


def test_parse_uri():
    vendor, package, version, cve_type = utils.parse_cpe(
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


def test_ubuntu_versions():
    assert utils.checkEpoch("1:4.14-1.1+deb7u1build0.12.04.1")
    assert utils.convert_to_semver("0.3.14-11ubuntu6")[0]
    assert utils.convert_to_semver("1.4.9a-1ubuntu0.1")[0]
    assert utils.convert_to_semver("20140405-0ubuntu1")[0]
    assert utils.convert_to_semver("1.10+dfsg~beta1-2ubuntu0.7")[0]
    assert utils.convert_to_semver("1.11.3+dfsg-3ubuntu2")[0]
    assert utils.convert_to_semver("1.0.4cvs20051004-2")[0]
    assert utils.convert_to_semver("7.0.0-0ubuntu45")[0]
    assert utils.convert_to_semver("1.5.0+1.5.1cvs20051015-1ubuntu10")[0]
    assert utils.convert_to_semver("1.2.8rel-1ubuntu3")[0]
    assert utils.convert_to_semver("3.3.8really3.3.7-0ubuntu5.2")[0]
    assert utils.convert_to_semver("1.5.0+1.5.1cvs20051015-1ubuntu10")[0]
    assert utils.convert_to_semver("0.9.2+cvs.1.0.dev.2004.07.28-4ubuntu1")[0]
    assert utils.convert_to_semver("8.1.2-0.20040524cvs-2")[0]
    assert utils.convert_to_semver("6.2.4.5.dfsg1-0.14ubuntu0.1")[0]
    assert utils.convert_to_semver("1.5.dfsg+1.5.0.13~prepatch070731-0ubuntu1")[0]
    assert utils.convert_to_semver("01.03.00.99.svn.300-3")[0]
    assert utils.checkEpoch("1:1.1.1k-7.el8_6")
