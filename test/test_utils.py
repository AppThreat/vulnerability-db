import vulndb.lib.utils as utils


def test_normalise():
    res = utils.normalise_num(100, 3)
    assert res == 100

    res = utils.normalise_num(100, 4)
    assert res == 1000

    res = utils.normalise_num(100, 2)
    assert res == 100


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
