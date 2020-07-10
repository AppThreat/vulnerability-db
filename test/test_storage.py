import json
import os
import tempfile

import pytest

from vdb.lib import storage as storage
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource


@pytest.fixture
def test_vuln_data():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cve_data.json"
    )
    with open(test_cve_data, "r") as fp:
        json_data = json.loads(fp.read())
        nvdlatest = NvdSource()
        return nvdlatest.convert(json_data)


@pytest.fixture
def test_gha_data():
    test_cve_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "gha_data.json"
    )
    with open(test_cve_data, "r") as fp:
        json_data = json.loads(fp.read())
        ghalatest = GitHubSource()
        return ghalatest.convert(json_data)[0]


def test_create(test_vuln_data):
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        data = storage.store(test_vuln_data, db_file=fp.name)
        assert data
        fp.flush()

        datas = storage.stream_read(db_file=fp.name)
        assert len(datas) > len(test_vuln_data)
        fp.close()
