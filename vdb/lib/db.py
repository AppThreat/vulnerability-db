from collections import defaultdict

from vdb.lib import config, storage
from vdb.lib.utils import convert_to_occurrence, parse_cpe, parse_purl, version_compare

index_data = None
vendor_index_data = None
pos_index_data = None


def build_index(index_pos_list):
    """This function builds two index. One with just name and version the other
    including vendor (aka group) string

    :param index_pos_list:
    :return: Normal index and vendor index
    """
    idx = defaultdict(list)
    vendor_idx = defaultdict(list)
    pos_idx = defaultdict(list)
    for dp in index_pos_list:
        store_pos = dp.get("store_pos")
        store_end_pos = dp.get("store_end_pos")
        for d in dp.get("index_list"):
            cve_id = d.get("id")
            min_version = d.get(
                "mie",
                d.get("mii"),
            )
            max_version = d.get(
                "mae",
                d.get("mai"),
            )
            if not min_version:
                min_version = "0"
            if not max_version:
                max_version = "*"
            ver_range_str = f"{min_version}-{max_version}|{cve_id}"
            idx[d["name"]].append(ver_range_str)
            store_pos_key = f"{store_pos}_{store_end_pos}|{cve_id}"
            pos_idx[d["name"]].append(store_pos_key)
            if d.get("vendor"):
                vendor_idx_key = f'{d.get("vendor")}|{d["name"]}'
                vendor_idx[vendor_idx_key].append((ver_range_str))
                pos_idx[vendor_idx_key].append(store_pos_key)
    return idx, vendor_idx, pos_idx


def get(db_file=config.vdb_bin_file, index_file=config.vdb_bin_index):
    """Get database instance

    :param db_file: DB file
    :param index_file: Index file
    :return: DB and index file
    """
    global index_data, vendor_index_data, pos_index_data
    index_data, vendor_index_data, pos_index_data = build_index(
        storage.stream_read(index_file)
    )
    return {"db_file": db_file, "index_file": index_file}


def store(db, datas, reindex=True):
    """Store data in the table

    :param table: Table instance
    :param datas: Data list to store
    :return: Stored packed documents
    """
    if datas is None:
        return None
    global index_data, vendor_index_data, pos_index_data
    docs = storage.store(datas, db_file=db["db_file"], index_file=db["index_file"])
    if reindex:
        # Re-read the index
        index_data, vendor_index_data, pos_index_data = build_index(
            storage.stream_read(db["index_file"])
        )
    return docs


def list_all(db):
    """Method to return all data

    :param db: db instance
    :return: List of data stored
    """
    return storage.stream_read(db["db_file"])


def list_all_occurrence(db):
    """Method to return all data

    :param db: db instance
    :return: List of data stored as occurrences
    """
    return convert_to_occurrence(storage.stream_read(db["db_file"]))


def index_count(index_file=config.vdb_bin_index):
    """
    Method to return the number of indexed items
    :param index_file: Index DB file
    :return: Count of the index
    """
    return len(storage.stream_read(index_file))


def _key_func(data, match_list):
    """Test function for package search

    :param version_attrib: Version value from the db
    :param value: Value to compare against
    :return: True if there is a match False otherwise
    """
    package = ""
    min_affected_version_including = ""
    max_affected_version_including = ""
    min_affected_version_excluding = None
    max_affected_version_excluding = None
    cpe_uri = ""
    if isinstance(data, dict):
        if not data.get("details"):
            return False
        cpe_uri = data["details"].get("cpe_uri")
        package = data["details"].get("package")
        min_affected_version_including = data["details"].get("mii", "0")
        min_affected_version_excluding = data["details"].get("mie", None)
        max_affected_version_including = data["details"].get("mai", "*")
        max_affected_version_excluding = data["details"].get("mae", None)
    else:
        cpe_uri = data.details.cpe_uri
        package = data.details.package
        min_affected_version_including = data.details.mii
        max_affected_version_including = data.details.mai
        min_affected_version_excluding = data.details.mie
        max_affected_version_excluding = data.details.mae
    if not cpe_uri:
        return False
    vendor, _, _, _ = parse_cpe(cpe_uri)
    for match in match_list:
        name_ver = match.split("|")
        # Search by name and version
        if len(name_ver) == 2:
            # Check if we have a hit
            if name_ver[0] == package and version_compare(
                name_ver[1],
                min_affected_version_including,
                max_affected_version_including,
                min_affected_version_excluding,
                max_affected_version_excluding,
            ):
                return True
        # Search by pos or vendor, name and version
        if len(name_ver) == 3:
            # Is name_ver[0] pos?
            if "_" in name_ver[0]:
                if name_ver[1] == package and version_compare(
                    name_ver[2],
                    min_affected_version_including,
                    max_affected_version_including,
                    min_affected_version_excluding,
                    max_affected_version_excluding,
                ):
                    return True
            else:
                # Check if we have a hit
                if (
                    name_ver[0] == vendor
                    and name_ver[1] == package
                    and version_compare(
                        name_ver[2],
                        min_affected_version_including,
                        max_affected_version_including,
                        min_affected_version_excluding,
                        max_affected_version_excluding,
                    )
                ):
                    return True
        # Search by pos, vendor, name and version
        if len(name_ver) == 4:
            # Check if we have a hit
            if (
                name_ver[1] == vendor
                and name_ver[2] == package
                and version_compare(
                    name_ver[3],
                    min_affected_version_including,
                    max_affected_version_including,
                    min_affected_version_excluding,
                    max_affected_version_excluding,
                )
            ):
                return True
    return False


def bulk_index_search(pkg_list):
    """"""
    ret_list = set()
    pos_cve_cache = {}
    for pkg in pkg_list:
        vendor = None
        name = None
        version = None
        # This key could be either a vendor|name or name
        vendor_idx_key = None
        if pkg.get("purl"):
            purl_obj = parse_purl(pkg.get("purl"))
            vendor = purl_obj.get("namespace")
            # Fallback to using type as the vendor
            if not vendor:
                vendor = purl_obj.get("type")
            name = purl_obj.get("name")
            version = purl_obj.get("version")
        else:
            vendor = pkg.get("vendor")
            name = pkg.get("name")
            version = pkg.get("version")
        vendor_idx_key = (
            f"{vendor.lower()}|{name.lower()}" if vendor else f"{name.lower()}"
        )
        version_list = None
        # If there is vendor information use it to perform strict search
        if vendor:
            version_list = vendor_index_data.get(vendor_idx_key, [])
            store_pos_cve = pos_index_data.get(vendor_idx_key)
        else:
            version_list = index_data.get(vendor_idx_key, [])
            store_pos_cve = pos_index_data.get(vendor_idx_key)
        if store_pos_cve:
            for sp in store_pos_cve:
                tmpA = sp.split("|")
                pos_cve_cache[tmpA[1]] = tmpA[0]
        for vers in version_list:
            cve_id = ""
            tmpA = vers.split("|")
            if len(tmpA) > 1:
                cve_id = tmpA[1]
            vrange = tmpA[0].split("-")
            minver = vrange[0]
            maxver = vrange[1]
            if not minver:
                minver = "0"
            store_pos = pos_cve_cache.get(cve_id)
            if version_compare(version, minver, maxver):
                ret_list.add(f"{store_pos}|{vendor_idx_key}|{version}")
    return list(ret_list)


def index_search(name, version):
    """Search the index for the given package name and version

    :param name: Name of the package
    :param version: Package version

    :return boolean True if the package should be found on the main database. False otherwise.
    """
    try:
        datas = bulk_index_search([{"name": name.lower(), "version": version}])
        return len(datas) > 0
    except IndexError:
        return False


def pkg_search(db, name, version):
    """Search for a given package and convert into Vulnerability Occurence

    :param db: db instance
    :param name: Name of the package
    :param version: Package version

    :return List of vulnerability occurrence or none
    """
    datas = storage.stream_bulk_search(
        [name.lower() + "|" + version], _key_func, db_file=db["db_file"]
    )
    return convert_to_occurrence(datas)


def vendor_pkg_search(db, vendor, name, version):
    """Search for a given package and convert into Vulnerability Occurence

    :param db: db instance
    :param vendor: Vendor name
    :param name: Name of the package
    :param version: Package version

    :return List of vulnerability occurrence or none
    """
    datas = storage.stream_bulk_search(
        [vendor.lower() + "|" + name.lower() + "|" + version],
        _key_func,
        db_file=db["db_file"],
    )
    return convert_to_occurrence(datas)


def pkg_bulk_search(db, pkg_key_list):
    """Bulk search for a given package and convert into Vulnerability Occurence

    :param db: db instance
    :param pkg_key_list: List of pos|package name|version keys

    :return List of vulnerability occurence or none
    """
    datas = storage.stream_bulk_search(pkg_key_list, _key_func, db_file=db["db_file"])
    return convert_to_occurrence(datas)
