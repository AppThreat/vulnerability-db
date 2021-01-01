from vdb.lib import config as config
from vdb.lib import storage as storage
from vdb.lib.utils import convert_to_occurrence, parse_cpe, version_compare

index_data = None
vendor_index_data = None


def build_index(index_list):
    """This function builds two index. One with just name and version the other
    including vendor (aka group) string

    :param index_list:
    :return: Normal index and vendor index
    """
    idx = {}
    vendor_idx = {}
    for d in index_list:
        min_version = d.get(
            "min_affected_version_excluding", d.get("min_affected_version_including")
        )
        max_version = d.get(
            "max_affected_version_excluding", d.get("max_affected_version_including")
        )
        if not min_version:
            min_version = "0"
        if not max_version:
            max_version = "*"
        ver_range_str = str(min_version) + "-" + str(max_version)
        curr_list = idx.get(d["name"], [])
        curr_list.append(ver_range_str)
        idx[d["name"]] = curr_list
        if d.get("vendor"):
            vendor_idx_key = d.get("vendor") + "|" + d["name"]
            vendor_list = vendor_idx.get(vendor_idx_key, [])
            vendor_list.append((ver_range_str))
            vendor_idx[vendor_idx_key] = vendor_list
    return idx, vendor_idx


def get(db_file=config.vdb_bin_file, index_file=config.vdb_bin_index):
    """Get database instance

    :param db_file: DB file
    :param index_file: Index file
    :return: DB and index file
    """
    global index_data, vendor_index_data
    index_data, vendor_index_data = build_index(storage.stream_read(index_file))
    return {"db_file": db_file, "index_file": index_file}


def store(db, datas):
    """Store data in the table

    :param table: Table instance
    :param datas: Data list to store
    :return: Stored packed documents
    """
    if datas is None:
        return None
    global index_data, vendor_index_data
    docs = storage.store(datas, db_file=db["db_file"], index_file=db["index_file"])
    # Re-read the index
    index_data, vendor_index_data = build_index(storage.stream_read(db["index_file"]))
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
        cpe_uri = data["details"].get("cpe_uri")
        package = data["details"].get("package")
        min_affected_version_including = data["details"].get(
            "min_affected_version_including", "0"
        )
        min_affected_version_excluding = data["details"].get(
            "min_affected_version_excluding", None
        )
        max_affected_version_including = data["details"].get(
            "max_affected_version_including", "*"
        )
        max_affected_version_excluding = data["details"].get(
            "max_affected_version_excluding", None
        )
    else:
        cpe_uri = data.details.cpe_uri
        package = data.details.package
        min_affected_version_including = data.details.min_affected_version_including
        max_affected_version_including = data.details.max_affected_version_including
        min_affected_version_excluding = data.details.min_affected_version_excluding
        max_affected_version_excluding = data.details.max_affected_version_excluding
    vendor, _, _ = parse_cpe(cpe_uri)
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
        # Search by vendor, name and version
        if len(name_ver) == 3:
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
    return False


def bulk_index_search(pkg_list):
    """"""
    ret_list = set()
    for pkg in pkg_list:
        version_list = None
        vendor_idx_key = None
        # If there is vendor information use it to perform strict search
        if pkg.get("vendor"):
            vendor_idx_key = pkg.get("vendor").lower() + "|" + pkg["name"].lower()
            version_list = vendor_index_data.get(vendor_idx_key, [])
        else:
            version_list = index_data.get(pkg["name"].lower(), [])
        for vers in version_list:
            vrange = vers.split("-")
            vnum = pkg["version"]
            minver = vrange[0]
            maxver = vrange[1]
            if not minver:
                minver = "0"
            if version_compare(vnum, minver, maxver):
                if vendor_idx_key:
                    ret_list.add(vendor_idx_key + "|" + pkg["version"])
                else:
                    ret_list.add(pkg["name"].lower() + "|" + pkg["version"])
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
    :param pkg_key_list: List of package name|version keys

    :return List of vulnerability occurence or none
    """
    datas = storage.stream_bulk_search(pkg_key_list, _key_func, db_file=db["db_file"])
    return convert_to_occurrence(datas)
