from typing import Any

import orjson

from vdb.lib import db6, utils
from vdb.lib.cve_model import CVE, CVE1


def _filter_hits(raw_hits: list, compare_ver: str) -> list:
    filtered_list = []
    for ahit in raw_hits:
        cve_id = ahit[0]
        vers = ahit[4]
        if utils.vers_compare(compare_ver, vers):
            filtered_list.append(
                {
                    "cve_id": cve_id,
                    "type": ahit[1],
                    "namespace": ahit[2],
                    "name": ahit[3],
                    "vers": vers,
                    "purl_prefix": ahit[-1]
                }
            )
    return filtered_list


def get_cve_data(
    db_conn, index_hits: list[dict, Any], search_str: str
) -> list[dict[str, str | CVE | None]]:
    """Get CVE data for the index results

    Args:
        db_conn: DB Connection or None to create a new one
        index_hits: Hits from one of the search methods
        search_str: Original search string used

    Returns:
        generator: generator for CVE data with original source data as a pydantic model
    """
    if not db_conn:
        db_conn, _ = db6.get(read_only=True)
    for ahit in index_hits:
        results = exec_query(
            db_conn,
            "SELECT DISTINCT cve_id, type, namespace, name, source_data_hash, json(source_data), json(override_data), purl_prefix FROM cve_data WHERE cve_id = ? AND purl_prefix = ? GROUP BY purl_prefix ORDER BY cve_id DESC;",
            (ahit["cve_id"], ahit["purl_prefix"]),
        )
        for res in results:
            yield {
                "cve_id": res[0],
                "type": res[1],
                "namespace": res[2],
                "name": res[3],
                "matching_vers": ahit["vers"],
                "matched_by": search_str,
                "source_data_hash": res[4],
                "source_data": (
                    CVE(
                        root=CVE1.model_validate(
                            orjson.loads(res[5]), strict=False
                        )
                    )
                    if res[5]
                    else None
                ),
                "override_data": (orjson.loads(res[6]) if res[6] else None),
                "purl_prefix": res[7]
            }


def search_by_cpe_like(cpe: str, with_data=False) -> list | None:
    """Search by CPE or colon-separate strings"""
    db_conn, index_conn = db6.get(read_only=True)
    if cpe.startswith("cpe:"):
        vendor, package, version, _ = utils.parse_cpe(cpe)
    elif cpe.count(":") == 2:
        vendor, package, version = cpe.split(":")
    else:
        return None
    raw_hits = exec_query(
        index_conn,
        "SELECT DISTINCT cve_id, type, namespace, name, vers, purl_prefix FROM cve_index where namespace = ? AND name = ?;",
        (vendor, package),
    )
    if not raw_hits:
        raw_hits = exec_query(
            index_conn,
            "SELECT DISTINCT cve_id, type, namespace, name, vers, purl_prefix FROM cve_index where type = ? AND name = ?;",
            (vendor, package),
        )
    filtered_list = _filter_hits(raw_hits, version)
    if with_data:
        return get_cve_data(db_conn, filtered_list, cpe)
    return filtered_list


def search_by_purl_like(purl: str, with_data=False) -> list | None:
    """Search by purl like string"""
    db_conn, index_conn = db6.get(read_only=True)
    purl_obj = utils.parse_purl(purl)
    if purl_obj:
        ptype = purl_obj.get("type")
        namespace = purl_obj.get("namespace")
        name = purl_obj.get("name")
        version = purl_obj.get("version", "*")
        purl_prefix = f"pkg:{ptype}/"
        if namespace:
            purl_prefix = f"{purl_prefix}{namespace}/"
        # Handle distro names for linux os purls by prefixing distro name to name
        if purl_obj["qualifiers"] and purl_obj["qualifiers"].get("distro_name"):
            distro_name = purl_obj["qualifiers"].get("distro_name")
            name = f"{distro_name}/{name}"
        purl_prefix = f"{purl_prefix}{name}"
        args = [purl_prefix, ptype]
        # We enforce a strict search for None
        if namespace is not None:
            args.append(namespace)
            extra_filter = " AND namespace = ?"
        else:
            extra_filter = " AND namespace IS NULL"
        extra_filter = f"{extra_filter} AND name = ?"
        args.append(name)
        raw_hits = exec_query(
            index_conn,
            f"SELECT DISTINCT cve_id, type, namespace, name, vers, purl_prefix FROM cve_index where purl_prefix = ? OR (type = ?{extra_filter});",
            args,
        )
        filtered_list = _filter_hits(raw_hits, version)
        if with_data:
            return get_cve_data(db_conn, filtered_list, purl)
        return filtered_list


def search_by_cve(cve_id: str, with_data=False) -> list | None:
    """Search by CVE"""
    db_conn, index_conn = db6.get(read_only=True)
    raw_hits = exec_query(
        index_conn,
        "SELECT DISTINCT cve_id, type, namespace, name, vers, purl_prefix FROM cve_index where cve_id = ?",
        (cve_id,),
    )
    filtered_list = _filter_hits(raw_hits, "*")
    if with_data:
        return get_cve_data(db_conn, filtered_list, cve_id)
    return filtered_list


def search_by_url(url: str, with_data=False) -> list | None:
    """Search by URL"""
    db_conn, index_conn = db6.get(read_only=True)
    purl_obj = utils.url_to_purl(url)
    if not purl_obj:
        return None
    name = purl_obj["name"]
    purl_str = (
        f"pkg:{purl_obj['type']}/{purl_obj['namespace']}/{name}"
        if purl_obj["namespace"]
        else f"pkg:{purl_obj['type']}/{name}"
    )
    if purl_obj["version"]:
        purl_str = f"{purl_str}@{purl_obj['version']}"
    return search_by_purl_like(purl_str, with_data)


def exec_query(conn, query: str, args: tuple[str, ...]) -> list:
    res = conn.execute(query, args)
    return res.fetchall()
