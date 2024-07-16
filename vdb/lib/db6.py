from datetime import datetime, timedelta, timezone
import json
import os
import sys

import apsw

from vdb.lib import config

db_conn: apsw.Connection = None
index_conn: apsw.Connection = None
tables_created = False
DB_FILE_SEP = "///" if sys.platform == "win32" else "//"


def ensure_schemas(db_conn_obj: apsw.Connection, index_conn_obj: apsw.Connection):
    """Create the sqlite tables and indexes in case they don't exist"""
    db_conn_obj.execute(
        "CREATE TABLE if not exists cve_data(cve_id TEXT NOT NULL, type TEXT NOT NULL, namespace TEXT, name TEXT NOT NULL, source_data BLOB NOT NULL, override_data BLOB, source_data_hash TEXT NOT NULL, purl_prefix TEXT NOT NULL);")
    db_conn_obj.pragma("synchronous", "OFF")
    db_conn_obj.pragma("journal_mode", "MEMORY")
    db_conn_obj.pragma("temp_store", "MEMORY")
    index_conn_obj.execute(
        "CREATE TABLE if not exists cve_index(cve_id TEXT NOT NULL, type TEXT NOT NULL, namespace TEXT, name TEXT NOT NULL, vers TEXT NOT NULL, purl_prefix TEXT NOT NULL);")
    index_conn_obj.pragma("synchronous", "OFF")
    index_conn_obj.pragma("journal_mode", "MEMORY")
    index_conn_obj.pragma("temp_store", "MEMORY")


def get(db_file: str = config.VDB_BIN_FILE, index_file: str = config.VDB_BIN_INDEX, read_only=False) -> (
        apsw.Connection, apsw.Connection):
    """Gets the connection to the index and the data databases. Raises apsw.CantOpenError if the database is not available."""
    global db_conn, index_conn, tables_created
    if not db_file.startswith("file:") and db_file != ":memory:":
        db_file = f"file:{DB_FILE_SEP}{os.path.abspath(db_file)}"
    if not index_file.startswith("file:") and index_file != ":memory:":
        index_file = f"file:{DB_FILE_SEP}{os.path.abspath(index_file)}"
    rw_flags = apsw.SQLITE_OPEN_URI | apsw.SQLITE_OPEN_NOFOLLOW | apsw.SQLITE_OPEN_CREATE | apsw.SQLITE_OPEN_READWRITE
    ro_flags = apsw.SQLITE_OPEN_URI | apsw.SQLITE_OPEN_NOFOLLOW | apsw.SQLITE_OPEN_READONLY
    # To avoid apsw.CantOpenError, we support readonly mode only if the db exists
    flags = ro_flags if read_only and os.path.exists(db_file) and os.path.exists(index_file) else rw_flags
    if not db_conn:
        db_conn = apsw.Connection(db_file, flags=flags)
    if not index_conn:
        index_conn = apsw.Connection(index_file, flags=flags)
    if not tables_created:
        ensure_schemas(db_conn, index_conn)
        tables_created = True
    return db_conn, index_conn


def stats():
    cve_data_count = 0
    res = db_conn.execute("SELECT count(*) FROM cve_data").fetchone()
    if res:
        cve_data_count = res[0]
    cve_index_count = 0
    res = index_conn.execute("SELECT count(*) FROM cve_index").fetchone()
    if res:
        cve_index_count = res[0]
    return cve_data_count, cve_index_count


def clear_all():
    if db_conn:
        db_conn.execute("DELETE FROM cve_data;")
    if index_conn:
        index_conn.execute("DELETE FROM cve_index;")


def optimize_and_close_all():
    """
    Safely close the connections by creating indexes and vacuuming if needed.
    """
    if db_conn:
        db_conn.execute(
            "CREATE INDEX if not exists idx1 on cve_data(cve_id, purl_prefix);")
        db_conn.execute("VACUUM;")
        db_conn.close()
    if index_conn:
        index_conn.execute(
            "CREATE INDEX if not exists cidx1 on cve_index(cve_id);")
        index_conn.execute(
            "CREATE INDEX if not exists cidx2 on cve_index(type, namespace, name);")
        index_conn.execute(
            "CREATE INDEX if not exists cidx3 on cve_index(type, name);")
        index_conn.execute(
            "CREATE INDEX if not exists cidx4 on cve_index(namespace, name);")
        index_conn.execute(
            "CREATE INDEX if not exists cidx5 on cve_index(purl_prefix);")
        index_conn.execute("VACUUM;")
        index_conn.close()


def get_db_file_metadata():
    """
    Returns the metadata for the cached vdb files.
    """
    if not os.path.exists(config.VDB_METADATA_FILE):
        return None
    with open(config.VDB_METADATA_FILE, encoding="utf-8") as meta_file:
        return json.load(meta_file)


def needs_update(days=1, hours=0, minutes=0, seconds=0, default_status=False):
    """
    Determines if the db needs to be updated based on creation time
    """
    db_metadata = get_db_file_metadata()
    if not db_metadata or not db_metadata.get("created_utc"):
        return default_status
    current_time = datetime.now(tz=timezone.utc)
    created_time = datetime.fromisoformat(db_metadata["created_utc"])
    diff = current_time - created_time
    return diff > timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
