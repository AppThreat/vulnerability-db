import os.path

import msgpack

from vdb.lib import config
from vdb.lib.utils import chunk_list, parse_cpe, serialize_vuln_list

batch_write_size = config.batch_write_size

max_buffer_size = config.max_buffer_size


def store(datas, db_file=config.vdb_bin_file, index_file=config.vdb_bin_index):
    """Store data in the table

    :param datas: Data list to store
    :param db_file: DB file to use
    """
    data_list = serialize_vuln_list(datas)
    packed_obj = None
    for batch in chunk_list(data_list, batch_write_size):
        index_list = []
        for data in batch:
            if data["details"]["cpe_uri"]:
                vendor, _, _, _ = parse_cpe(data["details"]["cpe_uri"])
                if vendor:
                    index_list.append(
                        {
                            "id": data.get("id"),
                            "vendor": vendor.lower(),
                            "name": data["details"]["package"].lower(),
                            "mii": data["details"].get("mii"),
                            "mai": data["details"].get("mai"),
                            "mie": data["details"].get("mie"),
                            "mae": data["details"].get("mae"),
                        }
                    )
        packed_obj = msgpack.packb(batch, use_bin_type=True)
        with open(db_file, mode="ab") as fp:
            store_pos = fp.tell()
            fp.write(packed_obj)
            store_end_pos = fp.tell()
            index_obj = msgpack.packb(
                [
                    {
                        "store_pos": store_pos,
                        "store_end_pos": store_end_pos,
                        "index_list": index_list,
                    }
                ],
                use_bin_type=True,
            )
            with open(index_file, mode="ab") as fp:
                fp.write(index_obj)
    return packed_obj


def stream_read(db_file=config.vdb_bin_file):
    """"""
    data_list = []
    if not os.path.isfile(db_file):
        return data_list
    with open(db_file, mode="rb") as fp:
        unpacker = msgpack.Unpacker(
            fp,
            use_list=1,
            strict_map_key=False,
            raw=False,
            max_buffer_size=max_buffer_size,
        )
        for unpacked in unpacker:
            if unpacked:
                data_list += unpacked
    return data_list


def stream_bulk_search(match_list, key_func, db_file=config.vdb_bin_file):
    """"""
    res = []
    store_end_pos = None
    with open(db_file, mode="rb") as fp:
        for amatch in match_list:
            tmpA = amatch.split("|")
            if len(tmpA) >= 3:
                tmpB = tmpA[0].split("_")
                store_pos = tmpB[0]
                store_end_pos = None
                if len(tmpB) > 1:
                    store_end_pos = tmpB[1]
                    if store_end_pos.isdigit():
                        store_end_pos = int(store_end_pos)
                if store_pos and store_pos.isdigit():
                    fp.seek(int(store_pos))
            unpacker = msgpack.Unpacker(
                fp,
                use_list=1,
                strict_map_key=False,
                raw=False,
                max_buffer_size=max_buffer_size,
            )
            for unpacked in unpacker:
                if isinstance(unpacked, list):
                    for data in unpacked:
                        if isinstance(data, dict) and key_func(data, [amatch]):
                            res.append([data, amatch])
                # Break if we are scanning past the storage size
                if store_end_pos and fp.tell() > store_end_pos:
                    break
    return res
