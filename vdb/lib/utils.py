import codecs
import importlib
import re
import string
from datetime import date, datetime
from enum import Enum
from hashlib import blake2b
from urllib.parse import parse_qs, urlparse

from cvss import CVSS3
from packageurl import PackageURL
from semver import VersionInfo

from vdb.lib import CPE_FULL_REGEX, PackageIssue, Severity, VulnerabilityOccurrence
from vdb.lib.config import (
    PLACEHOLDER_FIX_VERSION,
    PLACEHOLDER_EXCLUDE_VERSION,
    VENDOR_TO_VERS_SCHEME,
)

DATE_FORMAT_STR = "%Y-%m-%dT%H:%M:%S"

# semver base format
BASEVERSION = re.compile(
    r"""[vV]?
        (?P<major>0|[1-9]\d*)
        (\.
        (?P<minor>0|[1-9]\d*)
        (\.
            (?P<patch>0|[1-9]\d*[a-zA-Z]?)
        )?
        (?:[-.](?P<prerelease>
            (?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)
            (?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*
        ))?
        (?:-\+(?P<build>
            [0-9a-zA-Z-]+
            (?:\.[0-9a-zA-Z-]+)*
        ))?
        )?
    """,
    re.VERBOSE,
)

KNOWN_PRERELEASE_STR = ["final", "release", "alpha", "beta", "rc", "latest"]

DEBIAN_VALID_VERSION = re.compile(
    r"^((?P<epoch>\d+):)?"
    "(?P<upstream_version>[A-Za-z0-9.+:~-]+?)"
    "(-(?P<debian_revision>[A-Za-z0-9+.~]+))?$"
)


class ClassNotFoundError(Exception):
    """docstring for ClassNotFoundError"""

    def __init__(self, msg):
        super(ClassNotFoundError, self).__init__(msg)


def load(d):
    """Parses a python object from a JSON string. Every Object which should be loaded needs a constuctor that doesn't need any Arguments.
    Arguments: Dict object; the module which contains the class, the parsed object is instance of.
    """

    def _load(d1):
        if isinstance(d1, list):
            li = []
            for item in d1:
                li.append(_load(item))
            return li
        elif isinstance(d1, str) and ("\\n" in d1 or "\\t" in d1):
            return decompress_str(d1)
        elif isinstance(d1, dict) and "type" in d1:  # object
            t = d1["type"]
            if t == "datetime":
                if hasattr(datetime, "fromisoformat"):
                    return datetime.fromisoformat(d1["value"])
                else:
                    return datetime.strptime(d1["value"], DATE_FORMAT_STR)
            if t == "Severity":
                return Severity.from_str(d1["value"])
            try:
                del d1["type"]
                clazz = getattr(importlib.import_module("vdb.lib"), t)
                if hasattr(clazz, "from_dict"):
                    o = clazz.from_dict(d1)
                else:
                    o = clazz(**d1)
            except KeyError:
                raise ClassNotFoundError(
                    "Class '%s' not found in the given module!" % t
                )
            except TypeError:
                raise TypeError(
                    "Make sure there is an constuctor that doesn't take any arguments (class: %s)"
                    % t
                )
            return o
        elif isinstance(d1, dict):  # dict
            rd = {}
            for key in d1:
                rd[key] = _load(d1[key])
            return rd
        else:
            return d1

    return _load(d)


def dump(obj):
    """Dumps a python object to a JSON string. Argument: Python object"""

    def _dump(obj2, path):
        if isinstance(obj2, list):
            li = []
            i = 0
            for item in obj2:
                li.append(_dump(item, path + "/[" + str(i) + "]"))
                i += 1
            return li
        elif isinstance(obj2, Enum):  # Enum
            d = {"type": obj2.__class__.__name__, "value": obj2.value}
            return d
        elif isinstance(obj2, dict):  # dict
            rd = {}
            for key in obj2:
                rd[key] = _dump(obj2[key], path + "/" + key)
            return rd
        elif isinstance(obj2, datetime):  # datetime
            d = {"type": obj2.__class__.__name__}
            if hasattr(obj2, "isoformat"):
                d["value"] = obj2.isoformat()
            else:
                d["value"] = obj2.strftime(DATE_FORMAT_STR)
            return d
        elif (
            isinstance(obj2, str)
            or isinstance(obj2, bytes)
            or isinstance(obj2, int)
            or isinstance(obj2, float)
            or isinstance(obj2, complex)
            or isinstance(obj2, bool)
            or type(obj2).__name__ == "NoneType"
        ):
            return obj2
        else:
            d = {"type": obj2.__class__.__name__}
            for key in obj2.__dict__:
                d[key] = _dump(obj2.__dict__[key], path + "/" + key)
            return d

    return _dump(obj, "/")


def serialize_vuln_list(datas):
    """Serialize vulnerability data list to help with storage

    :param datas: Data list to store
    :return List of serialized data
    """
    data_list = []
    for datam in datas:
        match = None
        # Support for new syntax
        if isinstance(datam, list):
            data, match = datam
        else:
            data = datam
        ddata = data
        if not isinstance(data, dict):
            ddata = vars(data)
            details = data.details
        else:
            details = data["details"]
        for vuln_detail in details:
            data_to_insert = ddata.copy()
            data_to_insert["details"] = vuln_detail
            if match:
                data_list.append([dump(data_to_insert), match])
            else:
                data_list.append(dump(data_to_insert))
    return data_list


def version_len(version_str):
    """
    Method to return the length of a version string without dots and build
    information

    >>> version_len("1.0.0")
    3

    >>> version_len("2.1.800.5")
    6

    >>> version_len("1.2.0-beta1")
    3

    >>> version_len("1.3.0.beta1")
    3

    :param version_str: Version string
    :return: Length of the string without dots and build information
    """
    version_str = version_str.split("-")
    version_parts = [v for v in version_str[0].split(".") if str(v).isdigit()]
    return len("".join(version_parts))


def convert_to_num(version_str):
    """Convert the version string to a number

    >>> convert_to_num(None)
    0

    >>> convert_to_num(10)
    10

    >>> convert_to_num('1.0.0')
    100

    >>> convert_to_num('1.0.0-alpha')
    100
    """
    if not version_str:
        return 0
    if str(version_str).isdigit():
        return version_str
    version_str = version_str.replace(".", "")
    if "-" in version_str:
        version_str = version_str.split("-")[0]
    return int(version_str) if version_str.isdigit() else 0


def normalise_num(version_num, normal_len):
    """Normalise the length of the version number by adding 0 at the end

    >>> normalise_num(100, 3)
    100

    >>> normalise_num("1.0.0", 3)
    100

    >>> normalise_num("1.0.0-alpha", 3)
    100

    >>> normalise_num(100, 4)
    1000
    """
    version_num = str(version_num)
    version_num = re.sub(r"[^\d]+", "", version_num)
    if len(version_num) < normal_len:
        for i in range(len(version_num), normal_len):
            version_num = version_num + "0"
    return int(version_num) if version_num.isdigit() else 0


def normalise_version_str(version_num, normal_len):
    """Normalise the length of the version string by adding .0 at the end

    >>> normalise_version_str(1.0, 3)
    1.0.0

    >>> normalise_version_str(1.0.0, 4)
    1.0.0.0
    """
    version_num = str(version_num)
    version_num_parts = len(version_num.split("."))
    if version_num_parts < normal_len:
        for i in range(version_num_parts, normal_len):
            version_num = version_num + ".0"
    return version_num


def semver_compatible(compare_ver, min_version, max_version):
    """Method to check if all version numbers are semver compatible"""
    return (
        VersionInfo.is_valid(compare_ver)
        and VersionInfo.is_valid(min_version)
        and VersionInfo.is_valid(max_version)
    )


def convert_to_semver(version):
    """
    Convert an incomplete version string into a semver-compatible VersionInfo
    object

    * Tries to detect a "basic" version string (``major.minor.patch``).
    * If not enough components can be found, missing components are
        set to zero to obtain a valid semver version.

    :param str version: the version string to convert
    :return: a tuple with a :class:`VersionInfo` instance (or ``None``
        if it's not a version) and the rest of the string which doesn't
        belong to a basic version.
    :rtype: tuple(:class:`VersionInfo` | None, str)
    """
    if version and len(version) > 8 and check_hex(version):
        return None, None
    match = BASEVERSION.search(version)
    if not match:
        return None, version
    ver = {
        key: 0 if value is None else value for key, value in match.groupdict().items()
    }
    rest = match.string[match.end() :]  # noqa:E203
    # Trim patch
    if ver.get("patch") and len(ver.get("patch")) > 1:
        justnum = list(filter(str.isdigit, ver.get("patch")))
        if justnum:
            justnum = "".join(justnum)
            if justnum and justnum != ver.get("patch"):
                extrabits = ver.get("patch").replace(justnum, "")
                if len(extrabits) == 1:
                    ver["build"] = ord(extrabits)
                ver["patch"] = int(justnum)
    # Trim based on known prerelease strings
    if ver.get("prerelease"):
        try:
            prefloat = float(ver.get("prerelease", 0))
            ver["prerelease"] = int(prefloat)
        except Exception:
            pre_str = ver.get("prerelease", "").lower()
            # If the prerelease is a single alphabet then ignore it
            if len(pre_str) == 1:
                ver["prerelease"] = 0
                ver["build"] = ord(pre_str)
            else:
                for s in KNOWN_PRERELEASE_STR:
                    if s in pre_str:
                        ver["prerelease"] = 0
                        ver["build"] = 0
                        break
    if rest:
        maybe_build = rest.removeprefix("-rc").removeprefix("-r")
        if maybe_build.isdigit():
            ver["build"] = int(maybe_build)
    ver = VersionInfo(**ver)
    number_part = convert_to_num(rest)
    date_obj = None
    if "-" in version:
        try:
            date_obj = date.fromisoformat(version)
        except Exception:
            date_obj = None
    # Is this a date as used by go packages
    if date_obj and date_obj.year == ver.major and not ver.minor and not ver.patch:
        ver = VersionInfo(
            major=0,
            minor=0,
            patch=0,
            prerelease=int(f"{version.replace('-', '')[:8]}000000"),
            build=0,
        )
    if not number_part:
        rest = None
    return ver, rest


def check_hex(s):
    if not s:
        return False
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in s)


def check_epoch(s):
    if not s:
        return False
    m = DEBIAN_VALID_VERSION.search(s)
    if m and m.group("epoch"):
        return True
    if (
        ":" in s
        or "ubuntu" in s
        or "deb" in s
        or "mint" in s
        or "amzn" in s
        or "oracle" in s
    ):
        return True
    return False


def is_hash_mode(
    compare_ver,
    min_version,
    max_version,
    mie,
    mae,
):
    return (
        check_hex(compare_ver)
        or check_hex(min_version)
        or check_hex(max_version)
        or check_hex(mie)
        or check_hex(mae)
    )


def is_epoch_mode(
    compare_ver,
    min_version,
    max_version,
    mie,
    mae,
):
    return (
        check_epoch(compare_ver)
        or check_epoch(min_version)
        or check_epoch(max_version)
        or check_epoch(mie)
        or check_epoch(mae)
    )


def trim_epoch_colon(s):
    if "ubuntu" not in s:
        m = DEBIAN_VALID_VERSION.search(s)
        if m and m.group("upstream_version"):
            return m.group("upstream_version")
    if ":" in s:
        return s.split(":")[1].split("-")[0]
    return s


def trim_epoch(
    compare_ver,
    min_version,
    max_version,
    mie,
    mae,
):
    if check_epoch(compare_ver):
        compare_ver = trim_epoch_colon(compare_ver)
    if check_epoch(min_version):
        min_version = trim_epoch_colon(min_version)
    if check_epoch(max_version):
        max_version = trim_epoch_colon(max_version)
    if check_epoch(mie):
        mie = trim_epoch_colon(mie)
    if check_epoch(mae):
        mae = trim_epoch_colon(mae)
    return (
        compare_ver,
        min_version,
        max_version,
        mie,
        mae,
    )


def vers_compare(compare_ver: str | int | float, vers: str) -> bool:
    """Purl vers based version comparison"""
    min_version, max_version, min_excluding, max_excluding = None, None, None, None
    if vers == "*" or compare_ver is None:
        return True
    if vers.startswith("vers:"):
        vers_parts = vers.split("/")[-1].split("|")
        if len(vers_parts) == 1:
            single_version = vers_parts[0].strip().replace(" ", "")
            # Handle wildcard and the special placeholder fix version
            if single_version in (PLACEHOLDER_FIX_VERSION, "*"):
                return True
            # Handle unaffected case
            if (
                single_version.startswith("!=")
                and single_version.removeprefix("!=") == compare_ver
            ):
                return False
        else:
            for apart in vers_parts:
                apart = apart.strip().replace(" ", "")
                if apart.startswith(">="):
                    min_version = apart.removeprefix(">=")
                elif apart.startswith(">"):
                    min_excluding = apart.removeprefix(">")
                if apart.startswith("<="):
                    max_version = apart.removeprefix("<=")
                elif apart.startswith("<"):
                    max_excluding = apart.removeprefix("<")
    return version_compare(
        compare_ver, min_version, max_version, min_excluding, max_excluding
    )


def version_compare(
    compare_ver: str | int | float,
    min_version: str | int | float,
    max_version: str | int | float,
    mie: str | int | float | None = None,
    mae: str | int | float | None = None,
) -> bool:
    """Function to check if the given version is between min and max version

    >>> utils.version_compare("3.0.0", "2.0.0", "2.7.9.4")
    False

    >>> utils.version_compare("2.0.0", "2.0.0", "2.7.9.4")
    True

    >>> utils.version_compare("4.0.0", "2.0.0", "*")
    True
    """
    # Handle placeholder fix version
    if mae == PLACEHOLDER_FIX_VERSION and compare_ver:
        return True
    # Fix min versions that are erroneously sent as *
    if min_version and min_version == "*" and not mie and mae and "." in mae:
        min_version = 0
    hash_mode_detected = is_hash_mode(
        compare_ver,
        min_version,
        max_version,
        mie,
        mae,
    )
    # Debian OS packages could have epoch. Detect and extract the upstream version
    epoch_mode_detected = is_epoch_mode(
        compare_ver,
        min_version,
        max_version,
        mie,
        mae,
    )
    ubuntu_mode_detected = False
    if epoch_mode_detected:
        # Easy check
        if compare_ver and mae and compare_ver == mae:
            return False
        (
            tcompare_ver,
            tmin_version,
            tmax_version,
            tmie,
            tmae,
        ) = trim_epoch(
            compare_ver,
            min_version,
            max_version,
            mie,
            mae,
        )
        # 1.10-0ubuntu4 < 1.10-0ubuntu4.1
        if (
            tcompare_ver == tmax_version
            or tcompare_ver == tmae
            or (max_version and max_version.startswith(compare_ver))
            or (mae and mae.startswith(compare_ver))
        ):
            if (
                max_version
                and max_version.startswith(compare_ver)
                and max_version != compare_ver
            ):

                return True
            if mae and mae.startswith(compare_ver) and mae != compare_ver:
                return True
        # Sorry about this but ubuntu versioning scheme is a PITA
        if "ubuntu" in compare_ver or "build" in compare_ver or "deb" in compare_ver:
            # Trim any epoch
            if ":" in compare_ver:
                compare_ver = compare_ver.split(":")[-1]
            if max_version and ":" in max_version:
                max_version = max_version.split(":")[-1]
            if mae and ":" in mae:
                mae = mae.split(":")[-1]
            if "ubuntu" in compare_ver:
                tmpcv_arr = compare_ver.split("ubuntu")
            elif "deb" in compare_ver:
                tmpcv_arr = compare_ver.split("deb")
            else:
                tmpcv_arr = compare_ver.split("build")
            ubuntu_mode_detected = True
            tmpmv = None
            if max_version and (
                "ubuntu" in max_version or "-" in max_version or "deb" in max_version
            ):
                index_to_use = 0
                if max_version.startswith(tmpcv_arr[0]):
                    index_to_use = -1
                if "ubuntu" in max_version:
                    tmpmv = max_version.split("ubuntu")[index_to_use]
                elif "deb" in max_version:
                    tmpmv = max_version.split("deb")[index_to_use]
                compare_ver = tmpcv_arr[index_to_use]
                if tmpmv:
                    max_version = tmpmv
                if max_version and "-" in max_version:
                    max_version = max_version.split("-")[0]
            elif mae and ("ubuntu" in mae or "deb" in mae or "-" in mae):
                index_to_use = 0
                if mae.startswith(tmpcv_arr[0]):
                    index_to_use = -1
                for bstr in ("ubuntu", "deb", "-"):
                    if bstr in mae:
                        tmpmv_arr = mae.split(bstr)
                        # If the prefix is equal after splitting operate with suffix alone
                        if tmpmv_arr[0] == tmpcv_arr[0]:
                            index_to_use = -1
                        tmpmv = tmpmv_arr[index_to_use]
                        break
                compare_ver = tmpcv_arr[index_to_use]
                mae = tmpmv
                if mae and "-" in mae:
                    mae = mae.split("-")[0]
            if "-" in compare_ver:
                compare_ver = compare_ver.split("-")[0]
            # If after splitting the versions are equal return False
            if (max_version and compare_ver == max_version) or (
                mae and compare_ver == mae
            ):
                return False
            if mae:
                if VersionInfo.is_valid(compare_ver) and VersionInfo.is_valid(mae):
                    cmp_value = VersionInfo.parse(compare_ver).compare(mae)
                    return cmp_value < 0
                elif "." not in compare_ver and "." not in mae:
                    compare_ver = re.split(r"[+~]", compare_ver)[0]
                    mae = re.split(r"[+~]", mae)[0]
                    exnum = list(filter(str.isdigit, compare_ver))
                    if exnum:
                        compare_ver_restnum = int("".join(exnum))
                        exnum = list(filter(str.isdigit, mae))
                        if exnum:
                            mae_restnum = int("".join(exnum))
                            return compare_ver_restnum < mae_restnum
        if not ubuntu_mode_detected:
            compare_ver = tcompare_ver
            min_version = tmin_version
            max_version = tmax_version
            mie = tmie
            mae = tmae
    # Semver compatible and including versions provided
    is_min_exclude = False
    is_max_exclude = False
    if mie:
        min_version = mie
        is_min_exclude = True
    if mae:
        max_version = mae
        is_max_exclude = True
    if not min_version:
        min_version = "0"
    # If compare_ver is semver compatible and min_version is *
    # then max_version should be semver compatible
    if (
        compare_ver
        and VersionInfo.is_valid(compare_ver)
        and (not min_version or min_version == "*")
        and not VersionInfo.is_valid(max_version)
    ):
        return False
    # Perform semver match once we have all the required versions
    if compare_ver and min_version and max_version:
        if semver_compatible(compare_ver, min_version, max_version):
            min_value = VersionInfo.parse(compare_ver).compare(min_version)
            max_value = VersionInfo.parse(compare_ver).compare(max_version)
            min_check = min_value > 0 if is_min_exclude else min_value >= 0
            max_check = max_value < 0 if is_max_exclude else max_value <= 0
            return min_check and max_check
        # Are we dealing with dates?
        if compare_ver.startswith("20") and (
            min_version.startswith("20") or max_version.startswith("20")
        ):
            # Compare_ver has dots where as min and max do not.
            # So we convert all of them to dates
            if (
                "." not in min_version or "." not in max_version
            ) and "." in compare_ver:
                compare_ver = compare_ver.replace(".", "")
                min_version = min_version.replace(".", "")
                max_version = max_version.replace(".", "")
        # We have an incompatible semver string. Try to convert to semver format
        compare_semver, _ = convert_to_semver(compare_ver)
        min_semver, minrest = convert_to_semver(
            "0.0.0" if min_version == "*" else min_version
        )
        max_semver, maxrest = convert_to_semver(max_version)
        if compare_semver and min_semver and max_semver and not minrest and not maxrest:
            min_value = compare_semver.compare(min_semver)
            max_value = compare_semver.compare(max_semver)
            # If we are confident about the versions post upgrade then return True
            min_check = (
                min_value > 0
                if is_min_exclude and not ubuntu_mode_detected
                else min_value >= 0
            )
            max_check = (
                max_value < 0
                if is_max_exclude and not ubuntu_mode_detected
                else max_value <= 0
            )
            ret_check = min_check and max_check
            # openssl checks: 1.1.1n > 1.1.1g
            if (
                ret_check
                and max_semver
                and compare_semver.major == max_semver.major
                and compare_semver.minor == max_semver.minor
                and compare_semver.patch == max_semver.patch
                and compare_semver.prerelease == max_semver.prerelease
                and compare_semver.build != max_semver.build
            ):
                try:
                    ret_check = int(compare_semver.build) < int(max_semver.build)
                except Exception:
                    pass
            return ret_check
    compare_ver_build = None
    min_version_build = None
    max_version_build = None
    if compare_ver is None:
        compare_ver = ""
    # Extract any build string such as alpha or beta
    if "-" in compare_ver and compare_ver != "-":
        tmp_a = compare_ver.split("-")
        compare_ver = tmp_a[0]
        compare_ver_build = tmp_a[1]
    if "-" in min_version and min_version != "-":
        tmp_a = min_version.split("-")
        min_version = tmp_a[0]
        min_version_build = tmp_a[1]
    if not max_version or max_version == "-":
        max_version = "0"
    if "-" in max_version and max_version != "-":
        tmp_a = max_version.split("-")
        max_version = tmp_a[0]
        max_version_build = tmp_a[1]
    if not min_version or min_version == "*" or min_version == "-":
        min_version = "0"
    if compare_ver == "-" or compare_ver == "*":
        compare_ver = "0"
    if min_version == "0" and max_version == "*":
        return True
    # Simple case
    if not compare_ver_build and not min_version_build and not max_version_build:
        if (compare_ver == min_version and not is_min_exclude) or (
            compare_ver == max_version and not is_max_exclude
        ):
            return True
    compare_ver_parts = str(compare_ver).split(".")
    min_version_parts = str(min_version).split(".")
    max_version_parts = str(max_version).split(".")

    normal_ver_len = version_len(compare_ver)
    if version_len(min_version) > normal_ver_len:
        normal_ver_len = version_len(min_version)
    if version_len(max_version) > normal_ver_len:
        normal_ver_len = version_len(max_version)
    compare_ver_num = normalise_num(compare_ver, normal_ver_len)
    min_version_num = normalise_num(min_version, normal_ver_len)
    max_version_num = normalise_num(max_version, normal_ver_len)
    if (
        not max_version_num
        and compare_ver_num > min_version_num
        and not mie
        and not mae
        and not hash_mode_detected
    ):
        return True
    # If all versions follow proper versioning then perform a simple numerical comparison
    if (
        len(compare_ver_parts) == len(min_version_parts)
        and len(compare_ver_parts) == len(max_version_parts)
        and len(str(compare_ver_num)) == len(str(min_version_num))
        and len(str(compare_ver_num)) == len(str(max_version_num))
    ):
        if min_version_num <= compare_ver_num <= max_version_num:
            if (compare_ver_build == min_version_build and not is_min_exclude) or (
                compare_ver_build == max_version_build and not is_max_exclude
            ):
                return True
            if not compare_ver_build and (min_version_build or max_version_build):
                if (
                    compare_ver_num == min_version_num
                    and compare_ver_num == max_version_num
                ):
                    return False
                if max_version_build and compare_ver_num == max_version_num:
                    return False
            return True

    normal_len = len(compare_ver_parts)
    if len(min_version_parts) > normal_len:
        normal_len = len(min_version_parts)
    if len(max_version_parts) > normal_len:
        normal_len = len(max_version_parts)

    # Normalise the version numbers to be of same length
    compare_ver = normalise_version_str(compare_ver, normal_len)
    min_version = normalise_version_str(min_version, normal_len)
    max_version = normalise_version_str(max_version, normal_len)

    compare_ver_parts = str(compare_ver).split(".")
    min_version_parts = str(min_version).split(".")
    max_version_parts = str(max_version).split(".")
    for i in range(0, normal_len):
        if (
            not compare_ver_parts[i].isdigit()
            or not min_version_parts[i].isdigit()
            or not max_version_parts[i].isdigit()
        ):
            if (
                compare_ver_parts[i] == min_version_parts[i]
                and compare_ver_parts[i] == max_version_parts[i]
            ):
                continue
            else:
                return False
        elif int(compare_ver_parts[i]) >= int(min_version_parts[i]) and int(
            compare_ver_parts[i]
        ) <= int(max_version_parts[i]):
            continue
        elif int(compare_ver_parts[i]) < int(min_version_parts[i]) or int(
            compare_ver_parts[i]
        ) > int(max_version_parts[i]):
            if i == 0:
                return False
            if i == 1 and int(compare_ver_parts[i - 1]) <= int(
                max_version_parts[i - 1]
            ):
                return False
            if i >= 2 and int(compare_ver_parts[i - 1]) == int(
                max_version_parts[i - 1]
            ):
                return False
    # This will remove false positives where the comparison version is an excluded version
    if (is_min_exclude and compare_ver == min_version) or (
        is_max_exclude and compare_ver == max_version
    ):
        return False
    if hash_mode_detected:
        if compare_ver:
            if compare_ver == min_version:
                return True
            if compare_ver == max_version:
                return True
            if compare_ver == mie:
                return False
            if compare_ver == mae:
                return False
        return False
    return True


def parse_cpe(cpe_uri):
    """
    Parse cpe uri to return the parts
    :param cpe_uri: CPE to parse
    :return: Individual parts
    """
    parts = CPE_FULL_REGEX.match(cpe_uri)
    if parts:
        return (
            parts.group("vendor"),
            parts.group("package"),
            parts.group("version"),
            parts.group("cve_type"),
        )
    else:
        return "", None, None, None


def get_default_cve_data(severity):
    """
    Return some default CVE metadata for the given severity
    :param severity: Severity
    :return: score, severity, vectorString, attackComplexity
    """
    vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = 9.0
    severity = severity.upper()
    attack_complexity = severity
    if severity == "LOW":
        score = 2.0
        attack_complexity = "HIGH"
        vector_string = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    elif severity in ["MODERATE", "MODERATE", "MEDIUM"]:
        score = 5.0
        severity = "MEDIUM"
        vector_string = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"
    elif severity == "HIGH":
        score = 7.5
        attack_complexity = "LOW"
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    return score, severity, vector_string, attack_complexity


def get_cvss3_from_vector(vector: str) -> dict:
    """
    Return CVE metadata for the given vector
    :param vector: Vector
    :return: CVSS3 parsed and converted to json
    """
    c = CVSS3(vector)
    return c.as_json()


def convert_to_occurrence(datas):
    """Method to parse raw search result and convert to Vulnerability occurence

    :param datas: Search results from database
    :return List of vulnerability occurence
    """
    data_list = []
    id_list = []
    for dm in datas:
        match = None
        if isinstance(dm, list):
            d, match = dm
        else:
            d = dm
        vobj = load(d)
        vdetails = vobj["details"]
        if isinstance(vdetails, dict):
            package_type = vdetails["package_type"]
            cpe_uri = vdetails["cpe_uri"]
            fixed_location = vdetails["fixed_location"]
            mii = vdetails["mii"]
            mai = vdetails["mai"]
            mie = vdetails["mie"]
            mae = vdetails["mae"]
        else:
            package_type = vdetails.package_type
            cpe_uri = vdetails.cpe_uri
            fixed_location = vdetails.fixed_location
            mii = vdetails.mii
            mai = vdetails.mai
            mie = vdetails.mie
            mae = vdetails.mae
        unique_key = vobj["id"] + "|" + match if match else vobj["id"]
        # Filter duplicates for the same package with the same id
        if unique_key not in id_list:
            occ = VulnerabilityOccurrence(
                oid=vobj["id"],
                problem_type=vobj["problem_type"],
                otype=package_type,
                severity=vobj["severity"],
                cvss_score=vobj["score"],
                cvss_v3=vobj["cvss_v3"],
                package_issue=PackageIssue(
                    affected_location=cpe_uri,
                    fixed_location=fixed_location,
                    mii=mii,
                    mai=mai,
                    mie=mie,
                    mae=mae,
                ),
                short_description=vobj["description"],
                long_description=None,
                related_urls=vobj["related_urls"],
                effective_severity=vobj["severity"],
                source_update_time=vobj.get("source_update_time"),
                source_orig_time=vobj.get("source_orig_time"),
                matched_by=match,
            )
            id_list.append(unique_key)
            data_list.append(occ)
    return data_list


def fix_text(text):
    """
    Method to fix up bad text from feeds
    :param text: Text to cleanup
    :return: Fixed text
    """
    if text is None:
        text = ""
    text = re.sub(r"[]^\\-]", " ", text)
    return text


def convert_md_references(md_text):
    """Method to convert markdown list to references url format"""
    if not md_text:
        return []
    ref_list = []
    md_text = md_text.replace("\n", "").strip()
    for ref in md_text.split("- "):
        if not ref:
            continue
        parts = ref.split("](")
        if len(parts) == 2:
            ref_list.append(
                {"name": parts[0].replace("[", ""), "url": parts[1].replace(")", "")}
            )
    return ref_list


def parse_purl(purl_str: str) -> dict:
    """Method to parse a package url string safely"""
    purl_obj = None
    if purl_str and purl_str.startswith("pkg:"):
        try:
            purl_obj = PackageURL.from_string(purl_str).to_dict() if purl_str else None
            # For golang, move everything to name since there is no concept of namespace
            if (
                purl_obj
                and purl_obj.get("type") == "golang"
                and purl_obj.get("namespace")
            ):
                purl_obj["name"] = f'{purl_obj["namespace"]}/{purl_obj["name"]}'
                purl_obj["namespace"] = ""
        except ValueError:
            # Ignore errors
            pass
        if not purl_obj and purl_str:
            tmp_a = purl_str.split("@")[0]
            purl_obj = {}
            if tmp_a:
                tmp_b = tmp_a.split("/")
                if tmp_b:
                    if len(tmp_b) < 2:
                        purl_obj["name"] = tmp_b[-1].lower()
                        purl_obj["namespace"] = tmp_b[0].split(":")[-1]
                    if len(tmp_b) > 2:
                        namespace = tmp_b[-2]
                        if tmp_b[-2].startswith("pkg:"):
                            namespace = tmp_b[-2].split(":")[-1]
                        purl_obj["namespace"] = namespace
    return purl_obj


def convert_score_severity(score):
    """Convert numeric score to severity string"""
    if not score:
        return "LOW"
    try:
        score = float(score)
        if score < 4:
            return "LOW"
        elif score < 7:
            return "MEDIUM"
        elif score < 9:
            return "HIGH"
        else:
            return "CRITICAL"
    except ValueError:
        return "LOW"


def chunk_list(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def compress_str(s):
    """Compress string by replacing for newlines and tabs"""
    return s.strip().replace("\n", "\\n").replace("  ", "\\t")


def decompress_str(s):
    """Decompress string by decoding escape characters"""
    if isinstance(s, str):
        try:
            return codecs.escape_decode(bytes(s, "utf-8"))[0].decode("utf-8")
        except Exception:
            return s
    return s


def to_purl_vers(vendor: str, versions: list) -> str:
    vers_list = []
    scheme = VENDOR_TO_VERS_SCHEME.get(vendor, vendor)
    if vendor.startswith("git") or not vendor.isalpha():
        scheme = "generic"
    for aversion in versions:
        if isinstance(aversion, dict):
            version = aversion.get("version")
            less_than = aversion.get("lessThan")
            less_than_or_equal = aversion.get("lessThanOrEqual")
            status = aversion.get("status")
        else:
            version = aversion.version.model_dump(mode="python")
            less_than = (
                aversion.lessThan.model_dump(mode="python")
                if aversion.lessThan
                else None
            )
            less_than_or_equal = (
                aversion.lessThanOrEqual.model_dump(mode="python")
                if aversion.lessThanOrEqual
                else None
            )
            status = str(aversion.status.value)
        if status == "unaffected" and version:
            vers_list.append(f"!={version}")
        else:
            if version and version != "0" and version != "*":
                # Placeholder versions require special treatments
                if version in (PLACEHOLDER_FIX_VERSION, PLACEHOLDER_EXCLUDE_VERSION):
                    vers_list.append(version)
                    continue
                elif version == "0.0.0" and less_than_or_equal == "*":
                    vers_list.append("*")
                    continue
                elif version == less_than_or_equal:
                    vers_list.append(version)
                    continue
                else:
                    vers_list.append(f">={version}")
            if less_than and less_than != "*" and not less_than_or_equal:
                vers_list.append(f"<{less_than}")
            if not less_than and less_than_or_equal:
                if less_than_or_equal == "*":
                    vers_list.append("*")
                else:
                    vers_list.append(f"<={less_than_or_equal}")

    return f"vers:{scheme}/{'|'.join(vers_list)}" if vers_list else None


def calculate_hash(content: str, digest_size=16) -> str:
    """Function to calculate has using blake2b algorithm"""
    h = blake2b(digest_size=digest_size)
    h.update(content.encode())
    return h.hexdigest()


def url_to_purl(url: str) -> dict | None:
    """Convert a given http url to purl objecg"""
    url_obj = urlparse(url)
    git_repo_name = url_obj.hostname
    version = None
    if url_obj.path:
        paths = [
            p
            for p in url_obj.path.split("/")
            if p
            and p not in ("/", "pub", "scm", "cgi-bin", "cgit", "gitweb")
            and not p.endswith(".cgi")
        ]
        if paths:
            max_path = 2 if len(paths) >= 2 else 1
            git_repo_name = f"""{git_repo_name}/{'/'.join(paths[:max_path])}"""
        for part in ("/commit/", "/tag/", "/releases/", "/blob/"):
            if part in url_obj.path:
                version = url_obj.path.split(part)[-1].split("/")[0].split(";")[0]
                break
    if url_obj.query:
        query_obj = parse_qs(url_obj.query)
        # Eg: https://git.eyrie.org/?p=kerberos/remctl.git%3Ba=commit%3Bh=86c7e4
        if query_obj.get("p"):
            git_repo_name = f"""{git_repo_name.removesuffix("/")}/{query_obj.get("p")[0].split(";")[0].removeprefix("/")}"""
            if "a=commit" in url_obj.query and "h=" in url_obj.query:
                version = url_obj.query.split("h=")[-1].split(";")[0]
        for v in ("commit", "tag", "hash", "version", "id"):
            if query_obj.get(v):
                version = query_obj.get(v)[0].split(";")[0]
    git_repo_name = (
        git_repo_name.removesuffix("-").removesuffix("/commit").removesuffix(".git")
    )
    url_obj = urlparse(f"https://{git_repo_name}")
    # Fix for #112
    pkg_type = "generic"
    hostname = url_obj.hostname
    if url_obj.hostname in ("github.com", "gitlab.com"):
        pkg_type = url_obj.hostname.removesuffix(".com")
        git_repo_name = url_obj.path
        hostname = None
    # Filter repo names without a path
    # eg: github.com
    if not url_obj.path:
        return None
    purl_obj = parse_purl(
        f"pkg:{pkg_type}/{url_obj.hostname}/{url_obj.path}"
        if hostname
        else f"pkg:{pkg_type}/{url_obj.path}"
    )
    if not purl_obj or not purl_obj["namespace"] or not purl_obj["name"]:
        return None
    if not purl_obj["version"] and version:
        purl_obj["version"] = version
    return purl_obj
