import importlib
import re
from datetime import date, datetime
from enum import Enum

from semver import VersionInfo

from vdb.lib import CPE_REGEX, PackageIssue, Severity, VulnerabilityOccurrence

date_format_str = "%Y-%m-%dT%H:%M:%S"

# semver base format
BASEVERSION = re.compile(
    r"""[vV]?
        (?P<major>0|[1-9]\d*)
        (\.
        (?P<minor>0|[1-9]\d*)
        (\.
            (?P<patch>0|[1-9]\d*)
        )?
        (?:[-\.](?P<prerelease>
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


class ClassNotFoundError(Exception):
    """docstring for ClassNotFoundError"""

    def __init__(self, msg):
        super(ClassNotFoundError, self).__init__(msg)


def load(d):
    """Parses a python object from a JSON string. Every Object which should be loaded needs a constuctor that doesn't need any Arguments.
    Arguments: Dict object; the module which contains the class, the parsed object is instance of."""

    def _load(d):
        if isinstance(d, list):
            li = []
            for item in d:
                li.append(_load(item))
            return li
        elif isinstance(d, dict) and "type" in d:  # object
            t = d["type"]
            if t == "datetime":
                if hasattr(datetime, "fromisoformat"):
                    return datetime.fromisoformat(d["value"])
                else:
                    return datetime.strptime(d["value"], date_format_str)
            if t == "Severity":
                return Severity.from_str(d["value"])
            try:
                del d["type"]
                clazz = getattr(importlib.import_module("vdb.lib"), t)
                if hasattr(clazz, "from_dict"):
                    o = clazz.from_dict(d)
                else:
                    o = clazz(**d)
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
        elif isinstance(d, dict):  # dict
            rd = {}
            for key in d:
                rd[key] = _load(d[key])
            return rd
        else:
            return d

    return _load(d)


def dump(obj):
    """Dumps a python object to a JSON string. Argument: Python object"""

    def _dump(obj, path):
        if isinstance(obj, list):
            li = []
            i = 0
            for item in obj:
                li.append(_dump(item, path + "/[" + str(i) + "]"))
                i += 1
            return li
        elif isinstance(obj, Enum):  # Enum
            d = {}
            d["type"] = obj.__class__.__name__
            d["value"] = obj.value
            return d
        elif isinstance(obj, dict):  # dict
            rd = {}
            for key in obj:
                rd[key] = _dump(obj[key], path + "/" + key)
            return rd
        elif isinstance(obj, datetime):  # datetime
            d = {}
            d["type"] = obj.__class__.__name__
            if hasattr(obj, "isoformat"):
                d["value"] = obj.isoformat()
            else:
                d["value"] = obj.strftime(date_format_str)
            return d
        elif (
            isinstance(obj, str)
            or isinstance(obj, int)
            or isinstance(obj, float)
            or isinstance(obj, complex)
            or isinstance(obj, bool)
            or type(obj).__name__ == "NoneType"
        ):
            return obj
        else:
            d = {}
            d["type"] = obj.__class__.__name__
            for key in obj.__dict__:
                d[key] = _dump(obj.__dict__[key], path + "/" + key)
            return d

    return _dump(obj, "/")


def serialize_vuln_list(datas):
    """Serialize vulnerability data list to help with storage

    :param datas: Data list to store
    :return List of serialized data
    """
    data_list = []
    for data in datas:
        ddata = data
        details = None
        if type(data) != "dict":
            ddata = vars(data)
            details = data.details
        else:
            details = data["details"]
        for vuln_detail in details:
            data_to_insert = ddata.copy()
            data_to_insert["details"] = vuln_detail
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
    version_num = str(version_num).replace(".", "")
    if "-" in version_num:
        version_num = version_num.split("-")[0]
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
    version_num_parts = len(version_num.split("."))
    if version_num_parts < normal_len:
        for i in range(version_num_parts, normal_len):
            version_num = version_num + ".0"
    return version_num


def semver_compatible(compare_ver, min_version, max_version):
    """Method to check if all version numbers are semver compatible"""
    return (
        VersionInfo.isvalid(compare_ver)
        and VersionInfo.isvalid(min_version)
        and VersionInfo.isvalid(max_version)
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
    match = BASEVERSION.search(version)
    if not match:
        return (None, version)

    ver = {
        key: 0 if value is None else value for key, value in match.groupdict().items()
    }
    # Trim based on known prerelease strings
    if ver.get("prerelease"):
        pre_str = ver.get("prerelease", "").lower()
        for s in KNOWN_PRERELEASE_STR:
            if s in pre_str:
                ver["prerelease"] = None
                ver["build"] = None
                break

    ver = VersionInfo(**ver)
    rest = match.string[match.end() :]  # noqa:E203
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
            build=None,
        )
    if not number_part:
        rest = None
    return ver, rest


def version_compare(
    compare_ver,
    min_version,
    max_version,
    min_affected_version_excluding=None,
    max_affected_version_excluding=None,
):
    """Function to check if the given version is between min and max version

    >>> utils.version_compare("3.0.0", "2.0.0", "2.7.9.4")
    False

    >>> utils.version_compare("2.0.0", "2.0.0", "2.7.9.4")
    True

    >>> utils.version_compare("4.0.0", "2.0.0", "*")
    True
    """
    # Semver compatible and including versions provided
    is_min_exclude = False
    is_max_exclude = False
    if (not min_version or min_version == "*") and min_affected_version_excluding:
        min_version = min_affected_version_excluding
        is_min_exclude = True
    if (not max_version or max_version == "*") and max_affected_version_excluding:
        max_version = max_affected_version_excluding
        is_max_exclude = True
    if not min_version:
        min_version = "0"
    # If compare_ver is semver compatible and min_version is * then max_version should be semver compatible
    if (
        compare_ver
        and VersionInfo.isvalid(compare_ver)
        and (not min_version or min_version == "*")
        and not VersionInfo.isvalid(max_version)
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

        # We have an incompatible semver string. Try to convert to semver format
        compare_semver, comprest = convert_to_semver(compare_ver)
        min_semver, minrest = convert_to_semver(
            "0.0.0" if min_version == "*" else min_version
        )
        max_semver, maxrest = convert_to_semver(max_version)
        if (
            compare_semver
            and min_semver
            and max_semver
            and not comprest
            and not minrest
            and not maxrest
        ):
            min_value = compare_semver.compare(min_semver)
            max_value = compare_semver.compare(max_semver)
            # If we are confident about the versions post upgrade then return True
            min_check = min_value > 0 if is_min_exclude else min_value >= 0
            max_check = max_value < 0 if is_max_exclude else max_value <= 0
            return min_check and max_check

    compare_ver_build = None
    min_version_build = None
    max_version_build = None
    # Extract any build string such as alpha or beta
    if "-" in compare_ver and compare_ver != "-":
        tmpA = compare_ver.split("-")
        compare_ver = tmpA[0]
        compare_ver_build = tmpA[1]
    if "-" in min_version and min_version != "-":
        tmpA = min_version.split("-")
        min_version = tmpA[0]
        min_version_build = tmpA[1]
    if not max_version or max_version == "-":
        max_version = "0"
    if "-" in max_version and max_version != "-":
        tmpA = max_version.split("-")
        max_version = tmpA[0]
        max_version_build = tmpA[1]
    if max_version == "*":
        return True
    if not min_version or min_version == "*" or min_version == "-":
        min_version = "0"
    if compare_ver == "-" or compare_ver == "*":
        compare_ver = "0"
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
    # If all versions follow proper versioning then perform a simple numerical comparison
    if (
        len(compare_ver_parts) == len(min_version_parts)
        and len(compare_ver_parts) == len(max_version_parts)
        and len(str(compare_ver_num)) == len(str(min_version_num))
        and len(str(compare_ver_num)) == len(str(max_version_num))
    ):
        if compare_ver_num >= min_version_num and compare_ver_num <= max_version_num:
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
                else:
                    return True
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
    return True


def parse_cpe(cpe_uri):
    """
    Parse cpe uri to return the parts
    :param cpe_uri: CPE to parse
    :return: Individual parts
    """
    parts = CPE_REGEX.match(cpe_uri)
    return parts.group("vendor"), parts.group("package"), parts.group("version")


def get_default_cve_data(severity):
    """
    Return some default CVE metadata for the given severity
    :param severity: Severity
    :return: score, vectorString
    """
    vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = 9.0
    severity = severity.upper()
    attackComplexity = severity
    if severity == "LOW":
        score = 2.0
        attackComplexity = "HIGH"
        vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    elif severity in ["MODERATE", "MODERATE"]:
        score = 5.0
        severity = "MEDIUM"
        vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
    elif severity == "HIGH":
        score = 7.5
        attackComplexity = "LOW"
        vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    return score, severity, vectorString, attackComplexity


def convert_to_occurrence(datas):
    """Method to parse raw search result and convert to Vulnerability occurence

    :param datas: Search results from database
    :return List of vulnerability occurence
    """
    data_list = []
    id_list = []
    for d in datas:
        vobj = load(d)
        vdetails = vobj["details"]
        package_type = ""
        package = ""
        cpe_uri = ""
        if isinstance(vdetails, dict):
            package_type = vdetails["package_type"]
            package = vdetails["package"]
            cpe_uri = vdetails["cpe_uri"]
        else:
            package_type = vdetails.package_type
            package = vdetails.package
            cpe_uri = vdetails.cpe_uri
        unique_key = vobj["id"] + "|" + package
        # Filter duplicates for the same package with the same id
        if unique_key not in id_list:
            occ = VulnerabilityOccurrence(
                id=vobj["id"],
                problem_type=vobj["problem_type"],
                type=package_type,
                severity=vobj["severity"],
                cvss_score=vobj["score"],
                package_issue=PackageIssue(
                    affected_location=cpe_uri,
                    fixed_location=vdetails.fixed_location,
                    min_affected_version_including=vdetails.min_affected_version_including,
                    max_affected_version_including=vdetails.max_affected_version_including,
                    min_affected_version_excluding=vdetails.min_affected_version_excluding,
                    max_affected_version_excluding=vdetails.max_affected_version_excluding,
                ),
                short_description=vobj["description"],
                long_description=None,
                related_urls=vobj["related_urls"],
                effective_severity=vobj["severity"],
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
