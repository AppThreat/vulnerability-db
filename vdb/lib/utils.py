import importlib
from datetime import datetime
from enum import Enum
from vdb.lib import Severity, CPE_REGEX, VulnerabilityOccurrence, PackageIssue

date_format_str = "%Y-%m-%dT%H:%M:%S"


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
            except TypeError as te:
                print(te)
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


def version_compare(compare_ver, min_version, max_version):
    """Function to check if the given version is between min and max version

    >>> utils.version_compare("3.0.0", "2.0.0", "2.7.9.4")
    False

    >>> utils.version_compare("2.0.0", "2.0.0", "2.7.9.4")
    True

    >>> utils.version_compare("4.0.0", "2.0.0", "*")
    True
    """
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
    if "-" in max_version and max_version != "-":
        tmpA = max_version.split("-")
        max_version = tmpA[0]
        max_version_build = tmpA[1]

    if max_version == "*":
        return True
    if max_version == "-" or not max_version:
        max_version = "0"
    if not min_version or min_version == "*" or min_version == "-":
        min_version = "0"
    if compare_ver == "-" or compare_ver == "*":
        compare_ver = "0"
    # Simple case
    if not compare_ver_build and not min_version_build and not max_version_build:
        if compare_ver == min_version or compare_ver == max_version:
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
            if (
                compare_ver_build == min_version_build
                or compare_ver_build == max_version_build
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
        cpe_uri = ""
        if isinstance(vdetails, dict):
            package_type = vdetails["package_type"]
            cpe_uri = vdetails["cpe_uri"]
        else:
            package_type = vdetails.package_type
            cpe_uri = vdetails.cpe_uri
        unique_key = vobj["id"] + "|" + cpe_uri
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
                    fixed_location=None,
                    min_affected_version=vdetails.min_affected_version,
                    max_affected_version=vdetails.max_affected_version,
                ),
                short_description=vobj["description"],
                long_description=None,
                related_urls=vobj["related_urls"],
                effective_severity=vobj["severity"],
            )
            id_list.append(unique_key)
            data_list.append(occ)
    return data_list
