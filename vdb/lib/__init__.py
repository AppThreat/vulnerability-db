import os
import re
import tempfile
from abc import ABCMeta, abstractmethod
from datetime import datetime
from enum import Enum

import orjson

# Known application package types
# See https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
# chainguard and wolfi has been added for suppression purposes since the data quality is poor
KNOWN_PKG_TYPES = [
    "alpm",
    "bitbucket",
    "bitnami",
    "cargo",
    "composer",
    "cocoapods",
    "conda",
    "cpan",
    "cran",
    "docker",
    "generic",
    "github",
    "gitlab",
    "huggingface",
    "mlflow",
    "qpkg",
    "oci",
    "maven",
    "npm",
    "nuget",
    "pypi",
    "gem",
    "rubygems",
    "golang",
    "clojars",
    "conan",
    "pub",
    "hackage",
    "android",
    "dwf",
    "gsd",
    "hex",
    "packagist",
    "uvi",
    "apk",
    "deb",
    "rpm",
    "linux",
    "swid",
    "oss-fuzz",
    "ebuild",
    "swift",
    "apache",
    "android",
    "atom",
    "bower",
    "brew",
    "buildroot",
    "carthage",
    "chef",
    "chocolatey",
    "coreos",
    "ctan",
    "crystal",
    "drupal",
    "dtype",
    "dub",
    "elm",
    "eclipse",
    "gitea",
    "gradle",
    "guix",
    "haxe",
    "helm",
    "julia",
    "lua",
    "melpa",
    "meteor",
    "nim",
    "nix",
    "opam",
    "openwrt",
    "osgi",
    "p2",
    "pear",
    "pecl",
    "perl6",
    "platformio",
    "puppet",
    "sourceforge",
    "sublime",
    "terraform",
    "vagrant",
    "vim",
    "wordpress",
    "yocto"
]

# Maps variations of string to package types
PKG_TYPES_MAP = {
    "composer": ["php", "laravel", "wordpress", "joomla"],
    "maven": ["jenkins", "java", "kotlin", "groovy", "clojars", "hackage"],
    "npm": ["javascript", "node.js", "nodejs", "npmjs"],
    "nuget": [".net_framework", "csharp", ".net_core", "asp.net"],
    "pypi": ["python"],
    "gem": ["ruby"],
    "rubygems": ["ruby", "gem"],
    "golang": ["go"],
    "cargo": ["rust", "crates.io", "crates"],
    "pub": ["dart"],
    "hex": ["elixir"],
    "github": ["actions"],
    "apk": ["alpine"],
    "deb": ["ubuntu", "debian", "mint", "popos"],
    "rpm": [
        "redhat",
        "centos",
        "alma",
        "amazon",
        "rocky",
        "suse",
        "opensuse",
        "fedora",
        "fedoraproject"
    ],
    "alpm": ["arch", "archlinux"],
    "ebuild": ["gentoo", "portage"]
}

# CPE Regex
CPE_REGEX = re.compile(
    "cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+)?"
)

# CPE Full Regex including unused parameters
CPE_FULL_REGEX = re.compile(
    "cpe:?:[^:]+:(?P<cve_type>[^:]+):(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+):(?P<update>[^:]+):(?P<edition>[^:]+):(?P<lang>[^:]+):(?P<sw_edition>[^:]+):(?P<target_sw>[^:]+):(?P<target_hw>[^:]+):(?P<other>[^:]+)"
)


class VulnerabilitySource(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def download_all(cls):
        pass

    @classmethod
    @abstractmethod
    def download_recent(cls):
        pass

    @classmethod
    @abstractmethod
    def bulk_search(cls, app_info, pkg_list):
        pass

    @classmethod
    @abstractmethod
    def convert(cls, data):
        pass

    @classmethod
    @abstractmethod
    def convert5(cls, data):
        pass

    @classmethod
    @abstractmethod
    def store(cls, data):
        pass

    @classmethod
    @abstractmethod
    def refresh(cls):
        pass


class Severity(str, Enum):
    UNSPECIFIED: str = "UNSPECIFIED"
    LOW: str = "LOW"
    MEDIUM: str = "MEDIUM"
    HIGH: str = "HIGH"
    CRITICAL: str = "CRITICAL"

    @staticmethod
    def from_str(sevstr):
        if isinstance(sevstr, dict):
            sevstr = sevstr["value"]
        if not sevstr:
            return Severity.UNSPECIFIED
        for k, v in Severity.__members__.items():
            if k == sevstr.upper():
                return v
        return Severity.UNSPECIFIED

    def __str__(self):
        return self.value


def convert_time(time_str: str) -> datetime | None:
    """Converts a variety of datetime formats to datetime object

    :param time_str: String time to convert
    :return: datetime object
    """
    if time_str is None or time_str == "":
        return None
    dt = None
    try:
        dt = datetime.fromisoformat(time_str)
    except ValueError:
        date_formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%Mz",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ]
        for fmt in date_formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                break
            except ValueError:
                continue
    except TypeError:
        if isinstance(time_str, dict):
            time_str = time_str["value"]
            return convert_time(time_str)
    return dt or time_str


class CvssV3:
    """CVSS v3 representation"""

    base_score: float
    exploitability_score: float
    impact_score: float
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    vector_string: str

    def __init__(
            self,
            base_score,
            exploitability_score,
            impact_score,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            vector_string=None,
    ):
        self.base_score = base_score
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score
        self.attack_vector = attack_vector
        self.attack_complexity = attack_complexity
        self.privileges_required = privileges_required
        self.user_interaction = user_interaction
        self.scope = scope
        self.confidentiality_impact = confidentiality_impact
        self.integrity_impact = integrity_impact
        self.availability_impact = availability_impact
        self.vector_string = vector_string

    def to_dict(self):
        return {
            "base_score": self.base_score,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "vector_string": self.vector_string,
        }

    def __repr__(self):
        return orjson.dumps(self.to_dict()).decode("utf-8", "ignore")


class PackageIssue:
    """Package issue class"""

    def __init__(
            self,
            affected_location,
            fixed_location,
            mii=None,
            mai=None,
            mie=None,
            mae=None,
    ):
        self.affected_location = VulnerabilityLocation.from_values(
            affected_location,
            mii,
            mai,
            mie,
            mae,
        )
        # If there is no fixed_location but there is max excluded version then consider that as the fix
        if not fixed_location and mae:
            self.fixed_location = mae
        else:
            if fixed_location and fixed_location.startswith("cpe"):
                # Extract the fixed version from fixed_location cpe uri
                fixed_parts = (
                    CPE_REGEX.match(fixed_location) if fixed_location else None
                )
                if fixed_parts:
                    self.fixed_location = fixed_parts.group("version")
                else:
                    self.fixed_location = ""
            else:
                self.fixed_location = fixed_location

    @staticmethod
    def from_dict(package_issue):
        return PackageIssue(
            package_issue.get("affected_location"), package_issue.get("fixed_location")
        )

    def to_dict(self) -> dict:
        return {
            "affected_location": self.affected_location.to_dict(),
            "fixed_location": self.fixed_location,
        }

    def __str__(self):
        return orjson.dumps(
            {
                "affected_location": str(self.affected_location),
                "fixed_location": self.fixed_location,
            },
            option=orjson.OPT_NAIVE_UTC,
        ).decode("utf-8", "ignore")


class VulnerabilityDetail:
    """Vulnerability detail class"""

    def __init__(
            self,
            cpe_uri: str,
            package: str,
            min_affected_version_including: str | None,
            max_affected_version_including: str | None,
            min_affected_version_excluding: str | None,
            max_affected_version_excluding: str | None,
            severity: str,
            description: str | None,
            fixed_location: str,
            package_type: str,
            is_obsolete: str,
            source_update_time: str,
    ):
        parts = CPE_REGEX.match(cpe_uri)
        self.cpe_uri = cpe_uri
        # Occasionally, NVD CPE value could be invalid. We need to guard against this
        if parts:
            self.package = package if package else parts.group("package")
            self.mii = (
                min_affected_version_including
                if min_affected_version_including
                else parts.group("version")
            )
            self.mai = (
                max_affected_version_including
                if max_affected_version_including
                else parts.group("version")
            )
        else:
            # Use split to extract the package name in case of bad CPE value
            package_workaround = ""
            if cpe_uri:
                cpe_parts = cpe_uri.split(":")
                if len(cpe_parts) > 4:
                    package_workaround = cpe_parts[4]
            self.package = package if package else package_workaround
            self.mii = (
                min_affected_version_including
                if min_affected_version_including
                else "*"
            )
            self.mai = (
                max_affected_version_including
                if max_affected_version_including
                else "*"
            )
        self.mie = (
            min_affected_version_excluding if min_affected_version_excluding else None
        )
        self.mae = (
            max_affected_version_excluding if max_affected_version_excluding else None
        )
        self.severity = Severity.from_str(severity)
        self.description = description
        self.fixed_location = fixed_location
        self.package_type = VulnerabilityDetail.get_type(cpe_uri, package_type)
        self.is_obsolete = is_obsolete
        self.source_update_time: datetime = convert_time(source_update_time)

    @staticmethod
    def get_type(cpe_uri, package_type):
        if package_type and package_type in KNOWN_PKG_TYPES:
            return package_type
        parts = CPE_REGEX.match(cpe_uri)
        # cpe:2.3:a:netaddr_project:netaddr:*:*:*:*:*:ruby:*:*
        all_parts = CPE_FULL_REGEX.match(cpe_uri)
        if all_parts:
            cve_type = all_parts.group("cve_type")
            if cve_type != "a":
                return cve_type
        if parts:
            ptype = parts.group("vendor")
            if ptype in KNOWN_PKG_TYPES:
                return ptype
            if all_parts and (
                    all_parts.group("target_sw") and all_parts.group("target_sw") != "*"
                    or (
                        all_parts.group("sw_edition")
                        and all_parts.group("sw_edition") != "*"
                    )
            ):
                for vk, vv in PKG_TYPES_MAP.items():
                    target_sw = all_parts.group("target_sw")
                    sw_edition = all_parts.group("sw_edition")
                    if vk in (target_sw, sw_edition):
                        return vk
                    if target_sw in vv or sw_edition in vv:
                        return vk
                return ptype
            # Unknown type. Just pass-through for now
            return ptype
        return None

    @staticmethod
    def from_dict(detail):
        return VulnerabilityDetail(
            detail.get("cpe_uri"),
            detail.get("package"),
            detail.get("mii"),
            detail.get("mai"),
            detail.get("mie"),
            detail.get("mae"),
            detail.get("severity"),
            detail.get("description"),
            detail.get("fixed_location"),
            detail.get("package_type"),
            detail.get("is_obsolete"),
            detail.get("source_update_time"),
        )

    def to_dict(self):
        return {
            "cpe_uri": self.cpe_uri,
            "package": self.package,
            "mii": self.mii,
            "mai": self.mai,
            "mie": self.mie,
            "mae": self.mae,
            "severity": self.severity.value,
            "description": self.description,
            "fixed_location": self.fixed_location,
            "package_type": self.package_type,
            "is_obsolete": self.is_obsolete,
            "source_update_time": self.source_update_time.strftime("%Y-%m-%dT%H:%M:%S")
            if isinstance(self.source_update_time, datetime)
            else self.source_update_time,
        }

    def __repr__(self):
        return orjson.dumps(self.to_dict()).decode("utf-8", "ignore")


class Vulnerability:
    """Vulnerability"""

    cvss_v3: CvssV3

    def __init__(
            self,
            vid: str,
            assigner: str,
            problem_type: str,
            score: float,
            severity: str,
            description: str,
            related_urls: list[str],
            details: list[VulnerabilityDetail],
            cvss_v3: CvssV3,
            source_update_time: str,
            source_orig_time: str,
    ):
        self.id = vid
        self.assigner = assigner
        self.problem_type = problem_type
        self.score = score
        self.severity = Severity.from_str(severity)
        self.description = description
        self.related_urls = related_urls
        self.details = details
        self.cvss_v3 = cvss_v3
        self.source_update_time: datetime = convert_time(source_update_time)
        self.source_orig_time: datetime = convert_time(source_orig_time)

    def __repr__(self):
        return orjson.dumps(
            {
                "id": self.id,
                "assigner": self.assigner,
                "problem_type": self.problem_type,
                "score": self.score,
                "severity": self.severity.value,
                "description": self.description,
                "related_urls": self.related_urls,
                "details": str(self.details),
                "cvss_v3": str(self.cvss_v3),
                "source_update_time": self.source_update_time.strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
                "source_orig_time": self.source_orig_time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            option=orjson.OPT_NAIVE_UTC,
        ).decode("utf-8", "ignore")


class VulnerabilityLocation:
    cpe_uri: str
    vendor: str
    package: str
    version: str

    def __init__(self, cpe_uri, vendor, package, version):
        self.cpe_uri = cpe_uri
        self.vendor = vendor
        self.package = package
        self.version = version

    @staticmethod
    def from_values(
            cpe_uri,
            mii=None,
            mai=None,
            mie=None,
            mae=None,
    ):
        parts = None
        version = "*"
        if not cpe_uri and not mii and not mai and not mie and not mae:
            return None
        if cpe_uri:
            parts = CPE_REGEX.match(cpe_uri)
            version = mai if mai else parts.group(3)
        version_left = ""
        version_right = ""
        if mie:
            version_left = ">" + mie
        if mii and mii != "*":
            version_left = ">=" + mii
        if mae:
            version_right = "<" + mae
        if mai and mai != "*":
            version_right = "<=" + mai
        if version_left and not version_right:
            version = version_left
            # Convert >0.0.0 to *
            if version == ">0.0.0":
                version = "*"
        elif not version_left and version_right:
            version = version_right
        elif version_left and version_right:
            if mii == mai:
                version = mai
            else:
                version = f"{version_left}-{version_right}"
        if parts:
            return VulnerabilityLocation(
                cpe_uri, parts.group("vendor"), parts.group("package"), version
            )
        return None

    def __str__(self):
        return orjson.dumps(
            {
                "cpe_uri": str(self.cpe_uri),
                "package": str(self.package),
                "version": str(self.version),
                "vendor": str(self.vendor),
            },
            option=orjson.OPT_NAIVE_UTC,
        ).decode("utf-8", "ignore")

    def to_dict(self):
        return {
            "cpe_uri": str(self.cpe_uri),
            "package": str(self.package),
            "version": str(self.version),
            "vendor": str(self.vendor),
        }


class VulnerabilityOccurrence:
    """Class to represent an occurrence of a vulnerability"""

    id: str
    problem_type: str
    type: str
    severity: Severity
    cvss_score: str
    cvss_v3: CvssV3
    package_issue: PackageIssue
    short_description: str
    long_description: str
    related_urls: list
    effective_severity: Severity
    source_update_time: datetime
    source_orig_time: datetime
    matched_by: str

    def __init__(
            self,
            oid,
            problem_type,
            otype,
            severity,
            cvss_score,
            cvss_v3,
            package_issue,
            short_description,
            long_description,
            related_urls,
            effective_severity,
            source_update_time,
            source_orig_time,
            matched_by,
    ):
        self.id = oid
        self.problem_type = problem_type
        self.type = otype
        self.severity = severity
        self.cvss_score = cvss_score
        self.cvss_v3 = cvss_v3 if cvss_v3 else None
        self.package_issue = package_issue
        self.short_description = short_description
        self.long_description = long_description
        self.related_urls = related_urls
        self.effective_severity = effective_severity
        self.source_update_time = source_update_time
        self.source_orig_time = source_orig_time
        self.matched_by = matched_by

    def to_dict(self):
        """Convert the object to dict"""
        if isinstance(self.source_update_time, datetime):
            source_update_time = self.source_update_time.strftime("%Y-%m-%dT%H:%M:%S")
        else:
            new_time = self.source_update_time
            source_update_time = (
                new_time.strftime("%Y-%m-%dT%H:%M:%S")
                if (isinstance(new_time, datetime))
                else None
            )
        if isinstance(self.source_orig_time, datetime):
            source_orig_time = self.source_orig_time.strftime("%Y-%m-%dT%H:%M:%S")
        else:
            new_time = self.source_orig_time
            source_orig_time = (
                new_time.strftime("%Y-%m-%dT%H:%M:%S")
                if (isinstance(new_time, datetime))
                else None
            )
        return {
            "id": self.id,
            "problem_type": self.problem_type
            if isinstance(self.problem_type, str)
            else ",".join(self.problem_type),
            "type": self.type,
            "severity": str(self.severity),
            "cvss_score": str(self.cvss_score),
            "cvss_v3": self.cvss_v3.to_dict() if self.cvss_v3 else {},
            "package_issue": self.package_issue.to_dict() if self.package_issue else {},
            "short_description": self.short_description,
            "long_description": self.long_description,
            "related_urls": self.related_urls,
            "effective_severity": str(self.effective_severity),
            "source_update_time": source_update_time,
            "source_orig_time": source_orig_time,
            "matched_by": self.matched_by,
        }


class CustomNamedTemporaryFile:
    def __init__(self, mode="wb", delete=True):
        self._mode = mode
        self._delete = delete
        self._temp_file = None

    def __enter__(self):
        # Generate a random temporary file name
        file_name = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
        # Ensure the file is created
        open(file_name, "x").close()
        # Open the file in the given mode
        self._temp_file = open(file_name, self._mode)
        return self._temp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._temp_file:
            self._temp_file.close()
            if self._delete:
                os.remove(self._temp_file.name)
