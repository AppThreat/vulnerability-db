import json
import re
from abc import ABCMeta, abstractmethod
from datetime import datetime
from enum import Enum

# Known application package types
KNOWN_PKG_TYPES = [
    "composer",
    "maven",
    "npm",
    "nuget",
    "pypi",
    "rubygems",
    "golang",
    "crates",
]

# Maps variations of string to package types
PKG_TYPES_MAP = {
    "composer": ["php", "laravel", "wordpress", "joomla"],
    "maven": ["jenkins", "java", "kotlin", "groovy"],
    "npm": ["javascript", "node.js", "nodejs"],
    "nuget": [".net_framework", "csharp", ".net_core"],
    "pypi": ["python"],
    "rubygems": ["ruby"],
    "golang": ["go"],
    "crates": ["rust"],
}

# CPE Regex
CPE_REGEX = re.compile(
    "cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+)?"
)

# CPE Full Regex including unused parameters
CPE_FULL_REGEX = re.compile(
    "cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+):(?P<update>[^:]+):(?P<edition>[^:]+):(?P<lang>[^:]+):(?P<sw_edition>[^:]+):(?P<target_sw>[^:]+):(?P<target_hw>[^:]+):(?P<other>[^:]+)"
)


class VulnerabilitySource(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def download_all(cls, local_store=True):
        pass

    @classmethod
    @abstractmethod
    def download_recent(cls, local_store=True):
        pass

    @classmethod
    @abstractmethod
    def bulk_search(cls):
        pass

    @classmethod
    @abstractmethod
    def convert(cls, data):
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


def convert_time(time_str):
    """Convert iso string to date time object

    :param time_str: String time to convert
    """
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%Mz")
        return dt
    except Exception:
        return time_str


class Vulnerability(object):
    """Vulnerability"""

    def __init__(
        self,
        vid,
        problem_type,
        score,
        severity,
        description,
        related_urls,
        details,
        cvss_v3,
        source_update_time,
    ):
        self.id = vid
        self.problem_type = problem_type
        self.score = score
        self.severity = Severity.from_str(severity)
        self.description = description
        self.related_urls = related_urls
        self.details = details
        self.cvss_v3 = cvss_v3
        self.source_update_time: datetime = convert_time(source_update_time)

    def __repr__(self):
        return json.dumps(
            {
                "id": self.id,
                "problem_type": self.problem_type,
                "score": self.score,
                "severity": self.severity.value,
                "description": self.description,
                "related_urls": self.related_urls,
                "details": str(self.details),
                "cvss_v3": str(self.cvss_v3),
                "source_update_time": self.source_update_time.isoformat()
                if isinstance(self.source_update_time, datetime)
                else self.source_update_time,
            }
        )


class VulnerabilityDetail(object):
    """Vulnerability detail class"""

    def __init__(
        self,
        cpe_uri,
        package,
        min_affected_version_including,
        max_affected_version_including,
        min_affected_version_excluding,
        max_affected_version_excluding,
        severity,
        description,
        fixed_location,
        package_type,
        is_obsolete,
        source_update_time,
    ):
        parts = CPE_REGEX.match(cpe_uri)
        self.cpe_uri = cpe_uri
        # Occasionally, NVD CPE value could be invalid. We need to guard against this
        if parts:
            self.package = package if package else parts.group("package")
            self.min_affected_version_including = (
                min_affected_version_including
                if min_affected_version_including
                else parts.group("version")
            )
            self.max_affected_version_including = (
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
            self.min_affected_version_including = (
                min_affected_version_including
                if min_affected_version_including
                else "*"
            )
            self.max_affected_version_including = (
                max_affected_version_including
                if max_affected_version_including
                else "*"
            )
        self.min_affected_version_excluding = (
            min_affected_version_excluding if min_affected_version_excluding else None
        )
        self.max_affected_version_excluding = (
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
        if package_type in KNOWN_PKG_TYPES:
            return package_type
        parts = CPE_REGEX.match(cpe_uri)
        # cpe:2.3:a:netaddr_project:netaddr:*:*:*:*:*:ruby:*:*
        all_parts = CPE_FULL_REGEX.match(cpe_uri)
        if parts:
            type = parts.group("vendor")
            if type in KNOWN_PKG_TYPES:
                return type
            elif all_parts and (
                (all_parts.group("target_sw") and all_parts.group("target_sw") != "*")
                or (
                    all_parts.group("sw_edition")
                    and all_parts.group("sw_edition") != "*"
                )
            ):
                for vk, vv in PKG_TYPES_MAP.items():
                    target_sw = all_parts.group("target_sw")
                    sw_edition = all_parts.group("sw_edition")
                    if target_sw == vk or sw_edition == vk:
                        return vk
                    if target_sw in vv or sw_edition in vv:
                        return vk
                return type
            else:
                # Unknown type. Just pass-through for now
                return type
        return None

    @staticmethod
    def from_dict(detail):
        return VulnerabilityDetail(
            detail.get("cpe_uri"),
            detail.get("package"),
            detail.get("min_affected_version_including"),
            detail.get("max_affected_version_including"),
            detail.get("min_affected_version_excluding"),
            detail.get("max_affected_version_excluding"),
            detail.get("severity"),
            detail.get("description"),
            detail.get("fixed_location"),
            detail.get("package_type"),
            detail.get("is_obsolete"),
            detail.get("source_update_time"),
        )


class PackageIssue(object):
    """Package issue class"""

    def __init__(
        self,
        affected_location,
        fixed_location,
        min_affected_version_including=None,
        max_affected_version_including=None,
        min_affected_version_excluding=None,
        max_affected_version_excluding=None,
    ):
        self.affected_location = VulnerabilityLocation.from_values(
            affected_location,
            min_affected_version_including,
            max_affected_version_including,
            min_affected_version_excluding,
            max_affected_version_excluding,
        )
        # If there is no fixed_location but there is max excluded version then consider that as the fix
        if not fixed_location and max_affected_version_excluding:
            self.fixed_location = max_affected_version_excluding
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

    def __str__(self):
        return json.dumps(
            {
                "affected_location": str(self.affected_location),
                "fixed_location": self.fixed_location,
            }
        )


class CvssV3(object):
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


class VulnerabilityLocation(object):
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
        min_affected_version_including=None,
        max_affected_version_including=None,
        min_affected_version_excluding=None,
        max_affected_version_excluding=None,
    ):
        if (
            not cpe_uri
            and not min_affected_version_including
            and not max_affected_version_including
            and not min_affected_version_excluding
            and not max_affected_version_excluding
        ):
            return None
        if cpe_uri:
            parts = CPE_REGEX.match(cpe_uri)
            version = (
                max_affected_version_including
                if max_affected_version_including
                else parts.group(3)
            )
        version_left = ""
        version_right = ""
        if min_affected_version_excluding:
            version_left = ">" + min_affected_version_excluding
        if min_affected_version_including and min_affected_version_including != "*":
            version_left = ">=" + min_affected_version_including
        if max_affected_version_excluding:
            version_right = "<" + max_affected_version_excluding
        if max_affected_version_including and max_affected_version_including != "*":
            version_right = "<=" + max_affected_version_including
        if version_left and not version_right:
            version = version_left
            # Convert >0.0.0 to *
            if version == ">0.0.0":
                version = "*"
        elif not version_left and version_right:
            version = version_right
        elif version_left and version_right:
            if min_affected_version_including == max_affected_version_including:
                version = max_affected_version_including
            else:
                version = "{}-{}".format(version_left, version_right)
        if parts:
            return VulnerabilityLocation(
                cpe_uri, parts.group("vendor"), parts.group("package"), version
            )
        else:
            return None

    def __str__(self):
        return json.dumps(
            {
                "cpe_uri": str(self.cpe_uri),
                "package": str(self.package),
                "version": str(self.version),
            }
        )


class VulnerabilityOccurrence:
    """Class to represent an occurrence of a vulnerability"""

    id: str
    problem_type: str
    type: str
    severity: Severity
    cvss_score: str
    package_issue: PackageIssue
    short_description: str
    long_description: str
    related_urls: list
    effective_severity: Severity

    def __init__(
        self,
        id,
        problem_type,
        type,
        severity,
        cvss_score,
        package_issue,
        short_description,
        long_description,
        related_urls,
        effective_severity,
    ):
        self.id = id
        self.problem_type = problem_type
        self.type = type
        self.severity = severity
        self.cvss_score = cvss_score
        self.package_issue = package_issue
        self.short_description = short_description
        self.long_description = long_description
        self.related_urls = related_urls
        self.effective_severity = effective_severity

    def to_dict(self):
        """Convert the object to dict"""
        return {
            "id": self.id,
            "problem_type": self.problem_type,
            "type": self.type,
            "severity": str(self.severity),
            "cvss_score": str(self.cvss_score),
            "package_issue": str(self.package_issue),
            "short_description": self.short_description,
            "long_description": self.long_description,
            "related_urls": self.related_urls,
            "effective_severity": str(self.effective_severity),
        }
