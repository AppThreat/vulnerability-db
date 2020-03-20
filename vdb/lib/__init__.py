import json
import re
from abc import ABCMeta, abstractmethod
from datetime import datetime
from enum import Enum

# Known application package types
KNOWN_PKG_TYPES = ["composer", "maven", "npm", "nuget", "pypi", "rubygems", "golang"]

# CPE Regex
CPE_REGEX = re.compile(
    "cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+)"
)


class VulnerabilitySource(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def download_all():
        pass

    @classmethod
    @abstractmethod
    def download_recent():
        pass

    @classmethod
    @abstractmethod
    def bulk_search():
        pass

    @classmethod
    @abstractmethod
    def convert(data):
        pass

    @classmethod
    @abstractmethod
    def store(data):
        pass

    @classmethod
    @abstractmethod
    def refresh():
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
    """Vulnerability
    """

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
    """Vulnerability detail class
    """

    def __init__(
        self,
        cpe_uri,
        package,
        min_affected_version,
        max_affected_version,
        severity,
        description,
        fixed_location,
        package_type,
        is_obsolete,
        source_update_time,
    ):
        parts = CPE_REGEX.match(cpe_uri)
        self.cpe_uri = cpe_uri
        self.package = package if package else parts.group("package")
        self.min_affected_version = (
            min_affected_version if min_affected_version else parts.group("version")
        )
        self.max_affected_version = (
            max_affected_version if max_affected_version else parts.group("version")
        )
        self.severity = Severity.from_str(severity)
        self.description = description
        self.fixed_location = VulnerabilityLocation.from_values(
            fixed_location, self.min_affected_version, self.max_affected_version
        )
        self.package_type = VulnerabilityDetail.get_type(cpe_uri, package_type)
        self.is_obsolete = is_obsolete
        self.source_update_time: datetime = convert_time(source_update_time)

    @staticmethod
    def get_type(cpe_uri, package_type):
        if package_type in KNOWN_PKG_TYPES:
            return package_type
        parts = CPE_REGEX.match(cpe_uri)
        if parts:
            type = parts.group("vendor")
            if type in KNOWN_PKG_TYPES:
                return type
            else:
                # Unknown type. Just pass-through for now
                return type
        else:
            return None

    @staticmethod
    def from_dict(detail):
        return VulnerabilityDetail(
            detail.get("cpe_uri"),
            detail.get("package"),
            detail.get("min_affected_version"),
            detail.get("max_affected_version"),
            detail.get("severity"),
            detail.get("description"),
            detail.get("fixed_location"),
            detail.get("package_type"),
            detail.get("is_obsolete"),
            detail.get("source_update_time"),
        )


class PackageIssue(object):
    """Package issue class
    """

    def __init__(
        self,
        affected_location,
        fixed_location,
        min_affected_version=None,
        max_affected_version=None,
    ):
        self.affected_location = VulnerabilityLocation.from_values(
            affected_location, min_affected_version, max_affected_version
        )
        self.fixed_location = VulnerabilityLocation.from_values(
            fixed_location, None, None
        )

    @staticmethod
    def from_dict(package_issue):
        return PackageIssue(
            package_issue.get("affected_location"), package_issue.get("fixed_location")
        )

    def __str__(self):
        return json.dumps(
            {
                "affected_location": str(self.affected_location),
                "fixed_location": str(self.fixed_location),
            }
        )


class CvssV3(object):
    """CVSS v3 representation
    """

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
    package: str
    version: str

    def __init__(self, cpe_uri, package, version):
        self.cpe_uri = cpe_uri
        self.package = package
        self.version = version

    @staticmethod
    def from_values(cpe_uri, min_affected_version=None, max_affected_version=None):
        if not cpe_uri:
            return None
        parts = CPE_REGEX.match(cpe_uri)
        version = max_affected_version if max_affected_version else parts.group(3)
        if min_affected_version and max_affected_version:
            if min_affected_version == "*":
                version = "<" + max_affected_version
            elif max_affected_version == "*":
                version = ">" + min_affected_version
            else:
                version = min_affected_version + "-" + max_affected_version
        if parts:
            return VulnerabilityLocation(cpe_uri, parts.group(2), version)
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
    """Class to represent an occurrence of a vulnerability
    """

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
        """Convert the object to dict
        """
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
