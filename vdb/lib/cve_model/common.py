from enum import Enum
from typing import Annotated

from pydantic import Field, RootModel


class AttackVectorType(Enum):
    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class ModifiedAttackVectorType(Enum):
    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    NOT_DEFINED = "NOT_DEFINED"


class AttackComplexityType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"


class ModifiedAttackComplexityType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NOT_DEFINED = "NOT_DEFINED"


class PrivilegesRequiredType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"


class ModifiedPrivilegesRequiredType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"
    NOT_DEFINED = "NOT_DEFINED"


class UserInteractionType(Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"


class ModifiedUserInteractionType(Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"
    NOT_DEFINED = "NOT_DEFINED"


class ScopeType(Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


class ModifiedScopeType(Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedCiaType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ExploitCodeMaturityType(Enum):
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class RemediationLevelType(Enum):
    OFFICIAL_FIX = "OFFICIAL_FIX"
    TEMPORARY_FIX = "TEMPORARY_FIX"
    WORKAROUND = "WORKAROUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_DEFINED = "NOT_DEFINED"


class ConfidenceType(Enum):
    UNKNOWN = "UNKNOWN"
    REASONABLE = "REASONABLE"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirementType(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ScoreType(RootModel[float]):
    root: Annotated[float, Field(ge=0.0, le=10.0)]


class SeverityType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessVectorType(Enum):
    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"


class AccessComplexityType(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AuthenticationType(Enum):
    MULTIPLE = "MULTIPLE"
    SINGLE = "SINGLE"
    NONE = "NONE"


class CiaTypeModel(Enum):
    NONE = "NONE"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


class ExploitabilityType(Enum):
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ReportConfidenceType(Enum):
    UNCONFIRMED = "UNCONFIRMED"
    UNCORROBORATED = "UNCORROBORATED"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"


class CollateralDamagePotentialType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    LOW_MEDIUM = "LOW_MEDIUM"
    MEDIUM_HIGH = "MEDIUM_HIGH"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class TargetDistributionType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class Type(Enum):
    finder = "finder"
    reporter = "reporter"
    analyst = "analyst"
    coordinator = "coordinator"
    remediation_developer = "remediation developer"
    remediation_reviewer = "remediation reviewer"
    remediation_verifier = "remediation verifier"
    tool = "tool"
    sponsor = "sponsor"
    other = "other"
