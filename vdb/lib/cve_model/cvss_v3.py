# pylint: disable=C0115, C0103, C0301

from __future__ import annotations

from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, Field

from vdb.lib.cve_model.common import (
    AttackComplexityType,
    AttackVectorType,
    CiaRequirementType,
    CiaType,
    ConfidenceType,
    ExploitCodeMaturityType,
    ModifiedAttackComplexityType,
    ModifiedAttackVectorType,
    ModifiedCiaType,
    ModifiedPrivilegesRequiredType,
    ModifiedScopeType,
    ModifiedUserInteractionType,
    PrivilegesRequiredType,
    RemediationLevelType,
    ScopeType,
    ScoreType,
    SeverityType,
    UserInteractionType,
)


class Version(Enum):
    field_3_1 = "3.1"


class Version1Model(Enum):
    field_3_0 = "3.0"


class Field1(BaseModel):
    version: Annotated[Version, Field(description="CVSS Version")]
    vectorString: Annotated[
        str,
        Field(
            pattern="^CVSS:3[.]1/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
        ),
    ]
    attackVector: Optional[AttackVectorType] = None
    attackComplexity: Optional[AttackComplexityType] = None
    privilegesRequired: Optional[PrivilegesRequiredType] = None
    userInteraction: Optional[UserInteractionType] = None
    scope: Optional[ScopeType] = None
    confidentialityImpact: Optional[CiaType] = None
    integrityImpact: Optional[CiaType] = None
    availabilityImpact: Optional[CiaType] = None
    baseScore: ScoreType
    baseSeverity: SeverityType
    exploitCodeMaturity: Optional[ExploitCodeMaturityType] = None
    remediationLevel: Optional[RemediationLevelType] = None
    reportConfidence: Optional[ConfidenceType] = None
    temporalScore: Optional[ScoreType] = None
    temporalSeverity: Optional[SeverityType] = None
    confidentialityRequirement: Optional[CiaRequirementType] = None
    integrityRequirement: Optional[CiaRequirementType] = None
    availabilityRequirement: Optional[CiaRequirementType] = None
    modifiedAttackVector: Optional[ModifiedAttackVectorType] = None
    modifiedAttackComplexity: Optional[ModifiedAttackComplexityType] = None
    modifiedPrivilegesRequired: Optional[ModifiedPrivilegesRequiredType] = None
    modifiedUserInteraction: Optional[ModifiedUserInteractionType] = None
    modifiedScope: Optional[ModifiedScopeType] = None
    modifiedConfidentialityImpact: Optional[ModifiedCiaType] = None
    modifiedIntegrityImpact: Optional[ModifiedCiaType] = None
    modifiedAvailabilityImpact: Optional[ModifiedCiaType] = None
    environmentalScore: Optional[ScoreType] = None
    environmentalSeverity: Optional[SeverityType] = None


class Field0(BaseModel):
    version: Annotated[Version1Model, Field(description="CVSS Version")]
    vectorString: Annotated[
        str,
        Field(
            pattern="^CVSS:3[.]0/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
        ),
    ]
    attackVector: Optional[AttackVectorType] = None
    attackComplexity: Optional[AttackComplexityType] = None
    privilegesRequired: Optional[PrivilegesRequiredType] = None
    userInteraction: Optional[UserInteractionType] = None
    scope: Optional[ScopeType] = None
    confidentialityImpact: Optional[CiaType] = None
    integrityImpact: Optional[CiaType] = None
    availabilityImpact: Optional[CiaType] = None
    baseScore: ScoreType
    baseSeverity: SeverityType
    exploitCodeMaturity: Optional[ExploitCodeMaturityType] = None
    remediationLevel: Optional[RemediationLevelType] = None
    reportConfidence: Optional[ConfidenceType] = None
    temporalScore: Optional[ScoreType] = None
    temporalSeverity: Optional[SeverityType] = None
    confidentialityRequirement: Optional[CiaRequirementType] = None
    integrityRequirement: Optional[CiaRequirementType] = None
    availabilityRequirement: Optional[CiaRequirementType] = None
    modifiedAttackVector: Optional[ModifiedAttackVectorType] = None
    modifiedAttackComplexity: Optional[ModifiedAttackComplexityType] = None
    modifiedPrivilegesRequired: Optional[ModifiedPrivilegesRequiredType] = None
    modifiedUserInteraction: Optional[ModifiedUserInteractionType] = None
    modifiedScope: Optional[ModifiedScopeType] = None
    modifiedConfidentialityImpact: Optional[ModifiedCiaType] = None
    modifiedIntegrityImpact: Optional[ModifiedCiaType] = None
    modifiedAvailabilityImpact: Optional[ModifiedCiaType] = None
    environmentalScore: Optional[ScoreType] = None
    environmentalSeverity: Optional[SeverityType] = None
