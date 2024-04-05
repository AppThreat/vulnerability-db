import os
import uuid

import orjson
from semver import VersionInfo

from vdb.lib import (
    config,
    CPE_FULL_REGEX,
    KNOWN_PKG_TYPES,
    PKG_TYPES_MAP,
    Vulnerability,
    VulnerabilityDetail,
    VulnerabilitySource,
)
from vdb.lib import db6 as db_lib
from vdb.lib.cna import ASSIGNER_UUID_MAP
from vdb.lib.cve_model import (
    CVE,
    CVE1,
    Affected,
    CnaPublishedContainer,
    Containers,
    Cpe,
    CveId,
    CveMetadataPublished,
    DataType,
    DataVersion,
    Description,
    Description1,
    Language,
    Metrics,
    Metrics1,
    Metrics2,
    OrgId,
    ProblemType,
    ProblemTypes,
    Product,
    ProviderMetadata,
    Reference,
    References,
    State,
    Status,
    UuidType,
    Version,
    Versions,
)
from vdb.lib.cve_model.common import CiaType
from vdb.lib.cve_model.cvss_v3 import Field0, Field1
from vdb.lib.utils import calculate_hash, to_purl_vers

# Our DB creation process could result in duplicates. By tracking these keys we reduce them
source_completed_keys = {}
index_completed_keys = {}


def to_cve_metadata(avuln: Vulnerability):
    # Re-use the assigner org id
    if avuln.assigner:
        if ASSIGNER_UUID_MAP.get(avuln.assigner):
            assigner_org_id = ASSIGNER_UUID_MAP[avuln.assigner]
        else:
            # We have encountered a new assigner
            assigner_org_id = OrgId(UuidType(str(uuid.uuid4())))
            ASSIGNER_UUID_MAP[avuln.assigner] = assigner_org_id
    else:
        assigner_org_id = OrgId(UuidType(str(uuid.uuid4())))
    metadata = CveMetadataPublished(
        cveId=CveId(avuln.id),
        state=State.PUBLISHED,
        assignerOrgId=assigner_org_id,
        assignerShortName=avuln.assigner,
    )
    metadata.datePublished = avuln.source_orig_time
    metadata.dateUpdated = avuln.source_update_time
    return metadata


def all_semver_compatible(adetail: VulnerabilityDetail) -> bool:
    if adetail.mii and adetail.mii != "*" and not VersionInfo.is_valid(adetail.mii):
        return False
    if adetail.mae and adetail.mae != "*" and not VersionInfo.is_valid(adetail.mae):
        return False
    if adetail.mie and adetail.mie != "*" and not VersionInfo.is_valid(adetail.mie):
        return False
    if adetail.mai and adetail.mai != "*" and not VersionInfo.is_valid(adetail.mai):
        return False
    return True


def to_product_versions(vendor, adetail: VulnerabilityDetail) -> list[Versions]:
    versions = []
    lt_captured = False
    # Try to detect the version_type
    version_type = "custom"
    if vendor in KNOWN_PKG_TYPES:
        version_type = vendor
    elif all_semver_compatible(adetail):
        version_type = "semver"
    # The goal is to create a single entry with either version and lessThan
    #   or version and lessThanOrEqual
    # If this is not possible then we create a separate version objects
    if adetail.mii and adetail.mii not in ("*", "-"):
        if adetail.mai and adetail.mai not in ("*", "-"):
            versions.append(
                Versions(
                    version=Version(adetail.mii),
                    lessThanOrEqual=Version(adetail.mai),
                    versionType=version_type,
                    status=Status.affected,
                )
            )
            lt_captured = True
        elif adetail.mae:
            versions.append(
                Versions(
                    version=Version(adetail.mii),
                    lessThan=Version(adetail.mae),
                    versionType=version_type,
                    status=Status.affected,
                )
            )
            lt_captured = True
        else:
            versions.append(
                Versions(
                    version=Version(adetail.mii),
                    lessThanOrEqual=Version(adetail.mai),
                    versionType=version_type,
                    status=Status.affected,
                )
            )
    if adetail.mie and adetail.mie not in ("*", "-"):
        versions.append(
            Versions(
                version=Version(adetail.mie),
                versionType=version_type,
                status=Status.unaffected,
            )
        )
    if not lt_captured:
        if adetail.mai and adetail.mai not in ("*", "-"):
            versions.append(
                Versions(
                    version=Version("0"),
                    lessThanOrEqual=Version(adetail.mai),
                    versionType=version_type,
                    status=Status.affected,
                )
            )
        if adetail.mae and adetail.mae not in ("*", "-"):
            versions.append(
                Versions(
                    version=Version("0"),
                    lessThan=Version(adetail.mae),
                    versionType=version_type,
                    status=Status.affected,
                )
            )
    return versions


def to_cve_affected(avuln: Vulnerability) -> Affected | None:
    products = []
    adetail: VulnerabilityDetail
    for adetail in avuln.details:
        cpe_uri = adetail.cpe_uri
        parts = CPE_FULL_REGEX.match(cpe_uri)
        if parts:
            versions = to_product_versions(parts.group("vendor"), adetail)
            if versions:
                # Similar to purl type
                vendor = parts.group("vendor")
                # Similar to purl namespace
                product = parts.group("package").removesuffix("\\").removesuffix("!")
                # Similar to purl name
                package_name = parts.group("package")
                if "/" in product:
                    tmp_a = product.split("/")
                    # ubuntu/upstream/virtualbox should become
                    # product=ubuntu and package_name=upstream/virtualbox
                    if vendor in config.OS_PKG_TYPES or config.VENDOR_TO_VERS_SCHEME.get(vendor):
                        product = tmp_a[0]
                        package_name = "/".join(tmp_a[1:])
                    elif len(tmp_a) != 2:
                        if len(tmp_a) > 2 and vendor in ("generic", "swift"):
                            product = os.path.dirname(product)
                            package_name = os.path.basename(package_name)
                            # If we get an empty package_name then fallback to using the full string as package_name
                            if not package_name:
                                product = None
                                package_name = parts.group("package")
                        else:
                            product = None
                    elif vendor not in ("golang",):
                        product = tmp_a[0]
                        package_name = tmp_a[1]
                # Product and package name are the same.
                # For some ecosystems, we can remove the product (namespace) to rely only on name
                # For others, we can make the product the same as vendor
                if product == package_name:
                    if vendor in ("npm", "pypi", "gem", "swift"):
                        product = None
                    elif vendor not in (
                        "maven",
                        "composer",
                        "generic",
                        "github",
                        "gitlab",
                    ):
                        product = vendor
                # See if we can substitute vers scheme
                if config.VENDOR_TO_VERS_SCHEME.get(vendor):
                    vendor = config.VENDOR_TO_VERS_SCHEME.get(vendor)
                # This prevents cargo:cargo or nuget:nuget
                # or openssl:openssl:openssl
                # but retain such values for github and gitlab
                if (
                    product == vendor
                    and vendor not in ("github", "gitlab")
                    and (package_name == product or vendor in KNOWN_PKG_TYPES)
                ):
                    product = None
                # Deal with NVD mess such as npmjs or crates
                if vendor not in KNOWN_PKG_TYPES:
                    for k, v in PKG_TYPES_MAP.items():
                        if vendor.lower() in v:
                            vendor = k
                            break
                p = Product(
                    vendor=vendor,
                    product=product,
                    packageName=package_name,
                    cpes=[Cpe(cpe_uri)],
                    defaultStatus=Status.unknown,
                    versions=versions,
                )
                products.append(p)
    return Affected(products) if products else None


def to_complexity_type(complexity: str) -> str:
    if complexity and complexity.lower() == "low":
        return "LOW"
    return "HIGH"


def severity_to_impact(severity: str) -> CiaType:
    """Method to convert severity string to a valid impact enum string"""
    if not severity:
        return CiaType.NONE
    if severity.lower() in ("critical", "high", "medium", "moderate"):
        return CiaType.HIGH
    return CiaType.LOW


def to_metrics(avuln: Vulnerability) -> Metrics:
    metrics_list = []
    if avuln.cvss_v3.vector_string and avuln.cvss_v3.vector_string.startswith(
        "CVSS:3.1"
    ):
        metrics_list.append(
            Metrics1(
                cvssV3_1=Field1(
                    version="3.1",
                    baseScore=avuln.cvss_v3.base_score,
                    baseSeverity=config.THREAT_TO_SEVERITY.get(avuln.severity.lower()),
                    vectorString=avuln.cvss_v3.vector_string,
                    attackVector=avuln.cvss_v3.attack_vector,
                    attackComplexity=to_complexity_type(
                        avuln.cvss_v3.attack_complexity
                    ),
                    privilegesRequired=avuln.cvss_v3.privileges_required,
                    userInteraction=avuln.cvss_v3.user_interaction,
                    scope=avuln.cvss_v3.scope,
                    confidentialityImpact=severity_to_impact(
                        avuln.cvss_v3.confidentiality_impact
                    ),
                    integrityImpact=severity_to_impact(avuln.cvss_v3.integrity_impact),
                    availabilityImpact=severity_to_impact(
                        avuln.cvss_v3.availability_impact
                    ),
                )
            )
        )
    elif avuln.cvss_v3.vector_string and avuln.cvss_v3.vector_string.startswith(
        "CVSS:3.0"
    ):
        metrics_list.append(
            Metrics2(
                cvssV3_0=Field0(
                    version="3.0",
                    baseScore=avuln.cvss_v3.base_score,
                    baseSeverity=config.THREAT_TO_SEVERITY.get(avuln.severity.lower()),
                    vectorString=avuln.cvss_v3.vector_string,
                    attackVector=avuln.cvss_v3.attack_vector,
                    attackComplexity=avuln.cvss_v3.attack_complexity,
                    privilegesRequired=avuln.cvss_v3.privileges_required,
                    userInteraction=avuln.cvss_v3.user_interaction,
                    scope=avuln.cvss_v3.scope,
                    confidentialityImpact=severity_to_impact(
                        avuln.cvss_v3.confidentiality_impact
                    ),
                    integrityImpact=severity_to_impact(avuln.cvss_v3.integrity_impact),
                    availabilityImpact=severity_to_impact(
                        avuln.cvss_v3.availability_impact
                    ),
                )
            )
        )

    return Metrics(metrics_list)


def to_references(avuln: Vulnerability) -> list[Reference] | None:
    ref_list = [
        Reference(url=url) for url in avuln.related_urls if url.startswith("http")
    ]
    return References(ref_list) if ref_list else None


def to_cve_containers(avuln: Vulnerability) -> CnaPublishedContainer | None:
    provier_meta = ProviderMetadata(
        orgId=ASSIGNER_UUID_MAP.get(avuln.assigner, OrgId(UuidType(str(uuid.uuid4()))))
    )
    provier_meta.dateUpdated = avuln.source_update_time
    affected = to_cve_affected(avuln)
    if not affected:
        return None
    cont = CnaPublishedContainer(
        providerMetadata=provier_meta,
        descriptions=[Description(lang=Language("en"), value=avuln.description)],
        affected=affected,
        metrics=to_metrics(avuln),
    )
    references = to_references(avuln)
    if references:
        cont.references = references
    cont.dateAssigned = avuln.source_orig_time
    # CWE
    if avuln.problem_type and "noinfo" not in avuln.problem_type:
        problem_types = []
        for acwe in avuln.problem_type.split(","):
            # Check if this starts with CWE
            if acwe.startswith("CWE"):
                problem_types.append(
                    ProblemType(
                        descriptions=[
                            Description1(
                                lang=Language("en"),
                                description=acwe,
                                cweId=acwe,
                                type="CWE",
                            )
                        ]
                    )
                )
        if problem_types:
            cont.problemTypes = ProblemTypes(problem_types)
    return cont


class CVESource(VulnerabilitySource):
    """
    Generic CVE source that uses the CVE 5.0 models
    """

    db_conn = None
    index_conn = None

    def __init__(self):
        self.db_conn, self.index_conn = db_lib.get(
            db_file=config.VDB_BIN_FILE, index_file=config.VDB_BIN_INDEX
        )

    @classmethod
    def download_all(cls):
        db_lib.clear_all()

    @classmethod
    def download_recent(cls):
        pass

    @classmethod
    def bulk_search(cls, app_info, pkg_list):
        pass

    @classmethod
    def refresh(cls):
        pass

    def convert(self, cve_data: dict) -> list[Vulnerability]:
        pass

    def convert5(self, data: list[Vulnerability]) -> list[CVE]:
        cves = []
        for avuln in data:
            containers = Containers(cna=to_cve_containers(avuln))
            if containers:
                cve_obj = CVE1(
                    dataType=DataType.CVE_RECORD,
                    dataVersion=DataVersion.field_5_0,
                    cveMetadata=to_cve_metadata(avuln),
                    containers=containers,
                )
                cves.append(cve_obj)
        return cves

    def store(self, data: list[Vulnerability]):
        """Store data in the database"""
        cve5_list = self.convert5(data)
        self.store5(cve5_list)

    def store5(self, data: list[CVE]):
        """Store the CVE and index data into the SQLite database"""
        with self.db_conn as dbc:
            with self.index_conn as indexc:
                for d in data:
                    cve_id = d.cveMetadata.cveId
                    cve_id = cve_id.model_dump(mode="python")
                    source_data = d.model_dump(
                        mode="json",
                        exclude_defaults=True,
                        exclude_unset=True,
                        exclude_none=True,
                    )
                    source_data_str = orjson.dumps(source_data).decode(
                        "utf-8", "ignore"
                    )
                    source_hash = calculate_hash(source_data_str)
                    if d.containers.cna and d.containers.cna.affected:
                        for affected in d.containers.cna.affected.root:
                            vers = to_purl_vers(affected.vendor, affected.versions)
                            purl_type = (
                                affected.vendor
                                if affected.vendor in KNOWN_PKG_TYPES
                                else "generic"
                            )
                            purl_prefix = f"""pkg:{purl_type}/"""
                            if affected.product:
                                purl_prefix = f"{purl_prefix}{affected.product}/"
                            purl_prefix = f"{purl_prefix}{affected.packageName}"
                            pkg_key = f"{cve_id}|{affected.vendor}|{affected.product}|{affected.packageName}|{source_hash}"
                            index_pkg_key = f"{cve_id}|{affected.vendor}|{affected.product}|{affected.packageName}|{vers}"
                            # Filter obvious duplicates
                            if not source_completed_keys.get(pkg_key):
                                dbc.execute(
                                    "INSERT INTO cve_data values(?, ?, ?, ?, jsonb(?), ?, ?, ?);",
                                    (
                                        cve_id,
                                        affected.vendor,
                                        affected.product,
                                        affected.packageName,
                                        source_data_str,
                                        None,
                                        source_hash,
                                        purl_prefix,
                                    ),
                                )
                                source_completed_keys[pkg_key] = True
                            if not index_completed_keys.get(index_pkg_key):
                                indexc.execute(
                                    "INSERT INTO cve_index values(?, ?, ?, ?, ?, ?);",
                                    (
                                        cve_id,
                                        affected.vendor,
                                        affected.product,
                                        affected.packageName,
                                        vers,
                                        purl_prefix,
                                    ),
                                )
                                index_completed_keys[index_pkg_key] = True
