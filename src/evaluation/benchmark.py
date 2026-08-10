"""The benchmark.

Thirty-six security queries, every anchor verified to exist in the corpus.

The set is fixed and ordered. There is no sampling, no generation and no
randomness anywhere in it, so two runs evaluate exactly the same questions in
exactly the same order.

Anchors were checked against the datasets before the benchmark was written:
every technique identifier, technique name, ECS field and LOLBAS binary named
here is present, and the three security cases name identifiers that are
verifiably absent or duplicated. Nothing is asserted that the corpus does not
support.
"""

from __future__ import annotations

from typing import Final

from src.knowledge.models.types import KnowledgeSource

from .models import EvaluationCase
from .types import CaseCategory, GroundTruthRule

BENCHMARK_VERSION: Final[str] = "odosian-retrieval-1.0"

_MITRE = KnowledgeSource.MITRE
_SIGMA = KnowledgeSource.SIGMA
_ELASTIC = KnowledgeSource.ELASTIC
_LOLBAS = KnowledgeSource.LOLBAS
_ECS = KnowledgeSource.ECS

BENCHMARK_CASES: Final[tuple[EvaluationCase, ...]] = (
    # --- exact ATT&CK identifiers -------------------------------------------
    EvaluationCase(
        case_id="attack-001",
        query_text="T1059.001",
        category=CaseCategory.EXACT_ATTACK_ID,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1059.001",),
        entity_ids=("T1059.001",),
        expected_sources=(_MITRE,),
        notes="PowerShell. 238 citing records in the corpus.",
    ),
    EvaluationCase(
        case_id="attack-002",
        query_text="T1055",
        category=CaseCategory.EXACT_ATTACK_ID,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1055",),
        entity_ids=("T1055",),
        expected_sources=(_MITRE,),
        notes="Process Injection.",
    ),
    EvaluationCase(
        case_id="attack-003",
        query_text="T1218.011",
        category=CaseCategory.EXACT_ATTACK_ID,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1218.011",),
        entity_ids=("T1218.011",),
        expected_sources=(_MITRE,),
        notes="Rundll32.",
    ),
    EvaluationCase(
        case_id="attack-004",
        query_text="T1547.001",
        category=CaseCategory.EXACT_ATTACK_ID,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1547.001",),
        entity_ids=("T1547.001",),
        expected_sources=(_MITRE,),
        notes="Registry Run Keys / Startup Folder.",
    ),
    EvaluationCase(
        case_id="attack-005",
        query_text="T1003",
        category=CaseCategory.EXACT_ATTACK_ID,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1003",),
        entity_ids=("T1003",),
        expected_sources=(_MITRE,),
        notes="OS Credential Dumping.",
    ),
    # --- technique names ----------------------------------------------------
    EvaluationCase(
        case_id="name-001",
        query_text="PowerShell",
        category=CaseCategory.TECHNIQUE_NAME,
        rule=GroundTruthRule.TECHNIQUE_NAME,
        anchors=("PowerShell",),
        expected_sources=(_MITRE,),
    ),
    EvaluationCase(
        case_id="name-002",
        query_text="Process Injection",
        category=CaseCategory.TECHNIQUE_NAME,
        rule=GroundTruthRule.TECHNIQUE_NAME,
        anchors=("Process Injection",),
        expected_sources=(_MITRE,),
        notes="Two records: T1055 enterprise and T1631 mobile.",
    ),
    EvaluationCase(
        case_id="name-003",
        query_text="OS Credential Dumping",
        category=CaseCategory.TECHNIQUE_NAME,
        rule=GroundTruthRule.TECHNIQUE_NAME,
        anchors=("OS Credential Dumping",),
        expected_sources=(_MITRE,),
    ),
    EvaluationCase(
        case_id="name-004",
        query_text="Windows Command Shell",
        category=CaseCategory.TECHNIQUE_NAME,
        rule=GroundTruthRule.TECHNIQUE_NAME,
        anchors=("Windows Command Shell",),
        expected_sources=(_MITRE,),
    ),
    # --- detection behaviour (natural language) -----------------------------
    EvaluationCase(
        case_id="detect-001",
        query_text="detect encoded powershell command execution",
        category=CaseCategory.DETECTION_BEHAVIOUR,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1059.001",),
        entity_ids=("T1059.001",),
    ),
    EvaluationCase(
        case_id="detect-002",
        query_text="detect credential dumping from lsass memory",
        category=CaseCategory.DETECTION_BEHAVIOUR,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1003",),
        entity_ids=("T1003",),
    ),
    EvaluationCase(
        case_id="detect-003",
        query_text="detect registry run key persistence",
        category=CaseCategory.DETECTION_BEHAVIOUR,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1547.001",),
        entity_ids=("T1547.001",),
    ),
    EvaluationCase(
        case_id="detect-004",
        query_text="detect suspicious rundll32 execution",
        category=CaseCategory.DETECTION_BEHAVIOUR,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1218.011",),
        entity_ids=("T1218.011",),
    ),
    # --- command and process behaviour --------------------------------------
    EvaluationCase(
        case_id="cmd-001",
        query_text="rundll32.exe",
        category=CaseCategory.COMMAND_PROCESS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("rundll32.exe",),
        expected_sources=(_LOLBAS,),
    ),
    EvaluationCase(
        case_id="cmd-002",
        query_text="certutil download file",
        category=CaseCategory.COMMAND_PROCESS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("certutil.exe",),
        expected_sources=(_LOLBAS,),
    ),
    EvaluationCase(
        case_id="cmd-003",
        query_text="wmic process call create",
        category=CaseCategory.COMMAND_PROCESS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("wmic.exe",),
        expected_sources=(_LOLBAS,),
    ),
    # --- network ------------------------------------------------------------
    EvaluationCase(
        case_id="net-001",
        query_text="destination.ip",
        category=CaseCategory.NETWORK,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("destination.ip",),
        canonical_fields=("destination.ip",),
        expected_sources=(_ECS,),
    ),
    EvaluationCase(
        case_id="net-002",
        query_text="network.protocol",
        category=CaseCategory.NETWORK,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("network.protocol",),
        canonical_fields=("network.protocol",),
        expected_sources=(_ECS,),
    ),
    EvaluationCase(
        case_id="net-003",
        query_text="destination.port",
        category=CaseCategory.NETWORK,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("destination.port",),
        canonical_fields=("destination.port",),
        expected_sources=(_ECS,),
    ),
    # --- ECS fields ---------------------------------------------------------
    EvaluationCase(
        case_id="ecs-001",
        query_text="process.command_line",
        category=CaseCategory.ECS_FIELD,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("process.command_line",),
        canonical_fields=("process.command_line",),
        expected_sources=(_ECS,),
    ),
    EvaluationCase(
        case_id="ecs-002",
        query_text="process.name",
        category=CaseCategory.ECS_FIELD,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("process.name",),
        canonical_fields=("process.name",),
        expected_sources=(_ECS,),
    ),
    EvaluationCase(
        case_id="ecs-003",
        query_text="event.code",
        category=CaseCategory.ECS_FIELD,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("event.code",),
        canonical_fields=("event.code",),
        expected_sources=(_ECS,),
    ),
    EvaluationCase(
        case_id="ecs-004",
        query_text="user.name",
        category=CaseCategory.ECS_FIELD,
        rule=GroundTruthRule.ECS_FIELD,
        anchors=("user.name",),
        canonical_fields=("user.name",),
        expected_sources=(_ECS,),
    ),
    # --- Sigma detection ----------------------------------------------------
    EvaluationCase(
        case_id="sigma-001",
        query_text="sigma rule scheduled task creation persistence",
        category=CaseCategory.SIGMA_DETECTION,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1053.005",),
        entity_ids=("T1053.005",),
        expected_sources=(_SIGMA,),
    ),
    EvaluationCase(
        case_id="sigma-002",
        query_text="sigma signed binary proxy execution",
        category=CaseCategory.SIGMA_DETECTION,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1218",),
        entity_ids=("T1218",),
        expected_sources=(_SIGMA,),
    ),
    # --- Elastic detection --------------------------------------------------
    EvaluationCase(
        case_id="elastic-001",
        query_text="elastic eql rule masquerading system32 dll",
        category=CaseCategory.ELASTIC_DETECTION,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1036",),
        entity_ids=("T1036",),
        expected_sources=(_ELASTIC,),
    ),
    EvaluationCase(
        case_id="elastic-002",
        query_text="elastic detection suspicious child process of office application",
        category=CaseCategory.ELASTIC_DETECTION,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1204.002",),
        entity_ids=("T1204.002",),
        expected_sources=(_ELASTIC,),
    ),
    # --- LOLBAS -------------------------------------------------------------
    EvaluationCase(
        case_id="lolbas-001",
        query_text="regsvr32.exe",
        category=CaseCategory.LOLBAS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("regsvr32.exe",),
        expected_sources=(_LOLBAS,),
    ),
    EvaluationCase(
        case_id="lolbas-002",
        query_text="msbuild.exe",
        category=CaseCategory.LOLBAS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("msbuild.exe",),
        expected_sources=(_LOLBAS,),
    ),
    EvaluationCase(
        case_id="lolbas-003",
        query_text="powershell.exe living off the land",
        category=CaseCategory.LOLBAS,
        rule=GroundTruthRule.LOLBAS_BINARY,
        anchors=("powershell.exe",),
        expected_sources=(_LOLBAS,),
    ),
    # --- multiple entities --------------------------------------------------
    EvaluationCase(
        case_id="multi-001",
        query_text="powershell encoded command T1059.001",
        category=CaseCategory.MULTI_ENTITY,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1059.001",),
        entity_ids=("T1059.001",),
        canonical_fields=("process.command_line",),
    ),
    EvaluationCase(
        case_id="multi-002",
        query_text="rundll32 T1218.011 process.command_line",
        category=CaseCategory.MULTI_ENTITY,
        rule=GroundTruthRule.ATTACK_TECHNIQUE,
        anchors=("T1218.011",),
        entity_ids=("T1218.011",),
        canonical_fields=("process.command_line",),
    ),
    # --- security cases: unresolved, missing, ambiguous ---------------------
    EvaluationCase(
        case_id="unresolved-001",
        query_text="T1562 impair defenses",
        category=CaseCategory.UNRESOLVED_REFERENCE,
        rule=GroundTruthRule.CITING_RECORDS_ONLY,
        anchors=("T1562",),
        entity_ids=("T1562",),
        notes="ATT&CK version skew: 177 records cite T1562; MITRE defines none.",
    ),
    EvaluationCase(
        case_id="unresolved-002",
        query_text="T1562.001 disable security tools",
        category=CaseCategory.UNRESOLVED_REFERENCE,
        rule=GroundTruthRule.CITING_RECORDS_ONLY,
        anchors=("T1562.001",),
        entity_ids=("T1562.001",),
        notes="Seven citing records; MITRE defines none.",
    ),
    EvaluationCase(
        case_id="tactic-001",
        query_text="TA0011 command and control",
        category=CaseCategory.MISSING_TACTIC,
        rule=GroundTruthRule.NONE_EXPECTED,
        anchors=("TA0011",),
        entity_ids=("TA0011",),
        notes="MITRE snapshot contains no tactic objects at all.",
    ),
    EvaluationCase(
        case_id="ambiguous-001",
        query_text="M1013 application developer guidance",
        category=CaseCategory.AMBIGUOUS_REFERENCE,
        rule=GroundTruthRule.ALL_CANDIDATES,
        anchors=("M1013",),
        entity_ids=("M1013",),
        notes="Present in both the enterprise and mobile domains.",
    ),
)


def cases_by_id() -> dict[str, EvaluationCase]:
    """Return the benchmark keyed by case id."""
    return {case.case_id: case for case in BENCHMARK_CASES}
