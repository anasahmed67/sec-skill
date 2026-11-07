"""Data models for SecSkill AI Red Team vs. Blue Team Duel Arena."""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class DuelRole(str, Enum):
    RED = "RED"      # Attacker
    BLUE = "BLUE"    # Defender

class AttackPayload(BaseModel):
    name: str = Field(description="Name or title of the exploit payload")
    vector: str = Field(description="Vulnerability vector, e.g. CWE-89 SQL Injection")
    payload: str = Field(description="The concrete exploit payload string")
    bypass_technique: str = Field(description="Bypass technique used, e.g. WAF evasion, comment trick")
    explanation: str = Field(description="Technical explanation of the exploit mechanics")

class DefensePatch(BaseModel):
    strategy: str = Field(description="Defensive remediation strategy, e.g. AST parameterization")
    code: str = Field(description="The complete patched source code")
    diff: str = Field(default="", description="Unified diff or preview of changes")
    explanation: str = Field(description="Explanation of how the patch neutralizes attacks")

class ValidationVerdict(BaseModel):
    is_safe: bool = Field(description="True if the code is hardened against vulnerabilities")
    bypass_detected: bool = Field(description="True if Red's payload bypassed defenses")
    ast_safe: bool = Field(description="True if AST analysis shows zero unsafe sinks")
    taint_clean: bool = Field(description="True if taint dataflow does not reach sensitive sinks")
    ast_violations: List[str] = Field(default_factory=list, description="List of AST rule violations")
    taint_violations: List[str] = Field(default_factory=list, description="List of taint flow violations")
    details: str = Field(default="", description="Technical referee evaluation details")
    feedback_for_blue: str = Field(default="", description="SecSkill feedback directed to Blue Team")
    feedback_for_red: str = Field(default="", description="SecSkill feedback directed to Red Team")

class DuelRound(BaseModel):
    round_number: int
    red_payload: AttackPayload
    validation_before: ValidationVerdict
    blue_patch: Optional[DefensePatch] = None
    validation_after: Optional[ValidationVerdict] = None
    red_damage: int = 0
    blue_damage: int = 0
    red_hp: int = 100
    blue_hp: int = 100
    narrative: List[str] = Field(default_factory=list)

class DuelResult(BaseModel):
    winner: str = Field(description="BLUE, RED, or DRAW")
    target_name: str
    vulnerability_type: str
    rounds: List[DuelRound] = Field(default_factory=list)
    initial_code: str
    final_code: str
    is_hardened: bool = False
    saved_path: Optional[str] = None
    total_rounds: int = 0
    duration_seconds: float = 0.0

