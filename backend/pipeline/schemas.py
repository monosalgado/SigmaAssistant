"""Pydantic models for structured data exchange between pipeline stages."""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, Literal, List
from enum import Enum


# --- Stage 0: Intent Classification ---

class IntentClassification(BaseModel):
    intent: Literal["generate_rule", "refine_rule", "question", "chat"]
    reasoning: str


# --- Stage 1: Preprocessing ---

class UrlContent(BaseModel):
    url: str
    text: str
    title: str = ""

class PreprocessedInput(BaseModel):
    original_query: str
    segments: list[str] = Field(default_factory=list)
    url_content: list[UrlContent] = Field(default_factory=list)
    image_transcription: Optional[str] = None
    combined_text: str = ""


# --- Stage 2: Entity/Indicator Extraction ---

class ExtractedIndicator(BaseModel):
    value: str
    type: Literal[
        "process", "command_line", "file_path", "registry_key",
        "ip_address", "domain", "port", "user_agent",
        "api_call", "tool_name", "event_id", "hash",
        "service_name", "other"
    ]
    context: str = ""
    confidence: Literal["high", "medium", "low"] = "medium"

class ExtractionResult(BaseModel):
    indicators: list[ExtractedIndicator] = Field(default_factory=list)
    attack_summary: str = ""
    suggested_log_sources: list[str] = Field(default_factory=list)


# --- Stage 3: TTP Mapping ---

class TTPMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    relevance: str = ""
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"

class TTPMappingResult(BaseModel):
    mappings: list[TTPMapping] = Field(default_factory=list)


# --- Stage 4: Rule Generation ---

class GeneratedRule(BaseModel):
    yaml_content: str
    explanation: str = ""
    target_ttp: str = ""

class GenerationResult(BaseModel):
    rules: list[GeneratedRule] = Field(default_factory=list)
    notes: str = ""


# --- Stage 5: Validation ---

class ValidationIssue(BaseModel):
    severity: Literal["error", "warning", "info"]
    field: str
    message: str

class ValidationResult(BaseModel):
    is_valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
    corrected_rules: list[str] = Field(default_factory=list)


# --- Stage 6: Optimization ---

class OptimizedRule(BaseModel):
    yaml_content: str
    changes_made: list[str] = Field(default_factory=list)

class OptimizationResult(BaseModel):
    rules: list[OptimizedRule] = Field(default_factory=list)
    summary: str = ""


# --- Web Search Enrichment (Improvement 1) ---

class EnrichmentSource(BaseModel):
    url: str
    title: str
    snippet: str

class EnrichmentResult(BaseModel):
    search_queries: list[str] = Field(default_factory=list)
    sources: list[EnrichmentSource] = Field(default_factory=list)
    additional_context: str = ""


# --- Log Source Suggestion (Improvement 2) ---

class LogSourceSuggestion(BaseModel):
    category: str          # e.g., "process_creation", "network_connection"
    product: str           # e.g., "windows", "linux", "aws"
    service: str = ""      # e.g., "sysmon", "security", "cloudtrail"
    confidence: float = 0.5
    reasoning: str = ""
    relevant_fields: list[str] = Field(default_factory=list)

class LogSourceResult(BaseModel):
    suggestions: list[LogSourceSuggestion] = Field(default_factory=list)
    primary_source: str = ""


# --- User Feedback (Improvement 3) ---

class UserFeedback(BaseModel):
    approved_indicators: list[str] = Field(default_factory=list)
    removed_indicators: list[str] = Field(default_factory=list)
    approved_ttps: list[str] = Field(default_factory=list)
    added_ttps: list[str] = Field(default_factory=list)
    log_source_override: Optional[str] = None
    additional_notes: str = ""


# --- PoC Code Analysis (Improvement 4) ---

class CodeSnippet(BaseModel):
    language: str = "unknown"
    source: str = "inline"      # "inline", "github", "url"
    source_url: Optional[str] = None
    content: str = ""

class PoCAnalysisResult(BaseModel):
    snippets_found: int = 0
    behavioral_indicators: list[ExtractedIndicator] = Field(default_factory=list)
    attack_flow: str = ""


# --- Pipeline Metadata (returned to frontend) ---

class PipelineMetadata(BaseModel):
    indicators: list[ExtractedIndicator] = Field(default_factory=list)
    ttp_mappings: list[TTPMapping] = Field(default_factory=list)
    validation_issues: list[ValidationIssue] = Field(default_factory=list)
    optimization_changes: list[str] = Field(default_factory=list)
    enrichment_sources: list[EnrichmentSource] = Field(default_factory=list)
    log_source_suggestions: list[LogSourceSuggestion] = Field(default_factory=list)
    code_snippets_analyzed: int = 0
    feedback_applied: bool = False
